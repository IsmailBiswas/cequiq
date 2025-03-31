#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERVER "localhost"
#define PORT "4433"
#define PREFIX "XOXO"
#define PREFIX_SIZE (sizeof(PREFIX) - 1)
#define TOO_LARGE_DATA 1024 * 1024

#define REQ_DATA "ping"
#define REQ_DATA_SIZE (sizeof(REQ_DATA) - 1)

#define RES_DATA "123456789"
#define RES_DATA_SIZE (sizeof(RES_DATA) - 1)
#define MAX_REC_FRAME 3

#define END_DATA "END"
#define END_DATA_SIZE (sizeof(END_DATA) - 1)

typedef struct {
  char prefix[PREFIX_SIZE];
  uint64_t d_size;
  void *data;
} Frame;

uint64_t htonll(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return ((uint64_t)htonl(val & 0xFFFFFFFF) << 32) | htonl(val >> 32);
#else
  return val;
#endif
}

uint64_t ntohll(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return ((uint64_t)ntohl(val & 0xFFFFFFFF) << 32) | ntohl(val >> 32);
#else
  return val;
#endif
}

void *serialize_frame(const Frame *f, size_t *net_size) {
  if (!f || !net_size)
    return NULL;

  *net_size = sizeof(f->prefix) + sizeof(f->d_size) + f->d_size;
  void *buffer = malloc(*net_size);
  if (!buffer)
    return NULL;

  uint8_t *ptr = buffer;
  memcpy(ptr, f->prefix, sizeof(f->prefix));
  ptr += sizeof(f->prefix);

  uint64_t be_f_size = htonll(f->d_size);
  memcpy(ptr, &be_f_size, sizeof(be_f_size));
  ptr += sizeof(be_f_size);

  if (f->data && f->d_size > 0) {
    memcpy(ptr, f->data, f->d_size);
  }

  return buffer;
}

uint64_t *get_data_size(void *head) {
  if (!head) {
    return NULL;
  }
  char prefix[PREFIX_SIZE];
  memcpy(prefix, head, PREFIX_SIZE);
  if (strncmp(prefix, PREFIX, PREFIX_SIZE) != 0) {
    return NULL;
  }
  uint64_t data_size;
  memcpy(&data_size, head + PREFIX_SIZE, sizeof(uint64_t));
  uint64_t *size = malloc(sizeof(uint64_t));
  if (!size) {
    return NULL;
  }
  *size = ntohll(data_size);
  return size;
};

Frame *ssl_read_bytes(SSL *ssl) {

  int head_size = PREFIX_SIZE + sizeof(uint64_t);

  void *buffer = malloc(head_size);
  if (!buffer) {
    return NULL;
  }

  int total = 0;
  while (total < head_size) {
    int ret = SSL_read(ssl, (char *)buffer + total, head_size - total);

    if (ret > 0) {
      total += ret;
    } else {
      int err = SSL_get_error(ssl, ret);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        continue;
      }
      // Fatal error
      free(buffer);
      return NULL;
    }
  }

  uint64_t *data_size = get_data_size(buffer);
  if (!data_size || *data_size > TOO_LARGE_DATA) {
    free(data_size);
    free(buffer);
    return NULL;
  }
  free(buffer);

  void *data_buffer = malloc(*data_size);
  if (!data_buffer) {
    free(data_size);
    return NULL;
  }

  total = 0;
  while (total < *data_size) {
    usleep(500000);
    int ret = SSL_read(ssl, (char *)data_buffer + total, *data_size - total);

    if (ret > 0) {
      total += ret;
    } else {
      int err = SSL_get_error(ssl, ret);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        continue;
      }
      // Fatal error
      free(data_buffer);
      return NULL;
    }
  }

  Frame *frame = malloc(sizeof(Frame));
  if (!frame) {
    free(data_size);
    free(data_buffer);
    return NULL;
  }

  frame->d_size = *data_size;
  frame->data = data_buffer;
  memcpy(frame->prefix, PREFIX, PREFIX_SIZE);
  free(data_size);
  return frame;
}

int ssl_write_n_bytes(SSL *ssl, const void *data, size_t size) {
  size_t total_written = 0;

  int bytes_written =
      SSL_write(ssl, data + total_written, size - total_written);
  if (bytes_written <= 0) {
    return -1;
  }
  total_written += bytes_written;
  return 0; // success
}

int main() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  const SSL_METHOD *method = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL *ssl = SSL_new(ctx);
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(atoi(PORT));
  inet_pton(AF_INET, SERVER, &server_addr.sin_addr);

  if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("connect");
    return 1;
  }

  int ret_val = 1;
  SSL_set_fd(ssl, sock);
  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
  } else {
    // create data to be sent
    Frame frame = {.data = REQ_DATA, .d_size = REQ_DATA_SIZE, .prefix = PREFIX};
    size_t net_size;
    void *data = serialize_frame(&frame, &net_size);

    // write data to server
    ssl_write_n_bytes(ssl, data, net_size);

    int frame_count = 0;
    // read response from server
    while (frame_count < MAX_REC_FRAME) {
      Frame *rec_frame = ssl_read_bytes(ssl);
      if (rec_frame) {
        printf("RECEIVED DATA: %.*s\n", (int)rec_frame->d_size,
               (char *)rec_frame->data);
        printf("SIZE OF RECEIVED DATA IS %lu\n", rec_frame->d_size);
      }

      if (strncmp(rec_frame->data, END_DATA, END_DATA_SIZE) == 0) {
        ret_val = 0;
      }
      free(rec_frame->data);
      free(rec_frame);
      frame_count++;
    }
    free(data);
  }

  SSL_free(ssl);
  close(sock);
  SSL_CTX_free(ctx);
  puts("returning 0");
  return ret_val;
}
