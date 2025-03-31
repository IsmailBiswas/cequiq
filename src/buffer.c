#include "buffer.h"
#include "cequiq.h"
#include "cequiq_entry.h"
#include "fd_association.h"
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef DEBUG
// debug function
void print_ssl_error(SSL *ssl, int ret) {
  int err = SSL_get_error(ssl, ret);
  LOG("---SSL error %d", err);
  unsigned long e;

  switch (err) {
  case SSL_ERROR_ZERO_RETURN:
    printf("SSL connection closed cleanly\n");
    break;
  case SSL_ERROR_WANT_READ:
  case SSL_ERROR_WANT_WRITE:
    printf("SSL operation did not complete, try again\n");
    break;
  case SSL_ERROR_SYSCALL:
    perror("SSL syscall error");
    break;
  case SSL_ERROR_SSL:
    while ((e = ERR_get_error()) != 0) {
      printf("SSL error: %s\n", ERR_error_string(e, NULL));
    }
    break;
  default:
    printf("Unknown SSL error\n");
  }
}

#endif

WriteNode *create_write_node(WriteBuffer *write_buffer) {
  WriteNode *new_node = malloc(sizeof(WriteNode));
  if (!new_node) {
    return NULL;
  }

  new_node->data = write_buffer;
  new_node->next = NULL;
  return new_node;
};

void write_node_insert_at_tail(WriteNode **head, WriteNode *new_node) {
  if (*head == NULL) {
    *head = new_node;
    return;
  }

  WriteNode *temp = *head;
  while (temp->next != NULL)
    temp = temp->next;
  temp->next = new_node;
};

void clear_write_queue(WriteNode **head) {
  WriteNode *temp = *head;

  // if the first pointer is NULL then the list is empty, so just return
  if (!temp) {
    LOG(ORANGE "write queue is empty " RESET);
    return;
  }

  while (temp) {
    LOG(ORANGE "freeing write queue" RESET);
    WriteNode *next = temp->next;

    free(temp->data->buffer);
    free(temp->data);
    free(temp);

    temp = next;
  }

  *head = NULL;
}

// TODO: it should just delete the first node
void write_node_delete(WriteNode **head, WriteBuffer *node) {
  LOG("FREEING node");
  WriteNode *temp = *head, *prev = NULL;

  if (temp != NULL && temp->data == node) {
    *head = temp->next;
    free(node->buffer); // freeing the actual buffer
    node->buffer = NULL;
    free(node);
    node = NULL;
    free(temp);
    temp = NULL;
    return;
  }

  // search list
  while (temp != NULL && temp->data != node) {
    prev = temp;
    temp = temp->next;
  }

  // item not found
  if (temp == NULL)
    return;

  // snip current and free
  prev->next = temp->next;
  free(temp->data->buffer);
  temp->data->buffer = NULL;
  free(temp);
}

uint64_t ntohll(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return ((uint64_t)ntohl(val & 0xFFFFFFFF) << 32) | ntohl(val >> 32);
#else
  return val;
#endif
}

uint64_t htonll(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return ((uint64_t)htonl(val & 0xFFFFFFFF) << 32) | htonl(val >> 32);
#else
  return val;
#endif
}

int validate_frame(SSL *ssl, uint64_t *frame_size) {
  char head[HEAD_SIZE];
  int read_bytes = SSL_read(ssl, head, HEAD_SIZE);
  if (read_bytes <= 0) {
    if (SSL_get_error(ssl, read_bytes) == SSL_ERROR_WANT_READ) {
      LOG(ORANGE "WAITING FOR DATA" RESET);
    }
    return (SSL_get_error(ssl, read_bytes) == SSL_ERROR_WANT_READ) ? 0 : -1;
  }

  if (read_bytes != HEAD_SIZE) {
    fprintf(stderr, RED "malformed data: data too short for header\n" RESET);
    return -1;
  }

  if (memcmp(head, PREFIX, PREFIX_LENGTH) != 0) {
    fprintf(stderr, RED "malformed data: missing prefix %s\n" RESET, PREFIX);
    LOG("data frame didn't start with: %s", PREFIX);
    return -1;
  }

  uint64_t n_frame_size;
  memcpy(&n_frame_size, head + PREFIX_LENGTH, sizeof(uint64_t));
  uint64_t requested_frame_size = ntohll(n_frame_size);
  LOG("Requested frame size %lu bytes", requested_frame_size);

  if (requested_frame_size > MAX_DATA_FRAME_SIZE) {
    LOG("client tried to send more data than maximum allowed");
    return -1;
  }

  *frame_size = requested_frame_size;
  return 1;
};

// should only return -1 if there is a applicaiton error
int read_data(CequiqConfig *config) {
  SSL *ssl = get_ssl_by_fd(CONN);
  uint64_t *total_read = get_buf_read_size();
  uint64_t *frame_size = get_frame_size();

  int continue_reading = 1;
  int should_free_buffer = 0;
  int read_bytes = 0;
  // will store the pointer address to the read buffer for current connection
  void **read_buffer;

  while (continue_reading) {
    if (total_read == NULL) {
      LOG("total_read should be 0 but it is set to NULL, something went wrong");
      return -1;
    }

    // if total_read 0 then that means it's a start of new frame
    if (*total_read == 0) {
      int ret = validate_frame(ssl, frame_size);
      if (ret <= 0) {
        return ret;
      }

      // get pointer address of the current connection's read buffer and store
      // it
      read_buffer = get_read_buf();
      // store the new malloc address in the current buffer's pointer
      *read_buffer = malloc(*frame_size);

      if (!*read_buffer) {
        LOG("malloc failed");
        return -1;
      }
    } else {
      read_buffer = get_read_buf();
    }

    // read until error is returned. if the error is SSL_ERROR_WANT_READ then
    // epoll will wait for more data, in case of other errors caller of this
    // fucntion decides what to do.
    while (1) {
      read_bytes =
          SSL_read(ssl, *read_buffer + *total_read, *frame_size - *total_read);
      if (read_bytes <= 0) {
        break;
      }
      *total_read += read_bytes;
    }

    // if the error is other SSL_ERROR_WANT_READ then read buffer will be freed
    // and connection will be closed
    if (read_bytes <= 0) {
      if (SSL_get_error(ssl, read_bytes) != SSL_ERROR_WANT_READ) {
        print_ssl_error(ssl, read_bytes);
        should_free_buffer = 1;
      }
    }

    if (*total_read == *frame_size) {
      config->data_callback(*read_buffer, *frame_size);
      free(*read_buffer);
      *read_buffer = NULL;
      *frame_size = 0;
      *total_read = 0;
    }

    // Q: could I get stuck here? like SSL_pending returns >0 value but SSL_read
    // is unable to read it?
    if (SSL_pending(ssl) <= 0) {
      continue_reading = 0;
    }

    if (should_free_buffer) {
      free(*read_buffer);
      *read_buffer = NULL;
      return -1;
    }
  }

  return 0;
}

// write data to client
int cequiq_write_ssl(int fd) {
  SSL *ssl = get_ssl_by_fd(fd);
  if (ssl == NULL) {
    LOG("DIDN'T FIND SSL OBJECT");
    return -1;
  }

  uint64_t *total_write = get_total_write(fd);
  if (total_write == NULL) {
    LOG("DIDN'T FIND total_write");
    return -1;
  }

  uint64_t write_buf_size = get_write_data_size(fd);

  void *write_buf = get_write_data(fd);
  if (write_buf == NULL) {
    return -1;
  }

  int write_bytes = 0;
  while (*total_write < write_buf_size) {
    write_bytes =
        SSL_write(ssl, write_buf + *total_write, write_buf_size - *total_write);

    if (write_bytes > 0) {
      *total_write += write_bytes;
    }

    if (write_bytes <= 0) {
      break;
    }
  }

  if (*total_write == write_buf_size) {
    WriteNode **write_queue_head = get_write_queue_head(fd);
    write_node_delete(write_queue_head, (*write_queue_head)->data);
  }

  return 0;
}

typedef struct {
  char prefix[PREFIX_LENGTH];
  uint64_t d_size;
  void *data;
} Frame;

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

  // I wish was not copying this
  if (f->data && f->d_size > 0) {
    memcpy(ptr, f->data, f->d_size);
  }

  return buffer;
}

static int write_queue(const char *conn_id, void *data, uint64_t data_size) {
  size_t net_size;
  Frame f = {.prefix = PREFIX, .d_size = data_size, .data = data};
  void *s_data = serialize_frame(&f, &net_size);
  free(data);

  WriteBuffer *write_buffer = malloc(sizeof(WriteBuffer));
  if (!write_buffer) {
    return -1;
  }
  write_buffer->buffer = s_data;
  write_buffer->buffer_size = net_size;
  write_buffer->total_written = 0;

  // if a conn_id is null then is it considered that data is to be sent to same
  // connection who tiggerd the event
  int fd;
  if (conn_id == NULL) {
    fd = CONN;
  } else {
    fd = get_fd_by_id(conn_id);
    if (fd < 0) {
      return -1;
    };
  }
  WriteNode **write_queue_head = get_write_queue_head(fd);
  WriteNode *new_node = create_write_node(write_buffer);
  write_node_insert_at_tail(write_queue_head, new_node);

  cequiq_write_ssl(fd);
  return 0;
}

/* write_queue wrapper */
int cequiq_write(const char *conn_id, void *data, uint64_t size) {
  return write_queue(conn_id, data, size);
}
