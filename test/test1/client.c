#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERVER "localhost"
#define PORT "4433"

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

  SSL_set_fd(ssl, sock);
  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
  } else {
    printf("TLS handshake successful\n");
  }

  SSL_free(ssl);
  close(sock);
  SSL_CTX_free(ctx);
  puts("returning 0");
  return 0;
}
