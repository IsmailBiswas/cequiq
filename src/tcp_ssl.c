#include "tcp_ssl.h"
#include "buffer.h"
#include "cequiq_entry.h"
#include "cequiq_ssl.h"
#include "fd_association.h"
#include "internal.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uuid/uuid.h>

void terminate_connection(CequiqConfig *config, int fd, int epollfd);
int make_socket(uint16_t port) {
  int sock;
  struct sockaddr_in name;

  // Create a TCP socket
  sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    LOG("Failed to create socket");
    return -1;
  }

  int opt = 1;

  // Allow socket to reuse address (prevents "Address already in use" error)
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    LOG("Failed to set SO_REUSEADDR on socket");
    return -1;
  }

  // Enable keepalive to detect broken connections
  if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
    LOG("Failed to set SO_KEEPALIVE on socket");
    return -1;
  }

  // Set up the socket address structure
  name.sin_family = AF_INET;   // Use IPv4
  name.sin_port = htons(port); // Convert port to network byte order
  name.sin_addr.s_addr =
      htonl(INADDR_ANY); // Accept connections on any interface

  // Bind the socket to the specified port
  if (bind(sock, (struct sockaddr *)&name, sizeof(name)) < 0) {
    LOG("error:failed to bind socket to address: %s\n", strerror(errno));
    return -1;
  }

  return sock;
}

char *generate_uuid() {
  uuid_t uuid;
  char *uuid_str = malloc(UUID_STR_LEN);

  if (!uuid_str)
    return NULL;

  uuid_generate(uuid);
  uuid_unparse(uuid, uuid_str);

  return uuid_str;
}

// use epoll to handle multiple connections.

int set_nonblocking(const int sockfd) {
  int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags == -1) {
    return -1;
  }

  if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
    return -1;
  }
  return 0;
}

int start_listening(CequiqConfig *config) {
  int listen_socket = make_socket(config->port_number);
  if (listen_socket == -1)
    return -1;

  if (listen(listen_socket, 10) < 0) {
    LOG("failed to listen on socket: %s", strerror(errno));
    return -1;
  }

  if (listen_socket == -1) {
    return -1;
  }
  int epollfd, nfds, n, fd;
  struct sockaddr_in addr;
  socklen_t addr_size = sizeof(addr);

  struct epoll_event ev, events[MAX_EVENTS];
  epollfd = epoll_create1(0);
  if (epollfd == -1) {
    LOG("unable to create epoll instance");
    return -1;
  }

  ev.events = EPOLLIN;
  ev.data.fd = listen_socket;

  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_socket, &ev) == -1) {
    LOG("unable to register new socket with epoll");
    return -1;
  }

  SSL *ssl;
  SSL_CTX *ctx = setup_ssl(config);
  if (ctx == NULL) {
    return -1;
  }

  while (1) {
    nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    if (nfds == -1) {
      if (errno == EINTR) {
        LOG("epoll_wait() is interrupted by EINTR signal");
        continue; // Retry if interrupted by a signal
      }
      LOG("`epoll_wait()` returned an unrecoverable status, terminating...");
      return -1;
    }

    for (n = 0; n < nfds; n++) {
      // check if event is on the listen socket
      if (events[n].data.fd == listen_socket) {
        // accept new connection
        fd = accept(listen_socket, (struct sockaddr *)&addr, &addr_size);
        cequiq_state->current_fd = fd;
        if (fd < 0) {
          if (errno == EINTR) {
            LOG("was not able to `accept` new connection, received EINTR "
                "singal");
            continue; // Retry if interrupted by a signal
          }
          LOG("`accept()` returned an unrecoverable status: %s",
              strerror(errno));
          return -1;
        }

        // make new socket nonblocking
        if (set_nonblocking(fd) < 0) {
          LOG("failed to set nonblocking mode, closing connection and "
              "continuing...");
          close(fd);
          continue;
        };

        // configure epoll to monitor conn_sock.
        ev.events = EPOLLIN | EPOLLET | EPOLLOUT | EPOLLRDHUP | EPOLLERR;
        ev.data.fd = fd;

        // register new socket with epoll
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
          LOG("unable to register new socket with epoll, closing connection "
              "and continuing...");
          close(fd);
          continue;
        }

        ssl = NULL;
        // Try to complete ssl handshake, returns -1 on unrecoverable error
        int ret = execute_ssl_handshake(ctx, &ssl, fd);
        char *connection_id = generate_uuid();

        if (ret == -1 || connection_id == NULL) {
          epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
          close(fd);
          continue;
        };

        // stores the ssl objet in a hashmap
        if (add_ssl_to_fd_map(ssl) == -1) {
          // if add_ssl_to_fd_map fails, no need to call remove_ssl_to_fd_map()
          // because it only fails before allocating resources
          epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
          close(fd);
          continue;
        };

        if (set_fd_to_id(connection_id) == -1) {
          epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
          remove_ssl_to_fd_map();
          close(fd);
          continue;
        };

        if (set_id_to_fd(connection_id) == -1) {
          epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
          remove_ssl_to_fd_map();
          remove_id_to_fd_map();
          close(fd);
          continue;
        };

      } else {
        fd = events[n].data.fd;
        cequiq_state->current_fd = fd;

        // retrives stored ssl object from the hashmap
        ssl = get_ssl_by_fd(CONN);

        // if handshake is not complete then retries to complete it
        if (ssl != NULL && SSL_is_init_finished(ssl) == 0) {
          if (execute_ssl_handshake(ctx, &ssl, fd) == -1) {
            terminate_connection(config, fd, epollfd);
          }
        }

        // reed application data
        int read_error = 0;
        if (SSL_is_init_finished(ssl) == 1) {
          if (events[n].events & (EPOLLIN)) {
            read_error = read_data(config);
          }
        }

        // close the connection if peer has closed it's end or data frame was
        // invalid i.e read_data returned -1
        if (events[n].events & (EPOLLERR | EPOLLHUP) || read_error == -1) {
          terminate_connection(config, fd, epollfd);
        } else if (events[n].events & (EPOLLOUT)) {
          WriteNode **head = get_write_queue_head(fd);
          if (*head != NULL) {
            cequiq_write_ssl(fd);
          }
        }
      }
    }
  }
  LOG("---BREAKING OUT OF THE LOOP---");
}

void terminate_connection(CequiqConfig *config, int fd, int epollfd) {

  const char *device_id = get_current_id();
  config->close_callback(device_id);

  WriteNode **head = get_write_queue_head(CONN);
  clear_write_queue(head);

  LOG(RED "---CLOSING CONNECTION---" RESET);

  SSL *ssl = get_ssl_by_fd(CONN);

  // shutdown connection
  if (SSL_is_init_finished(ssl) == 1) {
    SSL_shutdown(ssl);
  }

  // stop monitoring fd
  epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);

  // free FD_MAP resource
  remove_ssl_to_fd_map();

  // free ID_MAP resource
  remove_id_to_fd_map();

  close(fd);
}
