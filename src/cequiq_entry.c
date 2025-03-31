#include "cequiq_entry.h"
#include "tcp_ssl.h"
#include <err.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <limits.h>
#include <stdio.h>
#include <unistd.h>
CequiqState *cequiq_state = NULL;

CequiqConfig *Cequiq_init() {
  CequiqConfig *config = malloc(sizeof(CequiqConfig));
  if (!config) {
    return NULL;
  }

  config->port_number = PORT;
  config->max_data_frame_size = MAX_DATA_FRAME_SIZE;
  config->certificate_file_name = CERTIFICATE_FILE_NAME;
  config->private_key_file_name = PRIVATE_KEY_FILE_NAME;
  config->server_directory = SERVER_DIRECTORY;
  config->ssl_cache_id = SSL_CACHE_ID;
  config->data_callback = NULL;
  config->close_callback = NULL;
  return config;
}

int validate_config(const CequiqConfig *cequiq) {
  if (cequiq->max_data_frame_size < MIN_DATA_FRAME_SIZE) {
    return -1;
  }
  if (cequiq->data_callback == NULL) {
    return -1;
  }
  if (cequiq->close_callback == NULL) {
    return -1;
  }

  return 0;
}

int create_internal_state() {
  cequiq_state = malloc(sizeof(CequiqConfig));
  if (!cequiq_state) {
    return -1;
  }

  FD_MAP **fd_map = malloc(sizeof(FD_MAP *));
  if (!fd_map) {
    free(cequiq_state);
    return -1;
  }
  *fd_map = NULL;

  ID_MAP **id_map = malloc(sizeof(ID_MAP *));
  if (!id_map) {
    free(fd_map);
    free(cequiq_state);
    return -1;
  }
  *id_map = NULL;

  ID_MAP **reverse_id_map = malloc(sizeof(ID_MAP *));
  if (!reverse_id_map) {
    free(fd_map);
    free(id_map);
    free(cequiq_state);
    return -1;
  }
  *reverse_id_map = NULL;

  cequiq_state->fd_map = fd_map;
  cequiq_state->id_map = id_map;
  cequiq_state->reverse_id_map = reverse_id_map;

  return 0;
}

void free_internal_state() {
  free(cequiq_state->fd_map);
  free(cequiq_state->id_map);
  free(cequiq_state);
}

int cequiq_start(CequiqConfig *config) {
  LOG("---CEQUIQ---");
  if (validate_config(config) < 0) {
    fprintf(stderr, "error: invalid config\n");
    return -1;
  };

  if (create_internal_state() == -1)
    return -1;

  LOG("starting cequiq server...");
  signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE
  start_listening(config);
  free_internal_state();
  return -1;
};
