#include "cequiq.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define REQ_DATA "ping"
#define REQ_DATA_SIZE (sizeof(REQ_DATA) - 1)

#define RES_DATA "pong"
#define RES_DATA_SIZE (sizeof(RES_DATA) - 1)

void data_callback(const void *data, uint64_t size) {
  (void)size;
  LOG("DATA CALLBACK FUNCTION");
  if (strncmp(data, REQ_DATA, RES_DATA_SIZE) == 0) {
    char *res_data = strdup(RES_DATA);
    cequiq_write(NULL, res_data, sizeof(RES_DATA) - 1);
  } else {
    char *res_data = strdup("uwu");
    cequiq_write(NULL, res_data, sizeof(RES_DATA) - 1);
  }
}

void close_callback(const char *device_id) {
  LOG("CLOSE CALLBACK FUNCTION");
  (void)device_id;
};

int main() {
  CequiqConfig *config = Cequiq_init();

  if (config == NULL) {
    LOG("failed to create cequiq config");
  }

  config->port_number = 4433;
  config->data_callback = data_callback;
  config->max_data_frame_size = 1024 * 1024;
  config->ssl_cache_id = "cequiq";
  config->close_callback = close_callback;
  config->private_key_file_name = "private_key.pem";
  config->certificate_file_name = "certificate.pem";
  config->server_directory = "./server_files";
  cequiq_start(config);
  return 0;
}
