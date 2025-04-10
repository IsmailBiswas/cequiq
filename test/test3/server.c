#include "cequiq.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define END_DATA "END"

void data_callback(const void *data, uint64_t size) {
  (void)data;
  (void)size;
  LOG("DATA CALLBACK FUNCTION");
  LOG("connection id %s", cq_get_connection_id());
  char *res_data = strdup("123456789");
  char *res_data2 = strdup("987654321");
  char *res_data3 = strdup(END_DATA);
  cequiq_write(NULL, res_data, strlen(res_data));
  cequiq_write(NULL, res_data2, strlen(res_data2));
  cequiq_write(NULL, res_data3, strlen(res_data3));
  LOG(GREEN "QUEUED ALL THREE" RESET);
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
  config->max_data_frame_size = 4096;
  config->ssl_cache_id = "cequiq";
  config->close_callback = close_callback;
  config->private_key_file_name = "private_key.pem";
  config->certificate_file_name = "certificate.pem";
  config->server_directory = "./server_files";
  cequiq_start(config);
  return 0;
}
