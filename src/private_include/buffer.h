#pragma once
#include "cequiq_entry.h"
#include "cequiq.h"
#include <openssl/ssl.h>

int read_data(CequiqConfig *config);
WriteNode *create_write_node(WriteBuffer *write_buffer);
// int write_queue(const char *conn_id, void *data, uint64_t size);
int cequiq_write_ssl(int fd);

void clear_write_queue(WriteNode **head);

