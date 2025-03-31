#pragma once

#include "cequiq_entry.h"
#include <openssl/ssl.h>
#include <stdint.h>

#define CONN -1


// add a mapping between connection file descriptor(fd) and the ssl object
int add_ssl_to_fd_map(SSL *ssl);


// returns a ssl object when a fd is provied, if `CONN`
// is provided reutns current connction's ssl object
SSL *get_ssl_by_fd(int fd);

void remove_ssl_to_fd_map();

// returns how much has been read for the current frame
uint64_t *get_buf_read_size();

// returns what is the current frame size 
uint64_t *get_frame_size();

// returns a pointer where read data is getting stored
void *get_read_buf();

// set the `id` for current connection
int set_id_to_fd(char *id);

// set provided `id` to current `fd`, this is inverse of `set_id_to_fd`
int set_fd_to_id(char *id);

// returns `fd` when a `id` is provided
int get_fd_by_id(const char *id);

// returns number of total byte written for the first queued buffer of a provided fd
uint64_t *get_total_write(int fd);

// returns address of write buffer
void *get_write_data(int fd);

// get size of the data which currently is getting written
uint64_t get_write_data_size(int fd);

void remove_id_to_fd_map();

// returns current connection's `id`
const char *get_current_id();

// returns the linklist head of the provided `fd` write queue
WriteNode **get_write_queue_head(int fd);


