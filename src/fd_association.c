#include "fd_association.h"
#include "cequiq.h"
#include "cequiq_entry.h"
#include "internal.h"
#include <stdint.h>
#include <string.h>
#include <uthash.h>
#include <uuid/uuid.h>

// stores ssl object in a hashmap which is keyed with the current connection's
// file descriptor number
int add_ssl_to_fd_map(SSL *ssl) {
  FD_MAP *entry = malloc(sizeof(FD_MAP));

  if (!entry) {
    return -1;
  }

  entry->fd = cequiq_state->current_fd;
  entry->ssl = ssl;
  entry->read_bytes = 0;
  entry->read_buffer = NULL;
  entry->write_queue = NULL;

  HASH_ADD_INT(*cequiq_state->fd_map, fd, entry);
  return 0;
}

// returns a number indicating how many bytes have been read for current frame
// from the ssl application data buffer
uint64_t *get_buf_read_size() {
  FD_MAP *entry;
  HASH_FIND_INT(*cequiq_state->fd_map, &cequiq_state->current_fd, entry);
  // if `fd` is present then it is guaranteed there is a 'node' in the
  // hash-table
  return &entry->read_bytes;
}

// returns current frame size
uint64_t *get_frame_size() {
  FD_MAP *entry;
  HASH_FIND_INT(*cequiq_state->fd_map, &cequiq_state->current_fd, entry);
  // if `fd` is present then it is guaranteed there is a 'node' in the
  // hash-table
  return &entry->read_buf_size;
}

// returns the address of the buffered data pointer
void *get_read_buf() {
  FD_MAP *entry;
  HASH_FIND_INT(*cequiq_state->fd_map, &cequiq_state->current_fd, entry);
  // if `fd` is present then it is guaranteed there is a 'node' in the
  // hash-table
  return &entry->read_buffer;
}

// returns the ssl object for the provided `fd`. If fd is CONN then returns
// current connection's ssl object
SSL *get_ssl_by_fd(int fd) {
  FD_MAP *entry;
  if (fd == CONN) {
    HASH_FIND_INT(*cequiq_state->fd_map, &cequiq_state->current_fd, entry);
  } else {
    HASH_FIND_INT(*cequiq_state->fd_map, &fd, entry);
  }
  // if fd is present then it is guaranteed there is a node in the hash-table
  return entry->ssl;
}

// Removes mapping between ssl object and `fd` and frees associated resources
void remove_ssl_to_fd_map() {
  FD_MAP *entry;
  HASH_FIND_INT(*cequiq_state->fd_map, &cequiq_state->current_fd, entry);
  // if fd is present then it is guaranteed there is a node in the hash-table
  HASH_DEL(*cequiq_state->fd_map, entry);
  SSL_free(entry->ssl);
  free(entry->read_buffer);
  free(entry);
}

// removes connection id to `fd` mapping and freeies resources.
void remove_id_to_fd_map() {
  ID_MAP *entry;
  // if `fd` is present then it is guaranteed there is a 'node' in the
  // hash-table
  HASH_FIND_INT(*cequiq_state->id_map, &cequiq_state->current_fd, entry);
  HASH_DEL(*cequiq_state->id_map, entry);
  free(entry->id);
  free(entry);
}

// creates new mapping between current connection `fd` as key and a new
// connection `id` as value
int set_fd_to_id(char *id) {
  ID_MAP *entry;

  entry = malloc(sizeof(ID_MAP));
  if (!entry)
    return -1;

  entry->id = id;
  entry->fd = cequiq_state->current_fd;
  HASH_ADD_INT(*cequiq_state->id_map, fd, entry);
  return 0;
};

// create a new mapping between a connection `id` as key and the current
// connection `fd` as value. This is the inverse function of `set_fd_to_id`
int set_id_to_fd(char *id) {
  ID_MAP *entry;

  entry = malloc(sizeof(ID_MAP));
  if (!entry)
    return -1;

  entry->id = id;
  entry->fd = cequiq_state->current_fd;
  HASH_ADD_STR(*cequiq_state->reverse_id_map, id, entry);
  return 0;
};

// returns current connection's `id`
const char *get_current_id() {
  ID_MAP *entry;
  HASH_FIND_INT(*cequiq_state->id_map, &cequiq_state->current_fd, entry);
  return entry->id; // it is null terminated.
};

// retuns a `fd` when an `id` is provided. if no `id` is found then returns -1
int get_fd_by_id(const char *id) {

  // copy safe size
  char local_id[UUID_STR_LEN];
  memcpy(local_id, id, UUID_STR_LEN - 1);
  local_id[UUID_STR_LEN - 1] = '\0';

  ID_MAP *entry;
  HASH_FIND_STR(*cequiq_state->reverse_id_map, local_id, entry);
  return entry ? entry->fd : -1;
};

// returns how many bytes has been written for the given `fd`, if `fd` is `CONN`
// then returns current connection's value
uint64_t *get_total_write(int fd) {
  FD_MAP *entry;
  if (fd == CONN) {
    HASH_FIND_INT(*cequiq_state->fd_map, &cequiq_state->current_fd, entry);
  } else {
    HASH_FIND_INT(*cequiq_state->fd_map, &fd, entry);
  }
  // no need to check if entry is `NULL`; if an `fd` exists, an entry is
  // guaranteed this is ensured when accepting the connection
  return entry->write_queue ? &entry->write_queue->data->total_written : NULL;
}

// reutns pointer to the data which getting written for the given `fd`, if `fd`
// is `CONN` then returns current connection's value
void *get_write_data(int fd) {
  FD_MAP *entry;
  if (fd == CONN) {
    HASH_FIND_INT(*cequiq_state->fd_map, &cequiq_state->current_fd, entry);
  } else {
    HASH_FIND_INT(*cequiq_state->fd_map, &fd, entry);
  }
  // no need to check if entry is `NULL`; if an `fd` exists, an entry is
  // guaranteed this is ensured when accepting the connection
  return entry->write_queue ? entry->write_queue->data->buffer : NULL;
}

// returns how big is the data which getting written for the given `fd`, if `fd`
// is `CONN` then returns current connection's value
uint64_t get_write_data_size(int fd) {
  FD_MAP *entry;
  if (fd == CONN) {
    HASH_FIND_INT(*cequiq_state->fd_map, &cequiq_state->current_fd, entry);
  } else {
    HASH_FIND_INT(*cequiq_state->fd_map, &fd, entry);
  }
  return entry ? entry->write_queue->data->buffer_size : 0;
};

// Returns the head of the linked list representing the write queue for the
// given `fd`. If `fd` is `CONN`, it returns the write queue for the current
// connection.

WriteNode **get_write_queue_head(int fd) {
  FD_MAP *entry;
  if (fd == CONN) {
    HASH_FIND_INT(*cequiq_state->fd_map, &cequiq_state->current_fd, entry);
  } else {
    HASH_FIND_INT(*cequiq_state->fd_map, &fd, entry);
  }
  return &entry->write_queue;
}

// A wrapper for `get_current_id` to have a better name for public API and
// returns a copy of the data
char *get_connection_id() {
  const char *id = get_current_id();
  char *copied = strdup(id);
  return copied;
}
