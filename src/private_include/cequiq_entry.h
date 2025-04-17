#pragma once
#include <stdint.h>
#include <openssl/ssl.h>
#include <uthash.h>
// #include "cequiq.h"

#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define RESET "\x1b[0m"
#define ORANGE "\x1b[38;5;214m"


#ifdef DEBUG
    #define LOG(fmt, ...) printf(GREEN "[+] " RESET fmt "\n", ##__VA_ARGS__)
#else
    #define LOG(fmt, ...)
#endif

#ifndef UUID_STR_LEN
#define UUID_STR_LEN 37 // 36 chars + null terminator
#endif


#define PORT 4343
#define MAX_DATA_FRAME_SIZE 1024 * 1024
#define MIN_DATA_FRAME_SIZE 1
#define MAX_CONNECTION_ID_SIZE 37
#define SERVER_DIRECTORY "./server_files"
#define CERTIFICATE_FILE_NAME "certificate.pem"
#define PRIVATE_KEY_FILE_NAME "private_key.pem"
#define APP_DATA_SIZE 0
#define CERT_HASH_FILE_NAME "cert_hash.txt"
#define SSL_CACHE_ID "cequiq"
#define PREFIX "XOXO"
enum { PREFIX_LENGTH = sizeof(PREFIX) - 1 }; 
enum { HEAD_SIZE = sizeof(PREFIX) + 7 }; // 8 btyes to indicate how long the data frame is


typedef struct {
    uint64_t buffer_size;
    void *buffer;
    uint64_t total_written;
} WriteBuffer;

typedef struct WriteNode {
    WriteBuffer *data;
    struct WriteNode *next;
} WriteNode;


typedef struct {
  int fd;
  SSL *ssl; 

  void *read_buffer;  
  uint64_t read_bytes;
  uint64_t read_buf_size;

  WriteNode *write_queue;

  UT_hash_handle hh;
} FD_MAP;

typedef struct {
  int fd;
  char *id;
  UT_hash_handle hh;
} ID_MAP;


typedef struct {
  ID_MAP **id_map;
  ID_MAP **reverse_id_map; // for retriving fd, when only have access to id
  FD_MAP **fd_map;
  int current_fd;
}CequiqState;
