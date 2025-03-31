#pragma once

#include <stddef.h>
#include <openssl/ssl.h>
#include "cequiq.h"

SSL_CTX *setup_ssl(const CequiqConfig *config);
int execute_ssl_handshake(SSL_CTX *ctx, SSL **ssl, const int fd);

