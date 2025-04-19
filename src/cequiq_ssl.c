#include "cequiq_ssl.h"
#include "cequiq.h"
#include "cequiq_entry.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int store_certificate_hash(const char *cert) {
  FILE *cert_file = fopen(cert, "r");
  if (!cert_file) {
    LOG("failed to open certificate file");
    return -1;
  }

  X509 *certificate = PEM_read_X509(cert_file, NULL, NULL, NULL);
  fclose(cert_file);
  if (!certificate) {
    LOG("unable to load certificate");
    return -1;
  }
  EVP_PKEY *public_key = X509_get_pubkey(certificate);
  if (!public_key) {
    X509_free(certificate);
    LOG("unable to extract public key from certificate");
    return -1;
  }

  unsigned char *pubkey_buf = NULL;
  int pubkey_len = i2d_PUBKEY(public_key, &pubkey_buf);
  if (pubkey_len < 0) {
    EVP_PKEY_free(public_key);
    X509_free(certificate);
    LOG("unable to convert public key to DER format");
    return -1;
  }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  if (!SHA256(pubkey_buf, pubkey_len, hash)) {
    EVP_PKEY_free(public_key);
    X509_free(certificate);
    OPENSSL_free(pubkey_buf);
    LOG("failed to compute sha256 hash of public key");
    return -1;
  }

  char *hash_str = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
  if (!hash_str) {
    EVP_PKEY_free(public_key);
    X509_free(certificate);
    OPENSSL_free(pubkey_buf);
    LOG("malloc failed");
    return -1;
  }

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(&hash_str[i * 2], "%02x", hash[i]);
  }

  EVP_PKEY_free(public_key);
  OPENSSL_free(pubkey_buf);
  X509_free(certificate);

  // calculate the file path where certifacation hash will be stored
  size_t hash_file_location_size =
      strlen(SERVER_DIRECTORY) + strlen(CERT_HASH_FILE_NAME) + 2;
  char *hash_file_location = malloc(hash_file_location_size);
  if (!hash_file_location) {
    LOG("malloc failed");
    free(hash_str);
    return -1;
  }
  snprintf(hash_file_location, hash_file_location_size, "%s/%s",
           SERVER_DIRECTORY, CERT_HASH_FILE_NAME);

  // store certificate hash to storage
  FILE *hash_file = fopen(hash_file_location, "wb");
  if (hash_file != NULL) {
    fwrite(hash_str, 1, strlen(hash_str), hash_file);
    fclose(hash_file);
  } else {
    LOG("Error opening the file");
  }

  // not explicitly checking if fwrite succeeds because it's returning anyways

  free(hash_file_location);
  free(hash_str);
  return 0;
};

typedef struct {
  char *cert_path;
  char *pkey_path;
  int error;
} CertPaths;

// calculate certicate file and private key file paths
CertPaths get_cert_paths(const CequiqConfig *config) {
  size_t path_size = strlen(config->server_directory);
  size_t cert_name_size = strlen(config->certificate_file_name);
  size_t pkey_name_size = strlen(config->private_key_file_name);
  size_t cert_path_size = path_size + cert_name_size + 2;
  size_t pkey_path_size = path_size + pkey_name_size + 2;

  char *cert_path = malloc(cert_path_size);
  char *pkey_path = malloc(pkey_path_size);

  if (!cert_path || !pkey_path) {
    LOG("malloc failed");
    free(cert_path);
    free(pkey_path);
    return (CertPaths){.cert_path = NULL, .pkey_path = NULL, .error = -1};
  }
  snprintf(cert_path, cert_path_size, "%s/%s", config->server_directory,
           config->certificate_file_name);
  snprintf(pkey_path, pkey_path_size, "%s/%s", config->server_directory,
           config->private_key_file_name);
  return (CertPaths){
      .cert_path = cert_path, .pkey_path = pkey_path, .error = 0};
}

void free_cert_paths(CertPaths paths) {
  free(paths.cert_path);
  free(paths.pkey_path);
}

SSL_CTX *init_openssl_ctx(const CequiqConfig *config) {
  SSL_CTX *ctx = NULL;
  long opts;
  CertPaths paths = get_cert_paths(config);

  if (paths.error < 0) {
    goto cleanup;
  }
  if (store_certificate_hash(paths.cert_path) < 0) {
    goto cleanup;
  }

  ctx = SSL_CTX_new(TLS_server_method());
  if (ctx == NULL) {
    LOG("Failed to create new SSL context");
    goto cleanup;
  }

  // set minumum TLS version to TLS 1.2
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
    LOG("Failed to set minimum TLS version to TLS 1.2");
    goto cleanup;
  }

  /*
   * Tolerate clients hanging up without a TLS "shutdown".  Appropriate in all
   * application protocols which perform their own message "framing", and
   * don't rely on TLS to defend against "truncation" attacks.
   */
  opts = SSL_OP_IGNORE_UNEXPECTED_EOF;

  /*
   * Block potential CPU-exhaustion attacks by clients that request frequent
   * renegotiation.  This is of course only effective if there are existing
   * limits on initial full TLS handshake or connection rates.
   */
  opts |= SSL_OP_NO_RENEGOTIATION;

  /*
   * Most servers elect to use their own cipher preference rather than that of
   * the client.
   */
  opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;

  /* Apply the selection options */
  SSL_CTX_set_options(ctx, opts);

  // Load the server's certificate chain file (PEM format)
  if (SSL_CTX_use_certificate_chain_file(ctx, paths.cert_path) <= 0) {
    LOG("Failed to load certificate chain file");
    goto cleanup;
  }
  // Load the corresponding private key, this also checks that the private
  // key matches the just loaded certificate.
  if (SSL_CTX_use_PrivateKey_file(ctx, paths.pkey_path, SSL_FILETYPE_PEM) <=
      0) {
    LOG("Failed to load private key file");
    goto cleanup;
  }

  /*
   * Servers that want to enable session resumption must specify a cache id
   * byte array, that identifies the server application, and reduces the
   * chance of inappropriate cache sharing.
   */
  SSL_CTX_set_session_id_context(ctx, (void *)config->ssl_cache_id,
                                 strlen(config->ssl_cache_id));
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

  /*
   * How many client TLS sessions to cache.  The default is
   * SSL_SESSION_CACHE_MAX_SIZE_DEFAULT (20k in recent OpenSSL versions),
   * which may be too small or too large.
   */
  SSL_CTX_sess_set_cache_size(ctx, 1024);

  /*
   * Sessions older than this are considered a cache miss even if still in
   * the cache.  The default is two hours.  Busy servers whose clients make
   * many connections in a short burst may want a shorter timeout, on lightly
   * loaded servers with sporadic connections from any given client, a longer
   * time may be appropriate.
   */
  SSL_CTX_set_timeout(ctx, 3600);

  /*
   * Clients rarely employ certificate-based authentication, and so we don't
   * require "mutual" TLS authentication (indeed there's no way to know
   * whether or how the client authenticated the server, so the term "mutual"
   * is potentially misleading).
   *
   * Since we're not soliciting or processing client certificates, we don't
   * need to configure a trusted-certificate store, so no call to
   * SSL_CTX_set_default_verify_paths() is needed.  The server's own
   * certificate chain is assumed valid.
   */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  free_cert_paths(paths);
  return ctx;

cleanup:
  SSL_CTX_free(ctx);
  free_cert_paths(paths);
  return NULL;
};

SSL_CTX *setup_ssl(const CequiqConfig *cequiq) {
  SSL_CTX *ctx = NULL;

  ctx = init_openssl_ctx(cequiq);
  if (ctx == NULL) {
    return NULL;
  }
  return ctx;
}

int execute_ssl_handshake(SSL_CTX *ctx, SSL **ssl_ptr, const int fd) {
  SSL *ssl;

  if (*ssl_ptr == NULL) {
    // Only create a new SSL object if one doesn't exist
    if ((ssl = SSL_new(ctx)) == NULL) {
      LOG("failed to create new SSL object");
      return -1;
    }

    if (SSL_set_fd(ssl, fd) == 0) {
      LOG("failed to associate file descriptor with SSL object");
      SSL_free(ssl);
      return -1;
    }

    *ssl_ptr = ssl;
  } else {
    ssl = *ssl_ptr;
  }

  int ret = SSL_accept(ssl);
  // if handshake is not complete
  if (ret <= 0) {
    int err = SSL_get_error(ssl, ret);
    // if error is SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE then return 1
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      return 1;
    } else {
      // indicate handshake faild by returning -1;
      char err_buf[1256];
      ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
      LOG("SSL handshake failed. OpenSSL error: %d, %s", err, err_buf);
      SSL_free(ssl);
      *ssl_ptr = NULL;
      return -1;
    }
  }
  LOG(GREEN "---TLS HANDSHAKE SUCCESSFUL---" RESET);
  return 0;
}
