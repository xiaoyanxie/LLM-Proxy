#ifndef PROXY_CLIENT_H
#define PROXY_CLIENT_H

#include "kv_helpers.h"
#include "http_parser.h"
#include <openssl/ssl.h>
#include <ctype.h>
#define TLS_BUF_SIZE 8 * 1024
#define CONN_IO_BUF_SIZE 4 * 1024
#define MAX_HOSTNAME_SIZE 253


struct proxy_session {
  int c_fd;
  SSL *c_ssl;
  int h_fd;
  SSL *h_ssl;
  char hostname[MAX_HOSTNAME_SIZE];
  int host_port;
  byte_array cth_buf_in;
  byte_array cth_buf_out;
  byte_array htc_buf_in;
  byte_array htc_buf_out;
  http_parser htc_parser;
  http_parser cth_parser;
  int is_https;
};

struct proxy_session *make_session(int fd, SSL_CTX *c_ctx, SSL_CTX *h_ctx);

void free_session(struct proxy_session *s);

int session_establish_SSL(struct proxy_session *s, X509 *cert, EVP_PKEY *key);

int session_serve(struct proxy_session *s);

int session_serve_https(struct proxy_session *s);
int session_serve_http(struct proxy_session *s);

#endif
