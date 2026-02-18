#define _GNU_SOURCE

#include "proxy_client.h"
#include "certificate.h"
#include "socket_helpers.h"
#include <ctype.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include "http_parser.h"

int noop_cb(byte_array *parsed, parse_header_result* header_res, void* u_ptr){
  byte_array* out = (byte_array*) u_ptr;
  kv_copy(unsigned char, *out, *parsed);
  return 0;
}


struct proxy_session *make_session(int fd, SSL_CTX *c_ctx, SSL_CTX *h_ctx) {
  struct proxy_session *c =
      (struct proxy_session *)malloc(sizeof(struct proxy_session));
  memset(c, '\0', sizeof(struct proxy_session));
  c->c_fd = fd;
  c->h_fd = -1;
  c->c_ssl = SSL_new(c_ctx);
  SSL_set_fd(c->c_ssl, c->c_fd);
  c->h_ssl = SSL_new(h_ctx);
  kv_init(c->cth_buf_in);
  kv_init(c->cth_buf_out);
  kv_init(c->htc_buf_in);
  kv_init(c->htc_buf_out);
  http_parser_init(&c->htc_parser);
  http_parser_init(&c->cth_parser);
  c->is_https = 0;
  return c;
}

void free_session(struct proxy_session *c) {
  if (!c) return;

  if (c->is_https && c->c_ssl != NULL) {
    SSL_shutdown(c->c_ssl);
    SSL_free(c->c_ssl);
    c->c_ssl = NULL;
  }

  if (c->is_https && c->h_ssl != NULL) {
    SSL_shutdown(c->h_ssl);
    SSL_free(c->h_ssl);
    c->h_ssl = NULL;
  }

  if (c->c_fd >= 0) {
    close(c->c_fd);
    c->c_fd = -1;
  }

  if (c->h_fd >= 0) {
    close(c->h_fd);
    c->h_fd = -1;
  }

  kv_destroy(c->cth_buf_in);
  kv_destroy(c->cth_buf_out);
  kv_destroy(c->htc_buf_in);
  kv_destroy(c->htc_buf_out);

  http_parser_free(&(c->htc_parser));
  http_parser_free(&(c->cth_parser));
}

int session_establish_SSL(struct proxy_session *sess, X509 *cert,
                          EVP_PKEY *key) {
  unsigned char tls_buf[TLS_BUF_SIZE];
  size_t bytes_read = 0;
  int n;
  unsigned char *end_of_header = NULL;

  while (1) {
    n = read(sess->c_fd, tls_buf + bytes_read, TLS_BUF_SIZE - bytes_read);
    if (n <= 0) {
      return 1;
    }
    bytes_read += n;
    end_of_header = memmem(tls_buf, bytes_read, "\r\n\r\n", 4);
    if (end_of_header != NULL) {
      break; // found full header
    }

    if (bytes_read == TLS_BUF_SIZE) {
      write(sess->c_fd, "HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n",
            49);
      printf("Header too large\n");
      return 1;
    }
  }

  size_t header_size = (end_of_header - tls_buf) + 4;

  /* --- Case 1: HTTPS tunnel via CONNECT --- */
  if (bytes_read >= 8 && memcmp(tls_buf, "CONNECT ", 8) == 0) {
    sess->is_https = 1;

    // parse hostname and port from CONNECT line
    unsigned char *hostname = tls_buf + 8;
    unsigned char *eol =
        memmem(hostname, header_size - (hostname - tls_buf), "\r\n", 2);
    size_t line_size = eol - hostname;
    unsigned char *colon = memchr(hostname, ':', line_size);
    size_t hostname_size;
    int port = 443;
    unsigned char *end_of_host =
        (unsigned char *)memchr(hostname, ' ', line_size);
    if (colon == NULL) {
      hostname_size = end_of_host - hostname;
    } else {
      char port_str[8];
      memset(port_str, 0, 8);
      hostname_size = colon - hostname;
      memcpy(port_str, colon + 1, end_of_host - (colon + 1));
      port = atoi(port_str);
    }
    memcpy(sess->hostname, hostname, hostname_size);
    sess->hostname[hostname_size] = '\0';
    sess->host_port = port;

    // reply 200 connection established
    write(sess->c_fd,
          "HTTP/1.1 200 Connection Established\r\nX-Proxy: CS112\r\n\r\n",
          39 + 17);

    size_t remaining_bytes = bytes_read - header_size;
    unsigned char *remaining = tls_buf + header_size;
    (void)remaining;
    (void)remaining_bytes; // currently unused

    // generating leaf cert
    cert_pair leaf_cert = generate_leaf_cert(sess->hostname, key, cert);
    SSL_use_certificate(sess->c_ssl, leaf_cert.cert);
    SSL_use_PrivateKey(sess->c_ssl, leaf_cert.key);

    int flags = fcntl(sess->c_fd, F_GETFL, 0);
    if (flags & O_NONBLOCK) {
      fcntl(sess->c_fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    int ret;
    for (;;) {
      ret = SSL_accept(sess->c_ssl);
      if (ret == 1) break;

      int err = SSL_get_error(sess->c_ssl, ret);
      if (err == SSL_ERROR_SYSCALL && errno == EINTR) {
        continue;
      }
      return 1;
    }

    int host_fd = connect_to_host(sess->hostname, port);
    if (host_fd < 0) {
      ERR_print_errors_fp(stderr);
      printf("TCP connection to host %s failed\n", sess->hostname);
      return 1;
    }
    sess->h_fd = host_fd;
    SSL_set_fd(sess->h_ssl, host_fd);

    // set SNI
    if (!SSL_set_tlsext_host_name(sess->h_ssl, sess->hostname)) {
      fprintf(stderr, "Failed to set SNI for host %s\n", sess->hostname);
      ERR_print_errors_fp(stderr);
      return 1;
    }

    static const unsigned char alpn_http1_1[] = "\x08http/1.1";
    SSL_set_alpn_protos(sess->h_ssl, alpn_http1_1, sizeof(alpn_http1_1) - 1);

    if (SSL_connect(sess->h_ssl) <= 0) {
      printf("SSL_connect with host failed\n");
      ERR_print_errors_fp(stderr);
      return 1;
    }

    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(sess->h_ssl, &alpn, &alpn_len);

    return 0;
  }

  /* --- Case 2: plain HTTP proxy request (no CONNECT) --- */
  sess->is_https = 0;

  // parse Host: header to get target host:port
  unsigned char *host_hdr =
      memmem(tls_buf, header_size, "\r\nHost:", 7);
  if (!host_hdr) {
    // very old/invalid HTTP/1.0 w/o Host
    write(sess->c_fd, "HTTP/1.1 400 Bad Request\r\n\r\n", 28);
    printf("Invalid HTTP request: no Host header\n");
    return 1;
  }

  unsigned char *hstart = host_hdr + 7; // skip "\r\nHost:"
  // skip spaces
  while (hstart < tls_buf + header_size && isspace(*hstart)) {
    hstart++;
  }
  unsigned char *hend =
      memmem(hstart, (tls_buf + header_size) - hstart, "\r\n", 2);
  if (!hend) {
    write(sess->c_fd, "HTTP/1.1 400 Bad Request\r\n\r\n", 28);
    printf("Invalid HTTP request: malformed Host line\n");
    return 1;
  }

  unsigned char *colon = memchr(hstart, ':', hend - hstart);
  int port = 80;
  size_t hostname_size;
  if (colon) {
    hostname_size = colon - hstart;
    char port_str[16];
    size_t port_len = (size_t)(hend - (colon + 1));
    if (port_len >= sizeof(port_str))
      port_len = sizeof(port_str) - 1;
    memcpy(port_str, colon + 1, port_len);
    port_str[port_len] = '\0';
    port = atoi(port_str);
  } else {
    hostname_size = hend - hstart;
  }

  if (hostname_size >= sizeof(sess->hostname))
    hostname_size = sizeof(sess->hostname) - 1;

  memcpy(sess->hostname, hstart, hostname_size);
  sess->hostname[hostname_size] = '\0';
  sess->host_port = port;

  int host_fd = connect_to_host(sess->hostname, port);
  if (host_fd < 0) {
    printf("TCP connection to host %s:%d failed\n", sess->hostname, port);
    return 1;
  }
  sess->h_fd = host_fd;

  // We already read the first HTTP request from client (tls_buf[0..bytes_read)).
  // Feed it into the HTTP request parser so header_result is available
  // and the bytes are staged into cth_buf_out to be sent to the origin.
  kv_push_bytes(&sess->cth_buf_in, tls_buf, bytes_read);
  int status = http_parser_process(&sess->cth_parser,
                                   &sess->cth_buf_in,
                                   HTTP_MSG_REQUEST,
                                   &noop_cb,
                                   &sess->cth_buf_out);
  if (status > 0) {
    printf("[%s] HTTP parse error request %d\n", sess->hostname, status);
    return 1;
  }

  // No TLS handshake here: client and server are both plain HTTP
  return 0;
}

struct llm_ctx {
  byte_array* out_buf;
  parse_header_result* req_header;
};

// push CONTENTS into USRP (byte array)
static size_t curl_cb(void *contents,
                      size_t size,
                      size_t nmemb,
                      void *userp) {
    size_t total = size * nmemb;
    byte_array *buf = (byte_array *)userp;
    if (total == 0) {
        return 0;
    }

    kv_push_bytes(buf, contents, total);
    return total;
}

static size_t curl_llm_cb(void *contents,
                      size_t size,
                      size_t nmemb,
                      void *userp) {
    size_t total = size * nmemb;
    byte_array *buf = (byte_array *)userp;
    if (total == 0) {
        return 0;
    }
    char header[256];
    int header_len = snprintf(
        header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        total
    );
    kv_push_bytes(buf, header, (size_t)header_len);
    kv_push_bytes(buf, contents, total);
    // kv_print_bytes(buf);
    return total;
}


int inject_llm_cb(byte_array *parsed, parse_header_result* header_res, void* u_ptr){
  if (header_res->is_chunked) {

  }
  struct llm_ctx* ctx = (struct llm_ctx*) u_ptr;
  CURL *curl = curl_easy_init();
  if (!curl) {
    printf("curl init failed\n");
    return -1;
  }
  char url_buf[2048];
  // printf("header method: %s\n", ctx->req_header->method);
  // printf("url: %s\n", ctx->req_header->full_url);
  snprintf(url_buf, sizeof(url_buf),
    "http://127.0.0.1:8080/inject-resp?method=%s&req_url=%s",
    ctx->req_header->method, ctx->req_header->full_url);
  curl_easy_setopt(curl, CURLOPT_URL, url_buf);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, parsed->a);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)parsed->n);
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: text/html; charset=utf-8");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_cb); // performs kv_push_bytes
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, ctx->out_buf); // byte_array injected_resp

  CURLcode res = curl_easy_perform(curl);

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    printf("inject_llm_cb curl not OK\n");
    return -1;
  }

  return 0;
}

int session_serve(struct proxy_session *s) {
  if (s->is_https) {
    return session_serve_https(s);
  } else {
    return session_serve_http(s);
  }
}

int session_serve_http(struct proxy_session *s) {
  fd_set rfds, wfds;
  unsigned char buf[CONN_IO_BUF_SIZE];
  int flags;

  flags = fcntl(s->h_fd, F_GETFL, 0);
  fcntl(s->h_fd, F_SETFL, flags | O_NONBLOCK);
  flags = fcntl(s->c_fd, F_GETFL, 0);
  fcntl(s->c_fd, F_SETFL, flags | O_NONBLOCK);

  int client_read_open = 1;
  int host_read_open = 1;

  size_t cth_read_total = 0;
  size_t cth_write_total = 0;
  size_t htc_read_total = 0;
  size_t htc_write_total = 0;

  struct llm_ctx llmctx = {&s->htc_buf_out, &(s->cth_parser.header_result)};

  while (1) {
    if (!client_read_open && !host_read_open &&
        s->cth_buf_in.n == 0 && s->htc_buf_out.n == 0) {
      break;
    }

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    if (client_read_open && s->c_fd >= 0)
      FD_SET(s->c_fd, &rfds);
    if (host_read_open && s->h_fd >= 0)
      FD_SET(s->h_fd, &rfds);

    if (s->cth_buf_out.n > 0 && s->h_fd >= 0)
      FD_SET(s->h_fd, &wfds);
    if (s->htc_buf_out.n > 0 && s->c_fd >= 0)
      FD_SET(s->c_fd, &wfds);

    int fdmax = s->c_fd > s->h_fd ? s->c_fd : s->h_fd;
    int sel = select(fdmax + 1, &rfds, &wfds, NULL, NULL);
    if (sel < 0) {
      if (errno == EINTR) continue;
      perror("select");
      break;
    }
    if (sel == 0) continue;

    ssize_t n;

    // C → P
    if (client_read_open && s->c_fd >= 0 && FD_ISSET(s->c_fd, &rfds)) {
      for (;;) {
        n = read(s->c_fd, buf, CONN_IO_BUF_SIZE);
        if (n > 0) {
          cth_read_total += (size_t)n;
          kv_push_bytes(&s->cth_buf_in, buf, (size_t)n);
          int status = http_parser_process(&s->cth_parser,
                                           &s->cth_buf_in,
                                           HTTP_MSG_REQUEST,
                                           &noop_cb,
                                           &s->cth_buf_out);
          if (status > 0) {
            printf("[%s] HTTP parse error req %d, closing\n",
                   s->hostname, status);
            client_read_open = 0;
            break;
          } else {
            // keep reading until EAGAIN
            continue;
          }
        } else if (n == 0) {
          client_read_open = 0;
          break;
        } else {
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            break;
          }
          client_read_open = 0;
          break;
        }
      }
    }

    // P → H
    if (s->cth_buf_out.n > 0 && s->h_fd >= 0 && FD_ISSET(s->h_fd, &wfds)) {
      n = write(s->h_fd, s->cth_buf_out.a, s->cth_buf_out.n);
      if (n > 0) {
        cth_write_total += (size_t)n;
        kv_erase_bytes(&s->cth_buf_out, 0, (size_t)n);
      } else if (n < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        printf("[%s] write to host failed\n", s->hostname);
        host_read_open = 0;
        s->cth_buf_out.n = 0;
      }
    }

    // H → P
    if (host_read_open && s->h_fd >= 0 && FD_ISSET(s->h_fd, &rfds)) {
      for (;;) {
        n = read(s->h_fd, buf, CONN_IO_BUF_SIZE);
        if (n > 0) {
          htc_read_total += (size_t)n;
          kv_push_bytes(&s->htc_buf_in, buf, (size_t)n);
          int status = http_parser_process(&s->htc_parser,
                                           &s->htc_buf_in,
                                           HTTP_MSG_RESPONSE,
                                           inject_llm_cb,
                                           &llmctx);
          if (status > 0) {
            printf("[%s] HTTP parse error resp %d, closing\n",
                   s->hostname, status);
            host_read_open = 0;
            break;
          } else {
            continue;
          }
        } else if (n == 0) {
          host_read_open = 0;
          break;
        } else {
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            break;
          }
          printf("[%s] read from host failed\n", s->hostname);
          host_read_open = 0;
          break;
        }
      }
    }

    // P → C
    if (s->htc_buf_out.n > 0 && s->c_fd >= 0 && FD_ISSET(s->c_fd, &wfds)) {
      n = write(s->c_fd, s->htc_buf_out.a, s->htc_buf_out.n);
      if (n > 0) {
        htc_write_total += (size_t)n;
        kv_erase_bytes(&s->htc_buf_out, 0, (size_t)n);
      } else if (n < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        printf("[%s] write to client failed\n", s->hostname);
        client_read_open = 0;
        s->htc_buf_out.n = 0;
      }
    }
  }

  return 0;
}

int session_serve_https(struct proxy_session *s) {
  fd_set rfds, wfds;
  unsigned char buf[CONN_IO_BUF_SIZE];
  int flags;

  flags = fcntl(s->h_fd, F_GETFL, 0);
  fcntl(s->h_fd, F_SETFL, flags | O_NONBLOCK);
  flags = fcntl(s->c_fd, F_GETFL, 0);
  fcntl(s->c_fd, F_SETFL, flags | O_NONBLOCK);

  int client_read_open = 1;
  int host_read_open = 1;

  size_t cth_read_total = 0;  // client → proxy read
  size_t cth_write_total = 0; // proxy → host write
  size_t htc_read_total = 0;  // host → proxy read
  size_t htc_write_total = 0; // proxy → client write
  // printf("[%s] session_serve start\n", s->hostname);

  struct llm_ctx llmctx = {&s->htc_buf_out, &(s->cth_parser.header_result)};

  while (1) {
    if (!client_read_open && !host_read_open && s->cth_buf_in.n == 0 &&
        s->htc_buf_out.n == 0) {
      // printf("[%s] loop exit: both sides closed and buffers empty\n",
      // s->hostname);
      break;
    }

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    if (client_read_open && s->c_fd >= 0)
      FD_SET(s->c_fd, &rfds);
    if (host_read_open && s->h_fd >= 0)
      FD_SET(s->h_fd, &rfds);

    if (s->cth_buf_out.n > 0 && s->h_fd >= 0)
      FD_SET(s->h_fd, &wfds);
    if (s->htc_buf_out.n > 0 && s->c_fd >= 0)
      FD_SET(s->c_fd, &wfds);

    int fdmax = s->c_fd > s->h_fd ? s->c_fd : s->h_fd;
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int sel = select(fdmax + 1, &rfds, &wfds, NULL, NULL);
    if (sel < 0) {
      if (errno == EINTR)
        continue;
      perror("select");
      printf("[%s] select() failed, breaking\n", s->hostname);
      break;
    }
    if (sel == 0)
      continue;

    int n, err;

    if (client_read_open && s->c_fd >= 0 && FD_ISSET(s->c_fd, &rfds)) {
      for (;;) {
        n = SSL_read(s->c_ssl, buf, CONN_IO_BUF_SIZE);
        if (n > 0) {
          cth_read_total += (size_t)n;
          kv_push_bytes(&s->cth_buf_in, buf, (size_t)n);
          int status = http_parser_process(&s->cth_parser,
                                      &s->cth_buf_in,
                                      HTTP_MSG_REQUEST, 
                                      &noop_cb,
                                      &s->cth_buf_out
                                    );
          // int status = http_parser_process(&s->parser,
          //                             &s->htc_buf_in,
          //                             http_resp_no_inject_cb,
          //                             &s->htc_buf_out
          //                             );
          if (status > 0) {
              printf("[%s] HTTP parse error htc %d, closing\n",
                    s->hostname, status);
              client_read_open = 0;
              break;
          }
          else {
            continue;
          }
        } else if (n == 0) {
          client_read_open = 0;
          break;
        } else {
          err = SSL_get_error(s->c_ssl, n);
          if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // printf("[%s] C→P SSL_read WANT_%s\n",
            //        s->hostname,
            //        err == SSL_ERROR_WANT_READ ? "READ" : "WRITE");
          } else {
            // printf("[%s] C→P SSL_read error=%d, closing client read\n",
            //        s->hostname, err);
            // ERR_print_errors_fp(stderr);
            client_read_open = 0;
          }
          break;
        }

        int pending = SSL_pending(s->c_ssl);
        if (pending <= 0) break;
      }
    }

    if (s->cth_buf_out.n > 0 && s->h_fd >= 0 && FD_ISSET(s->h_fd, &wfds)) {
      n = SSL_write(s->h_ssl, s->cth_buf_out.a, s->cth_buf_out.n);
      if (n > 0) {
        cth_write_total += (size_t)n;
        kv_erase_bytes(&s->cth_buf_out, 0, (size_t)n);
      } else {
        err = SSL_get_error(s->h_ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
          // printf("[%s] P→H SSL_write WANT_%s\n",
          //        s->hostname,
          //        err == SSL_ERROR_WANT_READ ? "READ" : "WRITE");
        } else {
          printf("[%s] P→H SSL_write error=%d, closing host side\n",
                 s->hostname, err);
          ERR_print_errors_fp(stderr);
          host_read_open = 0;
          s->cth_buf_out.n = 0;
        }
      }
    }

    if (host_read_open && s->h_fd >= 0 && FD_ISSET(s->h_fd, &rfds)) {
      while(1) {
        n = SSL_read(s->h_ssl, buf, CONN_IO_BUF_SIZE);
        if (n > 0) {
          htc_read_total += (size_t)n;
          kv_push_bytes(&s->htc_buf_in, buf, n);
          int status = http_parser_process(&s->htc_parser,
                                      &s->htc_buf_in,
                                      HTTP_MSG_RESPONSE, 
                                      inject_llm_cb,
                                      &llmctx
                                    );
          // int status = http_parser_process(&s->parser,
          //                             &s->htc_buf_in,
          //                             http_resp_no_inject_cb,
          //                             &s->htc_buf_out
          //                             );
          if (status > 0) {
              printf("[%s] HTTP parse error htc %d, closing\n",
                    s->hostname, status);
              host_read_open = 0;
              break;
          }
          else {
            continue;
          }
        }
        else if (n == 0) {
          host_read_open = 0;
          break;
        } else {
          err = SSL_get_error(s->h_ssl, n);
          if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // printf("[%s] H→P SSL_read WANT_%s\n",
            //        s->hostname,
            //        err == SSL_ERROR_WANT_READ ? "READ" : "WRITE");
          } else {
            printf("[%s] H→P SSL_read error=%d, closing host read\n",
                   s->hostname, err);
            ERR_print_errors_fp(stderr);
            host_read_open = 0;
          }
          break;
        }
        
        int pending = SSL_pending(s->h_ssl);
        if (pending <= 0)
          break;
      }
    }

    if (s->htc_buf_out.n > 0 && s->c_fd >= 0 && FD_ISSET(s->c_fd, &wfds)) {
      n = SSL_write(s->c_ssl, s->htc_buf_out.a, s->htc_buf_out.n);
      if (n > 0) {
        htc_write_total += (size_t)n;
        kv_erase_bytes(&s->htc_buf_out, 0, (size_t)n);
      } else {
        err = SSL_get_error(s->c_ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
          // printf("[%s] P→C SSL_write WANT_%s\n",
          //        s->hostname,
          //        err == SSL_ERROR_WANT_READ ? "READ" : "WRITE");
        } else {
          printf("[%s] P→C SSL_write error=%d, closing client side\n",
                 s->hostname, err);
          ERR_print_errors_fp(stderr);
          client_read_open = 0;
          s->htc_buf_out.n = 0;
        }
      }
    }
  }

  // printf("[%s] session_serve end: C→P read=%zu, P→H write=%zu, H→P read=%zu,
  // P→C write=%zu\n",
  //        s->hostname, cth_read_total, cth_write_total,
  //        htc_read_total, htc_write_total);

  return 0;
}
