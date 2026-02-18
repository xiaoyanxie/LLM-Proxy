#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdarg.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#include "uthash.h"

#define MAX_BUFF      65536
// #define MAX_BUFF      131072
#define FD_MAX        1024  //128*1024 = 131072kB = 128MB
#define MAX_ACTIVE_MS (5 * 60 * 1000)  // 5min
#define INJECTION_APP_PORT 8080
#define INJECTION_APP_HOST "127.0.0.1"

typedef enum {
    CONN_FREE   = 0,
    CONN_CLIENT = 1,
    CONN_SERVER = 2,
} ConnType;

typedef enum {
    TRANSPORT_PLAIN = 0,
    TRANSPORT_TLS   = 1
} TransportType;

typedef enum {
    CLIENT_READING_HEADER = 1,
    CLIENT_WAITING_RESP   = 2,
} ClientState;

typedef enum {
    SERVER_READING_HEADER  = 10,
    SERVER_FORWARDING_BODY = 11
} ServerState;

typedef struct HttpConn {
    int fd;
    bool in_use;
    ConnType kind;
    int peer_fd;

    uint8_t buff[MAX_BUFF];
    size_t  buff_used;

    int64_t last_active_ms;

    int state;           // client/server state

    size_t  header_len;
    int64_t content_length;
    size_t  body_forwarded;

    TransportType transport;

    SSL     *ssl;
    SSL_CTX *ssl_ctx;    // only used for client-side MITM ctx

    uint8_t pending_send[MAX_BUFF];
    size_t  pending_send_len;
    size_t  pending_send_off;
    bool    want_write;

    uint8_t *resp_buf;      // aggregated server response (raw)
    size_t   resp_len;
    size_t   resp_cap;

    bool chunked;
    enum {
        CHUNK_STATE_SIZE = 0,
        CHUNK_STATE_SIZE_EXT,
        CHUNK_STATE_SIZE_CR,
        CHUNK_STATE_DATA,
        CHUNK_STATE_DATA_CR,
        CHUNK_STATE_DATA_LF,
        CHUNK_STATE_TRAILER_CR,
        CHUNK_STATE_DONE
    } chunk_state;
    uint64_t chunk_size_accum;
    uint64_t chunk_bytes_remaining;
    int chunk_trailer_crlf;
} HttpConn;

static HttpConn conn_table[FD_MAX];

static SSL_CTX *g_upstream_ctx = NULL;   // as TLS client to origin servers
static X509    *g_ca_cert      = NULL;
static EVP_PKEY *g_ca_key      = NULL;

typedef struct MitmCertCacheEntry {
    char host[256];
    X509 *cert;
    EVP_PKEY *pkey;
    UT_hash_handle hh;
} MitmCertCacheEntry;

static MitmCertCacheEntry *g_mitm_cache = NULL;

static int  create_listen_socket(uint16_t port);
static void driver(int listen_fd);
static void init_conn_table(void);
static HttpConn *alloc_conn(int fd, ConnType kind);
static void free_conn(int fd, fd_set *activefds, int *p_maxfd, int listen_fd);
static int  handle_fd_event(int fd, bool readable, bool writable, fd_set *activefds, int *p_maxfd, int listen_fd);

static int  handle_client_event(HttpConn *c, fd_set *activefds, int *p_maxfd, int listen_fd);
static int  handle_server_event(HttpConn *s, fd_set *activefds, int *p_maxfd, int listen_fd);

static int  compute_next_timeout(int maxfd, int listen_fd);
static void sweep_timeouts(fd_set *activefds, int *p_maxfd, int listen_fd);

static ssize_t send_all(int fd, const void *buf, size_t len);
static char*   find_double_crlf(uint8_t *buf, size_t len);

static int connect_to_server(const char *host, uint16_t port);
static int parse_host_and_port_from_request(uint8_t *buf, size_t header_len,
                                            char *host_out, size_t host_out_sz,
                                            uint16_t *port_out);
static int parse_content_length_from_response(uint8_t *buf, size_t header_len,
                                              int64_t *content_length_out);

static int parse_connect_host_and_port(uint8_t *buf, size_t header_len,
                                       char *host_out, size_t host_out_sz,
                                       uint16_t *port_out);
static ssize_t conn_recv(HttpConn *c, void *buf, size_t len);
static ssize_t conn_send(HttpConn *c, const void *buf, size_t len);
static int flush_pending_send(HttpConn *c);
static int send_simple_error_to_client(HttpConn *c, int code, const char *reason);

static inline int64_t now_ms(void);
static inline int hex_value(char c);

#ifdef ENABLE_PROXY_LOG
static void proxy_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
}
#else
#define proxy_log(...) do { } while (0)
#endif

/* SSL helpers */
static int  ssl_global_init(const char *ca_cert_path, const char *ca_key_path);
static int  enable_tls_mitm(HttpConn *c, HttpConn *s, const char *host);
static void ssl_cleanup_conn(HttpConn *c);
static int  cache_get_leaf_material(const char *host, X509 **cert_out, EVP_PKEY **pkey_out);
static void cache_free_all_mitm_ctx(void);

/* header injection */
static int inject_cs112_and_forward(HttpConn *s);

static int make_socket_nonblocking(int fd);
static int ssl_accept_with_retry(SSL *ssl);
static bool header_has_chunked_encoding(uint8_t *buf, size_t header_len);
static void chunk_state_reset(HttpConn *c);
static int chunk_state_update(HttpConn *c, const uint8_t *data, size_t len);

/* python app integration */
static void   resp_buffer_reset(HttpConn *c);
static int    resp_buffer_append(HttpConn *c, const uint8_t *data, size_t len);
static int    forward_response_via_app(HttpConn *s, HttpConn *c);
static int    post_to_injection_app(const uint8_t *payload, size_t payload_len,
                                    uint8_t **out_buf, size_t *out_len);

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <port> <ca_cert_path> <ca_key_path>\n", argv[0]);
        return 1;
    }

    uint16_t port = (uint16_t)atoi(argv[1]);

    fprintf(stderr, "proxy start at %u\n", port);

    signal(SIGPIPE, SIG_IGN);

    if (ssl_global_init(argv[2], argv[3]) != 0) {
        fprintf(stderr, "SSL init failed\n");
        return 1;
    }

    init_conn_table();

    int listenfd = create_listen_socket(port);
    if (listenfd < 0) {
        perror("listen");
        return 1;
    }

    driver(listenfd);
    close(listenfd);
    cache_free_all_mitm_ctx();
    return 0;
}

static void driver(int listen_fd) {
    fd_set activefds, readfds, writefds;
    FD_ZERO(&activefds);
    FD_SET(listen_fd, &activefds);
    int maxfd = listen_fd;

    for (;;) {
        readfds = activefds;
        FD_ZERO(&writefds);
        for (int fd = 0; fd <= maxfd; fd++) {
            if (fd == listen_fd) continue;
            if (fd < 0 || fd >= FD_MAX) continue;
            HttpConn *c = &conn_table[fd];
            if (!c->in_use) continue;
            if (c->want_write && c->transport == TRANSPORT_TLS && c->pending_send_len > 0) {
                FD_SET(fd, &writefds);
            }
        }

        int ms = compute_next_timeout(maxfd, listen_fd);
        struct timeval tv;
        tv.tv_sec  = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;

        int n = select(maxfd + 1, &readfds, &writefds, NULL, &tv);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (n == 0) {
            sweep_timeouts(&activefds, &maxfd, listen_fd);
            continue;
        }

        for (int fd = 0; fd <= maxfd; fd++) {
            bool readable = FD_ISSET(fd, &readfds);
            bool writable = FD_ISSET(fd, &writefds);
            if (!readable && !writable) continue;

            if (fd == listen_fd) {
                if (!readable) continue;
                int cfd = accept(listen_fd, NULL, NULL);
                if (cfd < 0) {
                    perror("accept");
                    continue;
                }
                if (cfd >= FD_MAX) {
                    close(cfd);
                    continue;
                }
                FD_SET(cfd, &activefds);
                if (cfd > maxfd) maxfd = cfd;
                HttpConn *c = alloc_conn(cfd, CONN_CLIENT);
                if (!c) {
                    close(cfd);
                    FD_CLR(cfd, &activefds);
                    continue;
                }
            } else {
                int r = handle_fd_event(fd, readable, writable, &activefds, &maxfd, listen_fd);
                if (r < 0) {
                    free_conn(fd, &activefds, &maxfd, listen_fd);
                }
            }
        }
        sweep_timeouts(&activefds, &maxfd, listen_fd);
    }
}

static int handle_fd_event(int fd, bool readable, bool writable, fd_set *activefds, int *p_maxfd, int listen_fd) {
    if (fd < 0 || fd >= FD_MAX) return -1;
    HttpConn *c = &conn_table[fd];
    if (!c->in_use) return -1;

    c->last_active_ms = now_ms();

    if (writable && c->transport == TRANSPORT_TLS && c->pending_send_len > 0) {
        if (flush_pending_send(c) < 0) {
            return -1;
        }
    }

    if (!readable) {
        return 0;
    }

    if (c->kind == CONN_CLIENT) {
        return handle_client_event(c, activefds, p_maxfd, listen_fd);
    } else if (c->kind == CONN_SERVER) {
        return handle_server_event(c, activefds, p_maxfd, listen_fd);
    } else {
        return -1;
    }
}

static ssize_t conn_recv(HttpConn *c, void *buf, size_t len)
{
    if (!c) return -1;
    if (c->transport == TRANSPORT_TLS) {
        int n = SSL_read(c->ssl, buf, (int)len);
        if (n > 0) return n;
        int e = SSL_get_error(c->ssl, n);
        if (e == SSL_ERROR_ZERO_RETURN) {
            proxy_log("[proxy] conn_recv: SSL_read returned ZERO_RETURN on fd=%d\n", c->fd);
            return 0;
        }
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            return -2;  // no data yet; try again later
        }
        return -1;
    } else {
        ssize_t n = recv(c->fd, buf, len, 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return -2;
        }
        return n;
    }
}

static ssize_t conn_send(HttpConn *c, const void *buf, size_t len)
{
    if (!c) return -1;
    if (c->transport == TRANSPORT_TLS) {
        if (c->pending_send_len > 0) {
            if (len > sizeof(c->pending_send) - c->pending_send_len) {
                return -1;
            }
            memcpy(c->pending_send + c->pending_send_len, buf, len);
            c->pending_send_len += len;
            c->want_write = true;
            return (ssize_t)len;
        }
        size_t left = len;
        const uint8_t *p= buf;
        while (left > 0) {
            int n = SSL_write(c->ssl, p, (int)left);
            if (n <= 0) {
                int e = SSL_get_error(c->ssl, n);
                if (e == SSL_ERROR_ZERO_RETURN) {
                    proxy_log("[proxy] conn_send: SSL_write ZERO_RETURN fd=%d\n", c->fd);
                    return 0;
                }
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                    if (left > sizeof(c->pending_send)) {
                        proxy_log("[proxy] conn_send: pending buffer too small fd=%d left=%zu\n", c->fd, left);
                        return -1;
                    }
                    memcpy(c->pending_send, p, left);
                    c->pending_send_len = left;
                    c->pending_send_off = 0;
                    c->want_write = true;
                    return (ssize_t)len;
                }
                return -1;
            }
            p+= n;
            left-= (size_t)n;
        }
        return (ssize_t)len;
    } else {
        return send_all(c->fd, buf, len);
    }
}

static int flush_pending_send(HttpConn *c)
{
    if (!c) return -1;
    if (c->transport != TRANSPORT_TLS) return 0;
    if (c->pending_send_len == 0) {
        c->pending_send_off = 0;
        c->want_write = false;
        return 0;
    }

    while (c->pending_send_off < c->pending_send_len) {
        int to_write = (int)(c->pending_send_len - c->pending_send_off);
        int n = SSL_write(c->ssl, c->pending_send + c->pending_send_off, to_write);
        if (n <= 0) {
            int e = SSL_get_error(c->ssl, n);
            if (e == SSL_ERROR_ZERO_RETURN) {
                c->pending_send_len = 0;
                c->pending_send_off = 0;
                c->want_write = false;
                return 0;
            }
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                c->want_write = true;
                return 0;
            }
            return -1;
        }
        c->pending_send_off += (size_t)n;
    }

    c->pending_send_len = 0;
    c->pending_send_off = 0;
    c->want_write = false;
    return 0;
}


static int handle_client_event(HttpConn *c, fd_set *activefds, int *p_maxfd, int listen_fd)
{
    (void)listen_fd;

    ssize_t n = conn_recv(c, c->buff + c->buff_used, MAX_BUFF - c->buff_used);
    if (n == -2) {
        return 0;
    }
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        return -1;
    }

    c->buff_used += (size_t)n;

    if (c->state != CLIENT_READING_HEADER) {
        return 0;
    }

    char *p = find_double_crlf(c->buff, c->buff_used);
    if (!p) {
        if (c->buff_used == MAX_BUFF) {
            return -1;
        }
        return 0;
    }

    c->header_len = (size_t)(p - (char*)c->buff) + 4;

    char *start = (char *)c->buff;
    char *sp1 = memchr(start, ' ', c->header_len);
    if (!sp1) {
        return -1;
    }
    size_t method_len = (size_t)(sp1 - start);
    bool is_connect = (method_len == 7 && strncmp(start, "CONNECT", 7) == 0);
    bool is_get = (method_len == 3 && strncmp(start, "GET", 3) == 0);

    char host[256];
    uint16_t port = 0;

    if (is_connect) {
        if (parse_connect_host_and_port(c->buff, c->header_len,
                                        host, sizeof(host), &port) != 0) {
            return -1;
        }
        int sfd = connect_to_server(host, port);
        if (sfd < 0 || sfd >= FD_MAX) {
            if (sfd >= 0) close(sfd);
            return -1;
        }

        FD_SET(sfd, activefds);
        if (sfd > *p_maxfd) *p_maxfd = sfd;
        HttpConn *s = alloc_conn(sfd, CONN_SERVER);
        if (!s) {
            close(sfd);
            FD_CLR(sfd, activefds);
            return -1;
        }

        c->peer_fd = sfd;
        s->peer_fd = c->fd;

        /* send 200 to client in plain text */
        const char resp[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (send_all(c->fd, resp, sizeof(resp) - 1) < 0) {
            return -1;
        }

        /* switch to TLS MITM on both sides */
        if (enable_tls_mitm(c, s, host) != 0) {
            return -1;
        }

        c->buff_used  = 0;
        c->header_len = 0;
        return 0;
    }
    if (!is_get) {
    }

    port = 80;
    if (parse_host_and_port_from_request(c->buff, c->header_len,
                                         host, sizeof(host), &port) != 0) {
        return -1;
    }

    //reuse existing server connection if possible
    if (c->transport == TRANSPORT_TLS && c->peer_fd >= 0) {
        if (c->peer_fd < 0 || c->peer_fd >= FD_MAX) return -1;
        HttpConn *s = &conn_table[c->peer_fd];
        if (!s->in_use || s->kind != CONN_SERVER) return -1;

        //log for debugging
        {
            char firstline[256] = {0};
            size_t i = 0;
            while (i < c->buff_used && i + 1 < sizeof(firstline) && c->buff[i] != '\r' && c->buff[i] != '\n') {
                firstline[i] = (char)c->buff[i];
                i++;
            }
            firstline[i] = '\0';

        }
        if (conn_send(s, c->buff, c->buff_used) < 0) {
            proxy_log("[proxy] forwarding failed (reuse) client fd=%d -> server fd=%d\n", c->fd, s->fd);
            return -1;
        }

        c->buff_used  = 0;
        c->header_len = 0;
        c->state = CLIENT_WAITING_RESP;
        return 0;
    }

    int sfd = connect_to_server(host, port);
    if (sfd < 0 || sfd >= FD_MAX) {
        if (sfd >= 0) close(sfd);
        return -1;
    }

    FD_SET(sfd, activefds);
    if (sfd > *p_maxfd) *p_maxfd = sfd;
    HttpConn *s = alloc_conn(sfd, CONN_SERVER);
    if (!s) {
        close(sfd);
        FD_CLR(sfd, activefds);
        return -1;
    }

    c->peer_fd = sfd;
    s->peer_fd = c->fd;

    if (conn_send(s, c->buff, c->buff_used) < 0) {
        return -1;
    }

    //log for debugging 
    {
        char firstline[256] = {0};
        size_t i = 0;
        while (i < c->buff_used && i + 1 < sizeof(firstline) && c->buff[i] != '\r' && c->buff[i] != '\n') {
            firstline[i] = (char)c->buff[i];
            i++;
        }
        firstline[i] = '\0';

    }

    c->buff_used  = 0;
    c->header_len = 0;
    c->state = CLIENT_WAITING_RESP;

    return 0;
}


static int handle_server_event(HttpConn *s, fd_set *activefds, int *p_maxfd, int listen_fd)
{
    (void)activefds;
    (void)p_maxfd;
    (void)listen_fd;

    if (s->peer_fd < 0 || s->peer_fd >= FD_MAX) {
        return -1;
    }
    HttpConn *c = &conn_table[s->peer_fd];
    if (!c->in_use || c->kind != CONN_CLIENT) {
        return -1;
    }

    size_t prev_used = s->buff_used;
    ssize_t n = conn_recv(s, s->buff + s->buff_used, MAX_BUFF - s->buff_used);
    if (n == -2) {
        return 0;
    }
    if (n < 0) {
        return -1;
    }

    if (n > 0) {
        s->buff_used += (size_t)n;
        if (resp_buffer_append(s, s->buff + prev_used, (size_t)n) != 0) {
            return -1;
        }
    }

    bool server_closed = (n == 0);
    if (s->state == SERVER_READING_HEADER) {
        char *p = find_double_crlf(s->buff, s->buff_used);
        if (!p) {
            if (s->buff_used == MAX_BUFF) {
                return -1;
            }
            if (server_closed) {
                proxy_log("[proxy] upstream closed before full headers received\n");
                return -1;
            }
            return 0;
        }

        s->header_len = (size_t)(p - (char *)s->buff) + 4;

        if (parse_content_length_from_response(s->buff, s->header_len,
                                               &s->content_length) != 0) {
            s->content_length = -1;
        }

        s->chunked = header_has_chunked_encoding(s->buff, s->header_len);
        if (s->chunked) {
            chunk_state_reset(s);
        }

        size_t body_len = s->buff_used - s->header_len;
        bool chunk_done = false;
        if (s->chunked && body_len > 0) {
            int chunk_ret = chunk_state_update(s, s->buff + s->header_len, body_len);
            if (chunk_ret < 0) return -1;
            if (chunk_ret > 0) chunk_done = true;
        }

        if (s->content_length >= 0) {
            s->body_forwarded = body_len;
            if ((int64_t)s->body_forwarded >= s->content_length) {
                if (forward_response_via_app(s, c) != 0) return -1;
                return 0;
            }
        } else {
            s->body_forwarded = 0;
        }

        if (chunk_done) {
            if (forward_response_via_app(s, c) != 0) return -1;
            return 0;
        }

        s->buff_used = 0;
        s->state = SERVER_FORWARDING_BODY;
        return 0;
    }

    if (s->state == SERVER_FORWARDING_BODY) {
        bool chunk_done = false;
        if (s->chunked && s->buff_used > 0) {
            int chunk_ret = chunk_state_update(s, s->buff, s->buff_used);
            if (chunk_ret < 0) return -1;
            if (chunk_ret > 0) chunk_done = true;
        }

        if (s->content_length >= 0) {
            s->body_forwarded += s->buff_used;
        }

        s->buff_used = 0;

        bool complete = false;
        if (s->content_length >= 0 && (int64_t)s->body_forwarded >= s->content_length) {
            complete = true;
        } else if (s->chunked && chunk_done) {
            complete = true;
        } else if (server_closed && !s->chunked && s->content_length < 0) {
            complete = true;
        }

        if (complete) {
            if (forward_response_via_app(s, c) != 0) return -1;
            return 0;
        }
        if (server_closed) {
            proxy_log("[proxy] upstream closed before response complete on fd=%d\n", s->fd);
            return -1;
        }
        return 0;
    }

    if (server_closed && s->resp_len == 0) {
        proxy_log("[proxy] handle_server_event: upstream closed with ZERO_RETURN and no data on fd=%d, sending 502 to client fd=%d\n", s->fd, c->fd);
        send_simple_error_to_client(c, 502, "Bad Gateway");
        return -1;
    }

    return 0;
}


static int compute_next_timeout(int maxfd, int listen_fd)
{
    int64_t now = now_ms();
    int min_ms = MAX_ACTIVE_MS;
    bool found = false;

    for (int fd = 0; fd <= maxfd; fd++) {
        if (fd == listen_fd) continue;
        if (fd < 0 || fd >= FD_MAX) continue;
        HttpConn *c = &conn_table[fd];
        if (!c->in_use) continue;

        int64_t diff = now - c->last_active_ms;
        if (diff >= MAX_ACTIVE_MS) {
            return 0;
        } else {
            int remain = (int)(MAX_ACTIVE_MS - diff);
            if (!found || remain < min_ms) {
                min_ms = remain;
                found  = true;
            }
        }
    }
    return found ? min_ms : MAX_ACTIVE_MS;
}

static void sweep_timeouts(fd_set *activefds, int *p_maxfd, int listen_fd)
{
    int64_t now = now_ms();
    for (int fd = 0; fd <= *p_maxfd; fd++) {
        if (fd == listen_fd) continue;
        if (fd < 0 || fd >= FD_MAX) continue;
        if (!FD_ISSET(fd, activefds)) continue;

        HttpConn *c = &conn_table[fd];
        if (!c->in_use) continue;

        if (now - c->last_active_ms >= MAX_ACTIVE_MS) {
            free_conn(fd, activefds, p_maxfd, listen_fd);
        }
    }
}


static int parse_host_and_port_from_request(uint8_t *buf, size_t header_len,
                                            char *host_out, size_t host_out_sz,
                                            uint16_t *port_out)
{
    *port_out = 80;
    const char *needle = "\nHost:";
    char *hdr = (char*)buf;
    char *end = (char*)buf + header_len;
    char *p = strstr(hdr, needle);
    if (!p || p >= end) {
        for (p = hdr; p + 5 < end; p++) {
            if ((p[0] == '\r' || p[0] == '\n') &&
                (p[1] == 'H' || p[1] == 'h') &&
                (p[2] == 'o' || p[2] == 'O') &&
                (p[3] == 's' || p[3] == 'S') &&
                (p[4] == 't' || p[4] == 'T') &&
                p[5] == ':') {
                break;
            }
        }
        if (p >= end) {
            return -1;
        }
    } else {
        p++;
    }

    char *line_start = p;
    char *line_end = memchr(line_start, '\n', (size_t)(end - line_start));
    if (!line_end) line_end = end;

    char *host_begin = line_start;
    while (host_begin < line_end && *host_begin != ':') host_begin++;
    if (host_begin == line_end) return -1;
    host_begin++;

    while (host_begin < line_end && (*host_begin == ' ' || *host_begin == '\t')) host_begin++;

    char *host_end = line_end;
    while (host_end > host_begin &&
           (host_end[-1] == '\r' || host_end[-1] == ' ' || host_end[-1] == '\t'))
        host_end--;

    char *colon = memchr(host_begin, ':', (size_t)(host_end - host_begin));
    size_t host_len;
    if (colon) {
        host_len = (size_t)(colon - host_begin);
        if (host_len >= host_out_sz) host_len = host_out_sz - 1;
        memcpy(host_out, host_begin, host_len);
        host_out[host_len] = '\0';

        char port_str[16];
        size_t port_len = (size_t)(host_end - (colon + 1));
        if (port_len >= sizeof(port_str)) port_len = sizeof(port_str) - 1;
        memcpy(port_str, colon + 1, port_len);
        port_str[port_len] = '\0';
        unsigned long pv = strtoul(port_str, NULL, 10);
        if (pv == 0 || pv > 65535) return -1;
        *port_out = (uint16_t)pv;
    } else {
        host_len = (size_t)(host_end - host_begin);
        if (host_len >= host_out_sz) host_len = host_out_sz - 1;
        memcpy(host_out, host_begin, host_len);
        host_out[host_len] = '\0';
    }

    return 0;
}

static int parse_connect_host_and_port(uint8_t *buf, size_t header_len,
                                       char *host_out, size_t host_out_sz,
                                       uint16_t *port_out)
{
    *port_out = 443;

    char *start = (char *)buf;
    char *end   = (char *)buf + header_len;

    char *line_end = memchr(start, '\n', (size_t)(end - start));
    if (!line_end) return -1;
    if (line_end > start && line_end[-1] == '\r') line_end--;

    const char *prefix = "CONNECT ";
    size_t pre_len = strlen(prefix);
    if ((size_t)(line_end - start) <= pre_len) return -1;
    if (strncmp(start, prefix, pre_len) != 0) return -1;

    char *hostport = start + pre_len;
    char *sp2 = memchr(hostport, ' ', (size_t)(line_end - hostport));
    if (!sp2) return -1;

    char *colon = memchr(hostport, ':', (size_t)(sp2 - hostport));
    size_t host_len;
    if (colon) {
        host_len = (size_t)(colon - hostport);
        if (host_len >= host_out_sz) host_len = host_out_sz - 1;
        memcpy(host_out, hostport, host_len);
        host_out[host_len] = '\0';

        char port_str[16];
        size_t port_len = (size_t)(sp2 - (colon + 1));
        if (port_len >= sizeof(port_str)) port_len = sizeof(port_str) - 1;
        memcpy(port_str, colon + 1, port_len);
        port_str[port_len] = '\0';

        unsigned long pv = strtoul(port_str, NULL, 10);
        if (pv == 0 || pv > 65535) return -1;
        *port_out = (uint16_t)pv;
    } else {
        host_len = (size_t)(sp2 - hostport);
        if (host_len >= host_out_sz) host_len = host_out_sz - 1;
        memcpy(host_out, hostport, host_len);
        host_out[host_len] = '\0';
    }
    return 0;
}

static int parse_content_length_from_response(uint8_t *buf, size_t header_len,
                                              int64_t *content_length_out)
{
    *content_length_out = -1;
    char *hdr = (char*)buf;
    char *end = (char*)buf + header_len;
    char *p = hdr;

    while (p < end) {
        char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) break;
        size_t line_len = (size_t)(line_end - p);
        if (line_len > 0 && p[line_len - 1] == '\r') line_len--;

        if (line_len == 0) break;

        if (line_len >= 15 &&
            (p[0] == 'C' || p[0] == 'c') &&
            (p[1] == 'o' || p[1] == 'O') &&
            (p[2] == 'n' || p[2] == 'N') &&
            (p[3] == 't' || p[3] == 'T') &&
            (p[4] == 'e' || p[4] == 'E') &&
            (p[5] == 'n' || p[5] == 'N') &&
            (p[6] == 't' || p[6] == 'T') &&
            p[7] == '-' &&
            (p[8] == 'L' || p[8] == 'l') &&
            (p[9] == 'e' || p[9] == 'E') &&
            (p[10] == 'n' || p[10] == 'N') &&
            (p[11] == 'g' || p[11] == 'G') &&
            (p[12] == 't' || p[12] == 'T') &&
            (p[13] == 'h' || p[13] == 'H') &&
            p[14] == ':') {
            char *q = p + 15;
            while (q < p + line_len && (*q == ' ' || *q == '\t')) q++;
            long long v = strtoll(q, NULL, 10);
            if (v < 0) return -1;
            *content_length_out = v;
            return 0;
        }
        p = line_end + 1;
    }
    *content_length_out = -1;
    return 0;
}


static ssize_t send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n <= 0) {
            return -1;
        }
        p += (size_t)n;
        left -= (size_t)n;
    }
    return (ssize_t)len;
}

static int forward_response_via_app(HttpConn *s, HttpConn *c)
{
    if (!s || !c) return -1;
    if (s->resp_len == 0) {
        return -1;
    }

    uint8_t *modified = NULL;
    size_t modified_len = 0;
    if (post_to_injection_app(s->resp_buf, s->resp_len, &modified, &modified_len) != 0) {
        proxy_log("[proxy] failed to call injection app\n");
        send_simple_error_to_client(c, 502, "Bad Gateway");
        resp_buffer_reset(s);
        return -1;
    }

    if (conn_send(c, modified, modified_len) < 0) {
        free(modified);
        resp_buffer_reset(s);
        return -1;
    }

    free(modified);

    // reset states for next request/response
    s->state = SERVER_READING_HEADER;
    s->content_length = -1;
    s->body_forwarded = 0;
    s->buff_used = 0;
    s->header_len = 0;
    s->chunked = false;
    chunk_state_reset(s);
    resp_buffer_reset(s);

    c->state = CLIENT_READING_HEADER;
    c->buff_used = 0;
    c->header_len = 0;
    return 0;
}

static int make_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }
    return 0;
}

static int post_to_injection_app(const uint8_t *payload, size_t payload_len,
                                 uint8_t **out_buf, size_t *out_len)
{
    if (!payload || payload_len == 0 || !out_buf || !out_len) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(INJECTION_APP_PORT);
    if (inet_pton(AF_INET, INJECTION_APP_HOST, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    char header[256];
    int hdr_len = snprintf(header, sizeof(header),
                           "POST /inject-resp HTTP/1.1\r\n"
                           "Host: %s:%d\r\n"
                           "Content-Length: %zu\r\n"
                           "Content-Type: application/octet-stream\r\n"
                           "Connection: close\r\n\r\n",
                           INJECTION_APP_HOST, INJECTION_APP_PORT, payload_len);
    if (hdr_len <= 0 || hdr_len >= (int)sizeof(header)) {
        close(fd);
        return -1;
    }

    if (send_all(fd, header, (size_t)hdr_len) < 0) {
        close(fd);
        return -1;
    }
    if (send_all(fd, payload, payload_len) < 0) {
        close(fd);
        return -1;
    }

    size_t cap = payload_len + 4096;
    if (cap < MAX_BUFF) cap = MAX_BUFF;
    uint8_t *resp = malloc(cap);
    if (!resp) {
        close(fd);
        return -1;
    }
    size_t resp_len = 0;
    size_t header_len = 0;
    int64_t cl = -1;

    for (;;) {
        if (resp_len == cap) {
            size_t new_cap = cap * 2;
            uint8_t *p = realloc(resp, new_cap);
            if (!p) {
                free(resp);
                close(fd);
                return -1;
            }
            resp = p;
            cap = new_cap;
        }
        ssize_t n = recv(fd, resp + resp_len, cap - resp_len, 0);
        if (n < 0) {
            free(resp);
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        resp_len += (size_t)n;

        if (header_len == 0) {
            char *p = find_double_crlf(resp, resp_len);
            if (p) {
                header_len = (size_t)(p - (char *)resp) + 4;
                if (parse_content_length_from_response(resp, header_len, &cl) != 0) {
                    cl = -1;
                }
            }
        }
        if (header_len > 0 && cl >= 0) {
            if (resp_len >= header_len + (size_t)cl) {
                break;
            }
        }
    }
    close(fd);

    if (header_len == 0 || resp_len < header_len) {
        free(resp);
        return -1;
    }

    if (cl >= 0 && resp_len < header_len + (size_t)cl) {
        free(resp);
        return -1;
    }

    size_t body_len = (cl >= 0) ? (size_t)cl : (resp_len - header_len);
    uint8_t *out = malloc(body_len);
    if (!out) {
        free(resp);
        return -1;
    }
    memcpy(out, resp + header_len, body_len);

    free(resp);
    *out_buf = out;
    *out_len = body_len;
    return 0;
}

static int ssl_accept_with_retry(SSL *ssl)
{
    if (!ssl) return -1;
    for (;;) {
        int ret = SSL_accept(ssl);
        if (ret > 0) {
            return 0;
        }
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        proxy_log("[proxy] SSL_accept fatal error err=%d\n", err);
        return -1;
    }
}

//Will the header indicate chunked encoding? what about unchunked without
//content length? how to tell when the body is done?
static bool header_has_chunked_encoding(uint8_t *buf, size_t header_len)
{
    if (!buf || header_len == 0) return false;
    const char *needle = "transfer-encoding:";
    size_t needle_len = strlen(needle);
    for (size_t i = 0; i + needle_len < header_len; i++) {
        if (strncasecmp((const char *)buf + i, needle, needle_len) == 0) {
            const char *p = (const char *)buf + i + needle_len;
            while ((size_t)(p - (char *)buf) < header_len && (*p == ' ' || *p == '\t')) p++;
            if ((size_t)(p - (char *)buf) + 7 <= header_len &&
                strncasecmp(p, "chunked", 7) == 0) {
                return true;
            }
        }
    }
    return false;
}

static void chunk_state_reset(HttpConn *c)
{
    if (!c) return;
    c->chunk_state = CHUNK_STATE_SIZE;
    c->chunk_size_accum = 0;
    c->chunk_bytes_remaining = 0;
    c->chunk_trailer_crlf = 0;
}

static int chunk_state_update(HttpConn *c, const uint8_t *data, size_t len)
{
    if (!c || !c->chunked || !data) return 0;
    size_t i = 0;
    while (i < len) {
        uint8_t ch = data[i];
        switch (c->chunk_state) {
        case CHUNK_STATE_SIZE:
            if (ch == '\r') {
                c->chunk_state = CHUNK_STATE_SIZE_CR;
            } else if (ch == ';') {
                c->chunk_state = CHUNK_STATE_SIZE_EXT;
            } else {
                int hv = hex_value((char)ch);
                if (hv < 0) return -1;
                c->chunk_size_accum = (c->chunk_size_accum << 4) | (uint64_t)hv;
            }
            break;
        case CHUNK_STATE_SIZE_EXT:
            if (ch == '\r') {
                c->chunk_state = CHUNK_STATE_SIZE_CR;
            }
            break;
        case CHUNK_STATE_SIZE_CR:
            if (ch != '\n') return -1;
            if (c->chunk_size_accum == 0) {
                c->chunk_state = CHUNK_STATE_TRAILER_CR;
                c->chunk_trailer_crlf = 0;
            } else {
                c->chunk_bytes_remaining = c->chunk_size_accum;
                c->chunk_size_accum = 0;
                c->chunk_state = CHUNK_STATE_DATA;
            }
            break;
        case CHUNK_STATE_DATA: {
            size_t avail = len - i;
            if (avail >= c->chunk_bytes_remaining) {
                avail = (size_t)c->chunk_bytes_remaining;
            }
            c->chunk_bytes_remaining -= avail;
            i += avail;
            if (c->chunk_bytes_remaining == 0) {
                c->chunk_state = CHUNK_STATE_DATA_CR;
            }
            continue;
        }
        case CHUNK_STATE_DATA_CR:
            if (ch != '\r') return -1;
            c->chunk_state = CHUNK_STATE_DATA_LF;
            break;
        case CHUNK_STATE_DATA_LF:
            if (ch != '\n') return -1;
            c->chunk_state = CHUNK_STATE_SIZE;
            break;
        case CHUNK_STATE_TRAILER_CR:
            if (ch == '\r') {
                c->chunk_trailer_crlf = 1;
            } else if (ch == '\n' && c->chunk_trailer_crlf == 1) {
                c->chunk_trailer_crlf = 2;
            } else {
                c->chunk_trailer_crlf = 0;
            }
            if (c->chunk_trailer_crlf == 2) {
                c->chunk_state = CHUNK_STATE_DONE;
                return 1;
            }
            break;
        case CHUNK_STATE_DONE:
            return 1;
        }
        i++;
    }
    return 0;
}

static void resp_buffer_reset(HttpConn *c)
{
    if (!c) return;
    if (c->resp_buf) {
        free(c->resp_buf);
        c->resp_buf = NULL;
    }
    c->resp_len = 0;
    c->resp_cap = 0;
}

static int resp_buffer_append(HttpConn *c, const uint8_t *data, size_t len)
{
    if (!c || !data || len == 0) return 0;
    if (c->resp_len + len > c->resp_cap) {
        size_t new_cap = c->resp_cap ? c->resp_cap * 2 : MAX_BUFF;
        if (new_cap < c->resp_len + len) new_cap = c->resp_len + len;
        uint8_t *p = realloc(c->resp_buf, new_cap);
        if (!p) return -1;
        c->resp_buf = p;
        c->resp_cap = new_cap;
    }
    memcpy(c->resp_buf + c->resp_len, data, len);
    c->resp_len += len;
    return 0;
}

static void init_conn_table(void) {
    for (int i = 0; i < FD_MAX; i++) {
        conn_table[i].fd = -1;
        conn_table[i].in_use = false;
        conn_table[i].kind = CONN_FREE;
        conn_table[i].peer_fd = -1;
        conn_table[i].buff_used = 0;
        conn_table[i].last_active_ms = 0;
        conn_table[i].header_len = 0;
        conn_table[i].content_length = -1;
        conn_table[i].body_forwarded = 0;
        conn_table[i].state = 0;
        conn_table[i].transport = TRANSPORT_PLAIN;
        conn_table[i].ssl = NULL;
        conn_table[i].ssl_ctx = NULL;
        conn_table[i].pending_send_len = 0;
        conn_table[i].pending_send_off = 0;
        conn_table[i].want_write = false;
        conn_table[i].resp_buf = NULL;
        conn_table[i].resp_len = 0;
        conn_table[i].resp_cap = 0;
        conn_table[i].chunked = false;
        chunk_state_reset(&conn_table[i]);
    }
}

static HttpConn *alloc_conn(int fd, ConnType kind)
{
    if (fd < 0 || fd >= FD_MAX) return NULL;
    HttpConn *c = &conn_table[fd];
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->in_use = true;
    c->kind = kind;
    c->peer_fd = -1;
    c->buff_used = 0;
    c->last_active_ms = now_ms();
    c->header_len = 0;
    c->content_length = -1;
    c->body_forwarded = 0;
    c->transport = TRANSPORT_PLAIN;
    c->ssl = NULL;
    c->ssl_ctx = NULL;
    c->pending_send_len = 0;
    c->pending_send_off = 0;
    c->want_write = false;
    c->resp_buf = NULL;
    c->resp_len = 0;
    c->resp_cap = 0;
    c->chunked = false;
    chunk_state_reset(c);
    if (kind == CONN_CLIENT) {
        c->state = CLIENT_READING_HEADER;
    } else if (kind == CONN_SERVER) {
        c->state = SERVER_READING_HEADER;
    }
    return c;
}

static void free_conn(int fd, fd_set *activefds, int *p_maxfd, int listen_fd)
{
    if (fd == listen_fd) return;
    if (fd < 0 || fd >= FD_MAX) return;

    HttpConn *c = &conn_table[fd];
    if (!c->in_use) return;

    int peer = c->peer_fd;

    ssl_cleanup_conn(c);
    resp_buffer_reset(c);

    c->in_use = false;
    c->kind = CONN_FREE;
    c->fd = -1;
    c->peer_fd = -1;
    c->buff_used = 0;
    c->header_len = 0;
    c->content_length = -1;
    c->body_forwarded = 0;
    c->state  = 0;
    c->transport = TRANSPORT_PLAIN;
    c->pending_send_len = 0;
    c->pending_send_off = 0;
    c->want_write = false;
    c->chunked = false;
    chunk_state_reset(c);

    FD_CLR(fd, activefds);
    close(fd);

    if (peer >= 0 && peer < FD_MAX) {
        HttpConn *p = &conn_table[peer];
        if (p->in_use) {
            ssl_cleanup_conn(p);
            resp_buffer_reset(p);
            p->in_use = false;
            p->kind = CONN_FREE;
            p->fd  = -1;
            p->peer_fd = -1;
            p->buff_used = 0;
            p->header_len = 0;
            p->content_length = -1;
            p->body_forwarded = 0;
            p->state = 0;
            p->transport = TRANSPORT_PLAIN;
            FD_CLR(peer, activefds);
            close(peer);
        }
    }

    if (fd == *p_maxfd || (peer >= 0 && peer == *p_maxfd)) {
        while (*p_maxfd >= 0 && !FD_ISSET(*p_maxfd, activefds)) {
            (*p_maxfd)--;
        }
    }
}

static int connect_to_server(const char *host, uint16_t port)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;      // try IPv4/IPv6
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0) {
        proxy_log("[proxy] getaddrinfo(%s:%s) failed: %s\n",
                  host, port_str, gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(fd);
        fd = -1;
    }

    if (fd < 0) {
        proxy_log("[proxy] connect_to_server(%s:%u) failed: %s\n",
                  host, (unsigned)port, strerror(errno));
    }

    freeaddrinfo(res);
    return fd;
}

static int create_listen_socket(uint16_t port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    int yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, 128) < 0) {
        close(sockfd);
        return -1;
    }
    return sockfd;
}

static inline int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static inline int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static char* find_double_crlf(uint8_t *buf, size_t len)
{
    if (len < 4) return NULL;
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i]   == '\r' &&
            buf[i+1] == '\n' &&
            buf[i+2] == '\r' &&
            buf[i+3] == '\n') {
            return (char*)(buf + i);
        }
    }
    return NULL;
}

/* =============== header injection =============== */
static int inject_cs112_and_forward(HttpConn *s) {

    if (s->header_len < 4) return -1;

    const char inject_line[] = "X-Proxy:CS112\r\n";
    size_t inject_len = sizeof(inject_line) - 1;

    size_t old_header_len = s->header_len;
    size_t body_len       = s->buff_used - old_header_len;

    // keep headers up to last header line CRLF, drop final empty line CRLF
    size_t prefix_len= old_header_len - 2;

    // +2: only one extra CRLF as the blank line
    size_t new_header_len = prefix_len + inject_len + 2;

    if (new_header_len + body_len > MAX_BUFF) {
        return -1;
    }

    uint8_t tmp[MAX_BUFF];

    memcpy(tmp, s->buff, prefix_len);                     // old headers
    memcpy(tmp + prefix_len, inject_line, inject_len);    // X-Proxy header
    memcpy(tmp + prefix_len + inject_len, "\r\n", 2);     // single blank line
    memcpy(tmp + new_header_len, s->buff + old_header_len, body_len); // body

    memcpy(s->buff, tmp, new_header_len + body_len);
    s->header_len = new_header_len;
    s->buff_used  = new_header_len + body_len;

    return 0;
}

static int send_simple_error_to_client(HttpConn *c, int code, const char *reason)
{
    if (!c || !reason) return -1;
    char resp[256];
    int n = snprintf(resp, sizeof(resp), "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, reason);
    if (n <= 0) return -1;
    ssize_t s = conn_send(c, resp, (size_t)n);
    if (s < 0) return -1;
    return 0;
}


/* =============== OpenSSL helper impl =============== */

static int ssl_global_init(const char *ca_cert_path, const char *ca_key_path)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    g_upstream_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_upstream_ctx) {
        return -1;
    }

    SSL_CTX_set_verify(g_upstream_ctx, SSL_VERIFY_NONE, NULL);

    FILE *f = fopen(ca_cert_path, "r");
    if (!f) return -1;
    g_ca_cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!g_ca_cert) return -1;

    f = fopen(ca_key_path, "r");
    if (!f) return -1;
    g_ca_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!g_ca_key) return -1;

    return 0;
}

static int generate_leaf_cert_and_key(const char *host, X509 **cert_out, EVP_PKEY **pkey_out)
{
    if (!host || !cert_out || !pkey_out) return -1;

    X509 *cert = X509_new();
    if (!cert) return -1;

    X509_set_version(cert, 2);

    uint64_t serial = 0;
    if (RAND_bytes((unsigned char *)&serial, sizeof(serial)) != 1) {
        serial = (uint64_t)time(NULL);
    }
    ASN1_INTEGER_set_uint64(X509_get_serialNumber(cert), serial);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    X509_set_issuer_name(cert, X509_get_subject_name(g_ca_cert));

    X509_NAME *subj = X509_NAME_new();
    if (!subj) {
        X509_free(cert);
        return -1;
    }
    X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                               (const unsigned char *)host, -1, -1, 0);
    X509_set_subject_name(cert, subj);
    X509_NAME_free(subj);

    EVP_PKEY *leaf_pkey = EVP_PKEY_new();
    if (!leaf_pkey) {
        X509_free(cert);
        return -1;
    }
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    if (!rsa || !bn) {
        if (rsa) RSA_free(rsa);
        if (bn) BN_free(bn);
        EVP_PKEY_free(leaf_pkey);
        X509_free(cert);
        return -1;
    }
    if (!BN_set_word(bn, RSA_F4) || RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        BN_free(bn);
        RSA_free(rsa);
        EVP_PKEY_free(leaf_pkey);
        X509_free(cert);
        return -1;
    }
    BN_free(bn);
    if (EVP_PKEY_assign_RSA(leaf_pkey, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(leaf_pkey);
        X509_free(cert);
        return -1;
    }

    if (!X509_set_pubkey(cert, leaf_pkey)) {
        EVP_PKEY_free(leaf_pkey);
        X509_free(cert);
        return -1;
    }

    X509V3_CTX v3ctx;
    X509V3_set_ctx(&v3ctx, g_ca_cert, cert, NULL, NULL, 0);
    char altname[512];
    snprintf(altname, sizeof(altname), "DNS:%s", host);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_alt_name, altname);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (!X509_sign(cert, g_ca_key, EVP_sha256())) {
        EVP_PKEY_free(leaf_pkey);
        X509_free(cert);
        return -1;
    }

    *cert_out = cert;
    *pkey_out = leaf_pkey;
    return 0;
}

static int cache_get_leaf_material(const char *host, X509 **cert_out, EVP_PKEY **pkey_out)
{
    if (!host || !host[0] || !cert_out || !pkey_out) return -1;

    MitmCertCacheEntry *entry = NULL;
    HASH_FIND_STR(g_mitm_cache, host, entry);
    if (!entry) {
        X509 *cert = NULL;
        EVP_PKEY *pkey = NULL;
        if (generate_leaf_cert_and_key(host, &cert, &pkey) != 0) {
            return -1;
        }

        entry = malloc(sizeof(*entry));
        if (!entry) {
            X509_free(cert);
            EVP_PKEY_free(pkey);
            return -1;
        }
        strncpy(entry->host, host, sizeof(entry->host) - 1);
        entry->host[sizeof(entry->host) - 1] = '\0';
        entry->cert = cert;
        entry->pkey = pkey;
        HASH_ADD_STR(g_mitm_cache, host, entry);
    }

    if (!X509_up_ref(entry->cert)) {
        return -1;
    }
    if (!EVP_PKEY_up_ref(entry->pkey)) {
        X509_free(entry->cert);
        return -1;
    }

    *cert_out = entry->cert;
    *pkey_out = entry->pkey;
    return 0;
}

static void cache_free_all_mitm_ctx(void)
{
    MitmCertCacheEntry *entry, *tmp;
    HASH_ITER(hh, g_mitm_cache, entry, tmp) {
        HASH_DEL(g_mitm_cache, entry);
        X509_free(entry->cert);
        EVP_PKEY_free(entry->pkey);
        free(entry);
    }
}

static int enable_tls_mitm(HttpConn *c, HttpConn *s, const char *host)
{
    SSL *server_ssl = SSL_new(g_upstream_ctx);
    if (!server_ssl) return -1;
    SSL_set_fd(server_ssl, s->fd);
    //set SNI for upstream so servers that require it will respond correctly
    if (host && host[0]) {
        SSL_set_tlsext_host_name(server_ssl, host);
    }
    if (SSL_connect(server_ssl) <= 0) {
        SSL_free(server_ssl);
        return -1;
    }

    X509 *leaf_cert = NULL;
    EVP_PKEY *leaf_pkey = NULL;
    if (cache_get_leaf_material(host, &leaf_cert, &leaf_pkey) != 0) {
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
        return -1;
    }

    SSL_CTX *client_ctx = SSL_CTX_new(TLS_server_method());
    if (!client_ctx) {
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
        X509_free(leaf_cert);
        EVP_PKEY_free(leaf_pkey);
        return -1;
    }

    if (!SSL_CTX_use_certificate(client_ctx, leaf_cert) ||
        !SSL_CTX_use_PrivateKey(client_ctx, leaf_pkey)) {
        SSL_CTX_free(client_ctx);
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
        X509_free(leaf_cert);
        EVP_PKEY_free(leaf_pkey);
        return -1;
    }

    X509_free(leaf_cert);
    EVP_PKEY_free(leaf_pkey);

    SSL *client_ssl = SSL_new(client_ctx);
    if (!client_ssl) {
        SSL_CTX_free(client_ctx);
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
        return -1;
    }
    SSL_set_fd(client_ssl, c->fd);
    if (ssl_accept_with_retry(client_ssl) != 0) {
        SSL_free(client_ssl);
        SSL_CTX_free(client_ctx);
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
        return -1;
    }

    c->ssl = client_ssl;
    c->ssl_ctx = client_ctx;
    c->transport = TRANSPORT_TLS;
    c->state = CLIENT_READING_HEADER;
    c->buff_used = 0;
    c->header_len = 0;

    s->ssl = server_ssl;
    s->ssl_ctx = NULL;
    s->transport = TRANSPORT_TLS;
    s->state = SERVER_READING_HEADER;
    s->buff_used = 0;
    s->header_len = 0;

    make_socket_nonblocking(c->fd);
    make_socket_nonblocking(s->fd);
    return 0;
}

static void ssl_cleanup_conn(HttpConn *c)
{
    if (!c) return;
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->ssl_ctx) {
        SSL_CTX_free(c->ssl_ctx);
        c->ssl_ctx = NULL;
    }
    c->pending_send_len = 0;
    c->pending_send_off = 0;
    c->want_write = false;
}
