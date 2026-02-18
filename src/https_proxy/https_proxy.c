#define _GNU_SOURCE

#include "proxy_client.h"
#include "socket_helpers.h"
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <curl/curl.h>


#define BUFFER_BLOCK_SZ 4096
#define MAX_HEADER_SZ 32 * 1024

void *session_thread(void *arg) {
  struct proxy_session *session = arg;
  session_serve(session);
  free_session(session);
  free(session);
  return NULL;
}

int main(int argc, char *argv[]) {
  signal(SIGPIPE, SIG_IGN);
  if (argc != 4) {
    printf(
        "Argument incorrect: need to provide port, cert_path and key_path\n");
    return 1;
  }
  char *cert_path = argv[2];
  char *key_path = argv[3];

  // init SSL lib
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  const SSL_METHOD *client_method = TLS_client_method();
  const SSL_METHOD *server_method = TLS_server_method();
  SSL_CTX *proxy_to_host_ctx = SSL_CTX_new(client_method);
  SSL_CTX *proxy_to_client_ctx = SSL_CTX_new(server_method);

  // load ca cert and key
  X509 *ca_cert = PEM_read_X509(fopen(cert_path, "r"), NULL, NULL, NULL);
  EVP_PKEY *ca_key =
      PEM_read_PrivateKey(fopen(key_path, "r"), NULL, NULL, NULL);

  // open server socket
  int portn = atoi(argv[1]);
  int server_fd;
  init_socket(&server_fd, portn);
  listen(server_fd, SOMAXCONN);

  printf("https proxy hosting on %d\n", portn);
  while (1) {
    int client_fd = accept_connection(server_fd);
    if (client_fd < 0) {
      printf("Failed to accept connection\n");
      continue;
    }
    // printf("Accepted connection\n");

    // initialize client
    struct proxy_session *session =
        make_session(client_fd, proxy_to_client_ctx, proxy_to_host_ctx);
    if (session_establish_SSL(session, ca_cert, ca_key) == 0) {
      pthread_t thread_id;
      pthread_create(&thread_id, NULL, session_thread, session);
      pthread_detach(thread_id);
    } else {
      // printf("Failed to establish SSL connection\n");
      free_session(session);
      free(session);
    }
  }

  SSL_CTX_free(proxy_to_host_ctx);
  SSL_CTX_free(proxy_to_client_ctx);

  return 0;
}
