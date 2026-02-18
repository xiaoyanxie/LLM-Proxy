#ifndef SOCKET_HELPERS_H
#define SOCKET_HELPERS_H

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static inline int connect_to_host(const char *hostname, const int port) {
  struct hostent *host = gethostbyname(hostname);

  if (!host) {
    return -1;
  }

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket creation");
    return -1;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  memcpy(&addr.sin_addr.s_addr, host->h_addr_list[0], host->h_length);

  if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("connect to host");
    close(sockfd);
    return -1;
  }
  return sockfd;
}

static inline int init_socket(int *socketfd, int port) {
  *socketfd = socket(AF_INET, SOCK_STREAM, 0);
  int reuseopt = 1;

  setsockopt(*socketfd, SOL_SOCKET, SO_REUSEADDR, &reuseopt, sizeof reuseopt);

  if (*socketfd < 0) {
    perror("Socket creation failed.");
    return 1;
  }

  // define server socket address
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof server_addr);

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = INADDR_ANY;

  // cast server addr ess_in to sockaddr and bind
  if (bind(*socketfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) !=
      0) {
    perror("Socket bind failed.");
    return 1;
  };
  return 0;
}

static inline int accept_connection(int s_socketfd) {
  struct sockaddr_in client_addr;
  memset(&client_addr, 0, sizeof client_addr);
  // waiting to accept connection
  int client_addr_len = sizeof(client_addr);
  int c_socketfd = accept(s_socketfd, (struct sockaddr *)&client_addr,
                          (socklen_t *)&client_addr_len);

  if (c_socketfd < 0) {
    return -1;
  }
  return c_socketfd;
}

#endif
