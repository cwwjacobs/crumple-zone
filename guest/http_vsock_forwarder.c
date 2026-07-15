#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define HOST_CID 2
#define MODEL_PROXY_PORT 5001
#define LOOPBACK_PORT 8080

static int connect_host(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_vm address = {0};
    address.svm_family = AF_VSOCK;
    address.svm_cid = HOST_CID;
    address.svm_port = MODEL_PROXY_PORT;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int relay(int left, int right) {
    struct pollfd descriptors[2] = {
        {.fd = left, .events = POLLIN},
        {.fd = right, .events = POLLIN},
    };
    char buffer[16384];
    bool left_open = true;
    bool right_open = true;
    while (left_open || right_open) {
        if (poll(descriptors, 2, 30000) <= 0) return -1;
        for (int index = 0; index < 2; index++) {
            if (!(descriptors[index].revents & (POLLIN | POLLHUP))) continue;
            int source = descriptors[index].fd;
            int destination = descriptors[1 - index].fd;
            ssize_t count = read(source, buffer, sizeof(buffer));
            if (count <= 0) {
                shutdown(destination, SHUT_WR);
                descriptors[index].events = 0;
                if (index == 0) left_open = false; else right_open = false;
                continue;
            }
            size_t offset = 0;
            while (offset < (size_t)count) {
                ssize_t written = write(destination, buffer + offset, (size_t)count - offset);
                if (written < 0 && errno == EINTR) continue;
                if (written <= 0) return -1;
                offset += (size_t)written;
            }
        }
    }
    return 0;
}

int main(void) {
    signal(SIGCHLD, SIG_IGN);
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) return 120;
    int enabled = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(LOOPBACK_PORT);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 || listen(listener, 8) < 0) return 121;
    for (;;) {
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0 && errno == EINTR) continue;
        if (client < 0) return 122;
        pid_t child = fork();
        if (child < 0) {
            close(client);
            continue;
        }
        if (child == 0) {
            close(listener);
            int host = connect_host();
            if (host < 0) _exit(123);
            int status = relay(client, host);
            close(client);
            close(host);
            _exit(status == 0 ? 0 : 124);
        }
        close(client);
    }
}

