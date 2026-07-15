#define _GNU_SOURCE
#include <errno.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

#define HOST_CID 2
#define MCP_PORT 5002

static int write_all(int fd, const char *data, size_t length) {
    while (length > 0) {
        ssize_t count = write(fd, data, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        data += count;
        length -= (size_t)count;
    }
    return 0;
}

int main(void) {
    int host = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (host < 0) return 130;
    struct sockaddr_vm address = {0};
    address.svm_family = AF_VSOCK;
    address.svm_cid = HOST_CID;
    address.svm_port = MCP_PORT;
    if (connect(host, (struct sockaddr *)&address, sizeof(address)) < 0) return 131;
    struct pollfd descriptors[2] = {
        {.fd = STDIN_FILENO, .events = POLLIN},
        {.fd = host, .events = POLLIN},
    };
    char buffer[65536];
    bool stdin_open = true;
    bool host_open = true;
    while (stdin_open || host_open) {
        if (poll(descriptors, 2, -1) < 0) {
            if (errno == EINTR) continue;
            return 132;
        }
        if (descriptors[0].revents & (POLLIN | POLLHUP)) {
            ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (count <= 0) {
                shutdown(host, SHUT_WR);
                descriptors[0].events = 0;
                stdin_open = false;
            } else if (write_all(host, buffer, (size_t)count) < 0) return 133;
        }
        if (descriptors[1].revents & (POLLIN | POLLHUP)) {
            ssize_t count = read(host, buffer, sizeof(buffer));
            if (count <= 0) {
                descriptors[1].events = 0;
                host_open = false;
            } else if (write_all(STDOUT_FILENO, buffer, (size_t)count) < 0) return 134;
        }
    }
    close(host);
    return 0;
}

