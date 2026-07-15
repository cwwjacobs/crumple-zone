#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <linux/vm_sockets.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define HOST_CID 2
#define LIFECYCLE_PORT 5000
#define LINE_MAXIMUM 512

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

static int read_line(int fd, char *buffer, size_t capacity) {
    size_t used = 0;
    while (used + 1 < capacity) {
        char character;
        ssize_t count = read(fd, &character, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        if (character == '\n') {
            buffer[used] = '\0';
            return 0;
        }
        if (character < 0x20 || character > 0x7e) return -1;
        buffer[used++] = character;
    }
    return -1;
}

static bool valid_code(const char *value, size_t minimum, size_t maximum) {
    size_t length = strlen(value);
    if (length < minimum || length > maximum) return false;
    for (size_t index = 0; index < length; index++) {
        char character = value[index];
        if (!((character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') || character == '_')) return false;
    }
    return true;
}

static bool valid_hex(const char *value, size_t expected) {
    if (strlen(value) != expected) return false;
    for (size_t index = 0; index < expected; index++) {
        char character = value[index];
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) return false;
    }
    return true;
}

static int connect_host(void) {
    struct sockaddr_vm address = {0};
    address.svm_family = AF_VSOCK;
    address.svm_cid = HOST_CID;
    address.svm_port = LIFECYCLE_PORT;
    for (int attempt = 0; attempt < 200; attempt++) {
        int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd >= 0 && connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
            struct timeval timeout = {.tv_sec = 10, .tv_usec = 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            return fd;
        }
        if (fd >= 0) close(fd);
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }
    return -1;
}

static int write_marker(const char *run_id, const char *canary) {
    mkdir("/var/lib", 0755);
    mkdir("/var/lib/crumple", 0700);
    int marker = open("/var/lib/crumple/last_run", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (marker < 0) return -1;
    if (write_all(marker, run_id, strlen(run_id)) < 0 || write_all(marker, "\n", 1) < 0) {
        close(marker);
        return -1;
    }
    if (fsync(marker) < 0) {
        close(marker);
        return -1;
    }
    close(marker);

    mkdir("/run/crumple", 0700);
    int assignment = open("/run/crumple/assignment", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (assignment < 0) return -1;
    int written = dprintf(assignment, "run_id=%s\ncanary=%s\n", run_id, canary);
    if (written <= 0 || fsync(assignment) < 0) {
        close(assignment);
        return -1;
    }
    close(assignment);
    return 0;
}

int main(void) {
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "");
    mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "");
    mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=8m");
    mkdir("/run/crumple", 0700);
    bool prior_state = access("/var/lib/crumple/last_run", F_OK) == 0;
    dprintf(STDOUT_FILENO, "CZ_GUEST_BOOT_V1\n");

    int channel = connect_host();
    if (channel < 0) return 111;
    if (write_all(channel, "HELLO lifecycle.v1\n", 19) < 0) return 112;

    char line[LINE_MAXIMUM];
    char challenge[65] = {0};
    if (read_line(channel, line, sizeof(line)) < 0 ||
        sscanf(line, "CHALLENGE %64s", challenge) != 1 || !valid_hex(challenge, 32)) return 113;
    if (dprintf(channel, "READY %s %d\n", challenge, prior_state ? 1 : 0) < 0) return 114;

    char run_id[69] = {0};
    char canary[65] = {0};
    if (read_line(channel, line, sizeof(line)) < 0 ||
        sscanf(line, "ASSIGN %68s %64s", run_id, canary) != 2 ||
        !valid_code(run_id, 12, 68) || strncmp(run_id, "run_", 4) != 0 || !valid_hex(canary, 32)) return 115;
    if (write_marker(run_id, canary) < 0) return 116;
    if (dprintf(channel, "ASSIGNED %s %s\n", run_id, canary) < 0) return 117;

    if (read_line(channel, line, sizeof(line)) < 0 || strcmp(line, "SHUTDOWN") != 0) return 118;
    if (dprintf(channel, "BYE %s\n", run_id) < 0) return 119;
    fsync(channel);
    close(channel);
    sync();
    reboot(LINUX_REBOOT_CMD_RESTART);
    return 0;
}

