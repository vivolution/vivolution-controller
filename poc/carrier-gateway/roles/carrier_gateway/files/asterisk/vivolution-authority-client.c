#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define AUTHORITY_SOCKET "/run/vivolution-carrier-authority.sock"
#define RESPONSE_MAX 192

static int exact_destination(const char *value) {
    size_t length = strlen(value);
    if (length < 9 || length > 16 || value[0] != '+' || value[1] < '1' || value[1] > '9') {
        return 0;
    }
    for (size_t index = 2; index < length; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return 0;
        }
    }
    return 1;
}

static int exchange(const char *request) {
    int descriptor = -1;
    struct sockaddr_un address;
    char response[RESPONSE_MAX];
    struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
    size_t request_length = strlen(request);
    size_t received = 0;

    if (request_length == 0 || request_length > 96 || request[request_length - 1] != '\n') {
        return 2;
    }
    descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return 2;
    }
    if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
        close(descriptor);
        return 2;
    }
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        close(descriptor);
        return 2;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(AUTHORITY_SOCKET) >= sizeof(address.sun_path)) {
        close(descriptor);
        return 2;
    }
    memcpy(address.sun_path, AUTHORITY_SOCKET, strlen(AUTHORITY_SOCKET) + 1);
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(descriptor);
        return 2;
    }
    {
        size_t sent = 0;
        while (sent < request_length) {
            ssize_t written = send(descriptor, request + sent, request_length - sent, MSG_NOSIGNAL);
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                close(descriptor);
                return 2;
            }
            sent += (size_t)written;
        }
    }
    if (shutdown(descriptor, SHUT_WR) != 0) {
        close(descriptor);
        return 2;
    }
    while (received + 1 < sizeof(response)) {
        ssize_t count;
        do {
            count = read(descriptor, response + received, sizeof(response) - received - 1);
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            close(descriptor);
            return 2;
        }
        if (count == 0) {
            break;
        }
        received += (size_t)count;
        if (memchr(response, '\n', received) != NULL) {
            break;
        }
    }
    close(descriptor);
    if (received == 0 || received >= sizeof(response)) {
        return 2;
    }
    response[received] = '\0';
    if (response[received - 1] != '\n' || strchr(response, '\n') != response + received - 1) {
        return 2;
    }
    if (fwrite(response, 1, received, stdout) != received || fflush(stdout) != 0) {
        return 2;
    }
    return 0;
}

int main(int argc, char **argv) {
    char request[96];
    int length;
    if (argc == 2 && strcmp(argv[1], "--invalidate-start") == 0) {
        return exchange("INVALIDATE_START\n");
    }
    if (argc != 2 || !exact_destination(argv[1])) {
        return 2;
    }
    length = snprintf(request, sizeof(request), "CLAIM %s\n", argv[1]);
    if (length < 0 || (size_t)length >= sizeof(request)) {
        return 2;
    }
    return exchange(request);
}
