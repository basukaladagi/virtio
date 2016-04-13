/* desc: file transfer between guest and host via virtserialport
 *
 * notes:
 *      
 *      This program is a skeletal version of "auto-virtserial-guest.c" by:
 *
 *      Amit Shah <amit.shah@redhat.com>
 *      git://fedorapeople.org/home/fedora/amitshah/public_git/test-virtserial.git
 *
 *      Copyright (C) 2009, Red Hat, Inc.
 *
 *      Licensed under the GNU General Public License v2. See the file COPYING
 *      for more details.
 *
 * Siro Mugabi, nairobi-embedded.org
 *
 *      
 *      The program responds to commands received from the "virtserial-host" 
 *      program on the host via the following serial port device files:
 *
 *      > "/dev/virtio-ports/test1" or "/dev/vportNp1" for control commands.
 *      > "/dev/virtio-ports/test2" or "/dev/vportNp2" for data transfers
 *
 *  NOTE:
 *      > "/dev/virtio-ports/console.0" or "/dev/vportNp0" for hvc0 (not used)
 *
 *
 * Some information on the virtio serial ports is available at
 *  http://www.linux-kvm.org/page/VMchannel_Requirements
 *  https://fedoraproject.org/wiki/Features/VirtioSerial
 *
 */

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "virtserial-demo.h"

#define CONTROL_PORT "/dev/virtio-ports/test1"
#define CONTROL_PORT2 "/dev/vport0p1"
#define MAX_PORTS 10

/* The fd to work with for read / write requests. Set by the open message */
static int g_fd;
/* The fd to stuff in bytes for a big file receive command */
static int g_bigfile_fd;
/* The length to read / write. Set by the length message. Unset at close */
static int g_length;
/* Array to hold fds of all open ports. Used for polling host connect events */
static int g_open_fds[MAX_PORTS];
/* Array to hold poll results of g_open_fds from the sigio_handler() */
static int g_poll_results[MAX_PORTS];

static ssize_t safewrite(int fd, const void *buf, size_t count, bool eagain_ret)
{
    size_t ret, len;
    int flags;
    bool nonblock;

    nonblock = false;
    flags = fcntl(fd, F_GETFL);
    if (flags > 0 && flags & O_NONBLOCK)
        nonblock = true;

    len = count;
    while (len > 0) {
        ret = write(fd, buf, len);
        if (ret == -1) {
            if (errno == EINTR)
                continue;

            if (errno == EAGAIN) {
                if (nonblock && eagain_ret) {
                    return -EAGAIN;
                } else {
                    continue;
                }
            }
            return -errno;
        } else if (ret == 0) {
            break;
        } else {
            buf += ret;
            len -= ret;
        }
    }
    return count - len;
}

static ssize_t saferead(int fd, void *buf, size_t count, bool eagain_ret)
{
    size_t ret, len;
    int flags;
    bool nonblock;

    nonblock = false;
    flags = fcntl(fd, F_GETFL);
    if (flags > 0 && flags & O_NONBLOCK)
        nonblock = true;

    len = count;
    while (len > 0) {
        ret = read(fd, buf, len);
        if (ret == -1) {
            if (errno == EINTR)
                continue;

            if (errno == EAGAIN) {
                if (nonblock && eagain_ret) {
                    return -EAGAIN;
                } else {
                    continue;
                }
            }
            return -errno;
        } else if (ret == 0) {
            break;
        } else {
            buf += ret;
            len -= ret;
        }
    }
    return count - len;
}

static int safepoll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int ret;

    do {
        ret = poll(fds, nfds, timeout);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1)
        ret = -errno;

    return ret;
}

static char *get_port_dev(unsigned int nr)
{
    char *buf;
    buf = malloc(strlen("/dev/virtio-ports/test10") + 1);
    if (!buf)
        return NULL;
    sprintf(buf, "/dev/virtio-ports/test%u", nr);
    return buf;
}

static int open_port(int nr)
{
    char *buf;
    int fd, ret;

    buf = get_port_dev(nr);
    if (!buf)
        return -ENOMEM;
    fd = open(buf, O_RDWR);
    free(buf);

    if (fd == -1)
        return -errno;
    g_fd = fd;

    ret = fcntl(fd, F_SETOWN, getpid());
    if (ret < 0) {
        perror("F_SETOWN");
    }
    ret = fcntl(fd, F_GETFL);
    ret = fcntl(fd, F_SETFL, ret | O_ASYNC);
    if (ret < 0) {
        perror("F_SETFL");
    }

    if (nr < MAX_PORTS)
        g_open_fds[nr] = fd;
    return fd;
}

static int close_port(int nr)
{
    int ret;

    ret = close(g_open_fds[nr]);
    if (ret < 0)
        ret = -errno;
    g_length = 0;

    if (nr < MAX_PORTS) {
        g_open_fds[nr] = -1;
        g_poll_results[nr] = 0;
    }
    return ret;
}


static int set_port_nonblocking(int val)
{
    int ret, flags;

    flags = fcntl(g_fd, F_GETFL);
    if (flags == -1)
        return -errno;

    if (val)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    ret = fcntl(g_fd, F_SETFL, flags);
    if (ret == -1)
        return -errno;
    return 0;
}


static int open_host_bigfile(int val)
{
    g_bigfile_fd = open(HOST_BIG_FILE, O_RDWR | O_CREAT, S_IWUSR);
    if (g_bigfile_fd < 0)
        return -errno;
    return 0;
}

static int recv_bytestream(int val)
{
    int ret;
    char *buf;

    buf = malloc(g_length);
    if (!buf)
        return -ENOMEM;

    while((ret = saferead(g_fd, buf, g_length, false)) > 0) {
        ret = safewrite(g_bigfile_fd, buf, ret, false);
        if (ret < 0)
            break;
    }
    free(buf);
    close(g_bigfile_fd);
    return ret;
}

static int send_host_csum(int nr)
{
    char *buf;
    int ret, csum_fd;

    buf = malloc(g_length);

    ret = system("sha1sum /tmp/virtserial/host-big-file > /tmp/virtserial/host-csumfile");
    if (ret == -1)
        return -errno;
    if (WIFEXITED(ret) != true)
        return -1;
    if (WEXITSTATUS(ret) != 0)
        return -WEXITSTATUS(ret);

    csum_fd = open("/tmp/virtserial/host-csumfile", O_RDONLY);
    if (!csum_fd) {
        return -errno;
    }
    ret = saferead(csum_fd, buf, g_length, false);
    close(csum_fd);

    if (ret > 0)
        ret = safewrite(g_fd, buf, ret, false);
    free(buf);
    return ret;
}

static int open_guest_bigfile(int val)
{
    g_bigfile_fd = open(GUEST_BIG_FILE, O_RDONLY);
    if (g_bigfile_fd < 0)
        return -errno;
    return 0;
}

static int send_bytestream(int val)
{
    int ret;
    char *buf;

    buf = malloc(g_length);
    if (!buf)
        return -ENOMEM;

    while((ret = saferead(g_bigfile_fd, buf, g_length, false)) > 0) {
        ret = safewrite(g_fd, buf, ret, false);
        if (ret < 0)
            break;
    }
    free(buf);
    close(g_bigfile_fd);
    close(g_fd);
    return ret;
}

static int send_guest_csum(int nr)
{
    char *buf;
    int ret, csum_fd;

    buf = malloc(g_length);

    ret = system("sha1sum /tmp/virtserial/guest-big-file > /tmp/virtserial/guest-csumfile");
    if (ret == -1)
        return -errno;
    if (WIFEXITED(ret) != true)
        return -1;
    if (WEXITSTATUS(ret) != 0)
        return -WEXITSTATUS(ret);

    csum_fd = open("/tmp/virtserial/guest-csumfile", O_RDONLY);
    if (!csum_fd) {
        return -errno;
    }
    ret = saferead(csum_fd, buf, g_length, false);
    close(csum_fd);

    if (ret > 0)
        ret = safewrite(g_fd, buf, ret, false);
    free(buf);
    return ret;
}

static int get_port_from_fd(int fd)
{
    unsigned int i;

    for (i = 0; i < MAX_PORTS; i++) {
        if (g_open_fds[i] == fd)
            return i;
    }
    return -1;
}

static void sigio_handler(int signal)
{
    struct pollfd pollfds[MAX_PORTS];
    unsigned int i, j;
    int ret;

    for (i = 0, j = 0; i < MAX_PORTS; i++) {
        if (g_open_fds[i] > -1) {
            pollfds[j].fd = g_open_fds[i];
            pollfds[j++].events = POLLIN|POLLOUT;
        }
    }
    ret = safepoll(pollfds, j, 0);
    if (ret == -1) {
        for (i = 0; i < MAX_PORTS; i++)
            g_poll_results[i] = 0;
        return;
    }

    for (i = 0; i < j; i++) {
        int port;

        port = get_port_from_fd(pollfds[i].fd);
        if (port == -1)
            continue;
        g_poll_results[port] = pollfds[i].revents;
    }
}

static int install_sigio_handler(void)
{
    struct sigaction action;
    unsigned int i;
    int ret;

    action.sa_handler = sigio_handler;
    action.sa_flags = 0;
    ret = sigemptyset(&action.sa_mask);
    if (ret) {
        ret = -errno;
        goto out;
    }

    ret = sigaction(SIGIO, &action, NULL);
    if (ret)
        ret = -errno;

out:
    for (i = 0; i < MAX_PORTS; i++)
        g_poll_results[i] = 0;

    return ret;
}

static void send_report(int cfd, int ret)
{
    struct guest_packet gpkt;

    gpkt.key = KEY_RESULT;
    gpkt.value = ret;
    safewrite(cfd, &gpkt, sizeof(gpkt), false);
}

int main(int argc, char *argv[])
{
    struct guest_packet gpkt;
    struct pollfd pollfd[1];
    unsigned int i;
    int ret, cfd;


    /*
     * Have to install it right away. Else we'll start getting
     * SIGIOs and the default action is to terminate the process.
     */
    install_sigio_handler();

    ret = access(CONTROL_PORT, R_OK|W_OK);
    if (ret == -1) {
        ret = access(CONTROL_PORT2, R_OK|W_OK);
        if (ret == -1) {
            error(errno, errno, "No control port found %s or %s", CONTROL_PORT, CONTROL_PORT2);
        }
    }

back_to_open:
    cfd = open(CONTROL_PORT, O_RDWR);
    if (cfd == -1) {
        cfd = open(CONTROL_PORT2, O_RDWR);
        if (cfd == -1) {
            error(errno, errno, "open control port %s", CONTROL_PORT);
        }
    }

    gpkt.key = KEY_STATUS_OK;
    gpkt.value = 1;
    ret = safewrite(cfd, &gpkt, sizeof(gpkt), false);
    if (ret < 0)
        error(-ret, -ret, "write control port");

    for (i = 0; i < MAX_PORTS; i++)
        g_open_fds[i] = -1;

    pollfd[0].fd = cfd;
    pollfd[0].events = POLLIN;

    while (1) {
        ret = safepoll(pollfd, 1, -1);
        if (ret < 0)
            error(errno, errno, "poll");

        if (!(pollfd[0].revents & POLLIN))
            continue;

        ret = saferead(cfd, &gpkt, sizeof(gpkt), false);
        if (ret < sizeof(gpkt)) {
            /*
             * Out of sync with host. Close port and start over.
             * For us to get back in sync with host, this port
             * has to have buffer cachin disabled
             */
            close(cfd);
            goto back_to_open;
        }
        switch(gpkt.key) {
        case KEY_OPEN:
            ret = open_port(gpkt.value);
            send_report(cfd, ret);
            break;
        case KEY_CLOSE:
            ret = close_port(gpkt.value);
            send_report(cfd, ret);
            break;
        case KEY_NONBLOCK:
            ret = set_port_nonblocking(gpkt.value);
            send_report(cfd, ret);
            break;
        case KEY_LENGTH:
            g_length = gpkt.value;
            send_report(cfd, 0);
            break;
        case KEY_OPEN_HOST_BIGFILE:
            ret = open_host_bigfile(gpkt.value);
            send_report(cfd, ret);
            break;
        case KEY_HOST_BYTESTREAM:
            ret = recv_bytestream(gpkt.value);
            send_report(cfd, ret);
            break;
        case KEY_HOST_CSUM:
            ret = send_host_csum(gpkt.value);
            send_report(cfd, ret);
            break;
        case KEY_OPEN_GUEST_BIGFILE:
            ret = open_guest_bigfile(gpkt.value);
            send_report(cfd, ret);
            break;
        case KEY_GUEST_BYTESTREAM:
            ret = send_bytestream(gpkt.value);
            send_report(cfd, ret);
            break;
        case KEY_GUEST_CSUM:
            ret = send_guest_csum(gpkt.value);
            send_report(cfd, ret);
            break;
        case KEY_SHUTDOWN:
            system("shutdown -h now");
            break;
        default:
            send_report(cfd, -ERANGE);
            break;
        }
    }
    return 0;
}
