/*
 * file : virtserial-host.c
 * desc : file transfer between guest and host via virtserialport
 *
 * notes:
 * 
 *      This program is a skeletal version of "auto-virtserial.c" by:
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
 *      This program runs on the host and sends commands to the "virtserial-guest"
 *      program via the following UNIX domain sockets:
 *
 *      > "/tmp/virtserial/test0" not used here (meant for ops on 'virtconsole')
 *      > "/tmp/virtserial/test1" used for passing control commands
 *      > "/tmp/virtserial/test2" used for data transfers
 *
 *
 * Some information on the virtio serial ports is available at
 *  http://www.linux-kvm.org/page/VMchannel_Requirements
 *  https://fedoraproject.org/wiki/Features/VirtioSerial
 */

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include "virtserial-demo.h"

#define DEBUG 1

#ifdef DEBUG
void debug(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}
#else
#define debug(fmt, ...) do { } while (0)
#endif

#define BUF_LENGTH 4080
#define UNIX_PATH_MAX 108

static unsigned int nr_passed, nr_failed;
static bool guest_ok = false;

static struct host_chars {
    char *path;
    int sock;
    bool caching;
    bool throttled;
} chardevs[] = {
    {
        .path = "/tmp/virtserial/test0",
        .caching = false,
        .throttled = false,
    }, {
        .path = "/tmp/virtserial/test1",
        .caching = true,
        .throttled = false,
    }, {
        .path = "/tmp/virtserial/test2",
        .caching = true,
        .throttled = false,
    }, {
        NULL,
    }
};

static int host_connect_chardev(int nr)
{
    struct sockaddr_un sock;
    int ret;

    chardevs[nr].sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (chardevs[nr].sock == -1)
        error(errno, errno, "socket %d", nr);

    sock.sun_family = AF_UNIX;
    memcpy(&sock.sun_path, chardevs[nr].path, sizeof(sock.sun_path));
    ret = connect(chardevs[nr].sock, (struct sockaddr *)&sock, sizeof(sock));
        if (ret < 0)
            error(errno, errno, "connect: %s", chardevs[nr].path);
    return ret;
}

static int host_close_chardev(int nr)
{
    return close(chardevs[nr].sock);
}

static int get_guest_response(struct guest_packet *gpkt)
{
    return read(chardevs[1].sock, gpkt, sizeof(*gpkt));
}

static int guest_cmd_only(struct guest_packet *gpkt)
{
    return write(chardevs[1].sock, gpkt, sizeof(*gpkt));
}

static int guest_cmd(struct guest_packet *gpkt)
{
	int ret  = 0;
	gpkt->key = 100;
	gpkt->value = 321;
   ret = write(chardevs[1].sock, gpkt, sizeof(*gpkt));

   printf("wrote something to guest. ret val:%d\n", ret);

    get_guest_response(gpkt);
    printf("Got guest response\n");
    printf("Key:%d: value:%d\n", gpkt->key, gpkt->value);
    printf("KEY_RESULT:%d\n", KEY_RESULT);
    if (gpkt->key == KEY_RESULT)
        return gpkt->value;
    return -1;
}

static int guest_open_port(int nr)
{
    struct guest_packet gpkt;

    gpkt.key = KEY_OPEN;
    gpkt.value = nr;
    return guest_cmd(&gpkt);
}

static int guest_close_port(int nr)
{
    struct guest_packet gpkt;

    gpkt.key = KEY_CLOSE;
    gpkt.value = nr;
    return guest_cmd(&gpkt);
}

static int guest_set_length(int nr, int len)
{
    struct guest_packet gpkt;

    gpkt.key = KEY_LENGTH;
    gpkt.value = len;
    return guest_cmd(&gpkt);
}


static int guest_set_port_nonblocking(int nr, int value)
{
    struct guest_packet gpkt;

    gpkt.key = KEY_NONBLOCK;
    gpkt.value = value;
    return guest_cmd(&gpkt);
}

static int guest_open_host_bigfile(int value)
{
    struct guest_packet gpkt;

    gpkt.key = KEY_OPEN_HOST_BIGFILE;
    gpkt.value = value;
    return guest_cmd(&gpkt);
}

static int guest_open_guest_bigfile(int value)
{
    struct guest_packet gpkt;

    gpkt.key = KEY_OPEN_GUEST_BIGFILE;
    gpkt.value = value;
    return guest_cmd(&gpkt);
}

#if GUEST_SHUTDOWN
static void guest_shutdown(void)
{
    struct guest_packet gpkt;

    gpkt.key = KEY_SHUTDOWN;
    guest_cmd_only(&gpkt);
    return;
}
#endif

enum result_ops {
    OP_EQ = 0,
    OP_NE,
    OP_LT,
    OP_GT,
};

/*
 * Function that displays pass/fail results for each test, keeps a count
 * of tests passing and failing.
 * Arguments:
 *  test: the name of the test
 *  enabled: type of testing to be done: enabled / disabled
 *  stage: in case of failures, this shows which stage failed
 *  ret: return value of function
 *  expected_en: expected value of 'ret'  for the test to pass in enabled case
 *  expected_dis: expected value of 'ret' for the test to pass in disabled case
 *  op: This is the operator to test the return and the expected return --
 *      equal, greater than, less than, not equal.
 *  final: is this the final subtest for this testcase? (helpful for
 *         the test_passed case.)
 *
 * Returns 0 if test passed, -1 if it failed
 */

static int result(const char *test, const bool enabled, const char *stage,
            const int ret, const int expected_en, const int expected_dis,
            const int op, const bool final)
{
    int r, expected;
    char *ch_op;

    expected = enabled ? expected_en : expected_dis;

    switch (op) {
    case OP_EQ:
        r = (ret == expected) ? 0 : -1;
        ch_op = "=";
        break;
    case OP_NE:
        r = (ret != expected) ? 0 : -1;
        ch_op = "!=";
        break;
    case OP_LT:
        r = (ret < expected) ? 0 : -1;
        ch_op = "<";
        break;
    case OP_GT:
        r = (ret > expected) ? 0 : -1;
        ch_op = ">";
        break;
    default:
        r = -1;
        ch_op = "?";
    }
    if (!final && !r)
        return r;

    printf("Im here\n");

    fprintf(stderr, "%*s - %*s (%*s): ",
        25, test, 8, enabled ? "enabled" : "disabled", 10, stage);
    if (!r) {
        fprintf(stderr, "PASS\n");
        nr_passed++;
    } else {
        fprintf(stderr, "FAIL");
        debug("  (Expected result: %s %d, received result: %d)",
                    ch_op, expected, ret);
        fprintf(stderr, "\n");
        nr_failed++;
    }
    return r;
}

static int test_host_file_send(int nr)
{
    char buf[BUF_LENGTH];
    char csum[BUF_LENGTH];
    struct guest_packet gpkt;
    int err, ret, fd, csum_fd;

    printf("<DEBUG MSG:%s:%d>\n", __func__, __LINE__);

    /*
     * Open guest, open host, send file, compute checksum on
     * guest, compute checksum here, compare
     */
    fd = open(HOST_BIG_FILE, O_RDONLY);
    err = result(__func__, true, "open", fd, -1, 0, OP_GT, false);
    if (err)
        return err;

    guest_open_port(nr);
    host_connect_chardev(nr);

    ret = guest_open_host_bigfile(1);
    err = result(__func__, true, "guest open", ret, -1, 0, OP_GT, false);
    if (err)
        goto out_close;

    guest_set_length(nr, BUF_LENGTH);

    gpkt.key = KEY_HOST_BYTESTREAM;
    gpkt.value = nr;
    guest_cmd_only(&gpkt);
    /* The guest now is waiting for our data */
printf("Guest is waiting for our data\n");

    while (1) {
        ret = read(fd, buf, BUF_LENGTH);
        if (ret < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        else if (ret < 0) {
            fprintf(stderr, "read error %d\n", errno);
            break;
        }
        if (ret == 0)
            break;
        write(chardevs[nr].sock, buf, ret);
    }

    close(fd);
    /* guest will stop reading only if read() returns 0 */
    host_close_chardev(nr);

    err = result(__func__, true, "read/write", ret, -1, 0, OP_GT, false);
    if (err)
        goto out_close;

    get_guest_response(&gpkt);
    err = result(__func__, true, "bytestream response",
                 gpkt.key, KEY_RESULT, 0, OP_EQ, false);
    if (err)
        goto out_close;

    err = result(__func__, true, "bytestream response",
                 gpkt.value, 0, 0, OP_EQ, false);
    if (err)
        goto out_close;

    host_connect_chardev(nr);
    gpkt.key = KEY_HOST_CSUM;
    gpkt.value = nr;
    guest_cmd_only(&gpkt);

    /* Compute checksum here while the guest does the same */
    ret = system("sha1sum /tmp/virtserial/host-big-file > /tmp/virtserial/host-csumfile");
    err = result(__func__, true, "csum1",
                 ret, -1, 0, OP_GT, false);
    if (err)
        goto out_close;

    err = result(__func__, true, "csum2",
                 WIFEXITED(ret), true, 0, OP_EQ, false);
    if (err)
        goto out_close;

    err = result(__func__, true, "csum3",
                 WEXITSTATUS(ret), 0, 0, OP_EQ, false);
    if (err)
        goto out_close;

    csum_fd = open("/tmp/virtserial/host-csumfile", O_RDONLY);
    err = result(__func__, true, "open csumfd",
                 csum_fd, -1, 0, OP_GT, false);
    if (err)
        goto out_close;

    read(csum_fd, csum, BUF_LENGTH);
    close(csum_fd);

    get_guest_response(&gpkt);
    err = result(__func__, true, "csum response",
                 gpkt.key, KEY_RESULT, 0, OP_EQ, false);
    if (err)
        goto out_close;

    err = result(__func__, true, "guest csum",
                 gpkt.value, 0, 0, OP_GT, false);
    if (err)
        goto out_close;

    /* Guest sent its computed checksum on the same port */
    read(chardevs[nr].sock, buf, gpkt.value);
    ret = strncmp(csum, buf, gpkt.value);
    err = result(__func__, true, "csum", ret, 0, 0, OP_EQ, true);
    if (err) {
        debug("guest csum: %s\n", buf);
        debug("host csum : %s\n", csum);
    }

out_close:
    host_close_chardev(nr);
    guest_close_port(nr);
    return err;
}

static int test_guest_file_send(int nr)
{
    char buf[BUF_LENGTH];
    char csum[BUF_LENGTH];
    struct pollfd pollfds[1];
    struct guest_packet gpkt;
    int err, ret, fd, csum_fd;

    /*
     * Open guest, open host, recv file, compute checksum on
     * guest, compute checksum here, compare
     */
    fd = open("/tmp/virtserial/guest-big-file", O_RDWR | O_CREAT, S_IWUSR);
    err = result(__func__, true, "host open", fd, -1, 0, OP_GT, false);
    if (err) {
        return err;
    }

    guest_open_port(nr);
    host_connect_chardev(nr);

    ret = guest_set_port_nonblocking(nr, true);

    ret = guest_open_guest_bigfile(1);
    err = result(__func__, true, "guest open", ret, -1, 0, OP_GT, false);
    if (err)
        goto out_close;

    guest_set_length(nr, BUF_LENGTH);

    gpkt.key = KEY_GUEST_BYTESTREAM;
    gpkt.value = nr;
    guest_cmd_only(&gpkt);
    /* The guest now is sending us data */

    pollfds[0].fd = chardevs[nr].sock;
    pollfds[0].events = POLLIN;
    while (1) {
        /* If no response received for 5s, assume guest is stuck. */
        ret = poll(pollfds, 1, 5000);
        if (ret <= 0) {
            debug("poll returned %d\n", ret);
            break;
        }
        ret = read(chardevs[nr].sock, buf, BUF_LENGTH);
        if (ret == 0)
            break;
        if (ret < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        else if (ret < 0) {
            fprintf(stderr, "read error %d\n", errno);
            break;
        }
        write(fd, buf, ret);
        if (ret > 0 && ret < BUF_LENGTH)
            break;
    }
    err = result(__func__, true, "read/write", ret, -1, 0, OP_GT, false);
    if (err)
        goto out_close;

    close(fd);
    get_guest_response(&gpkt);
    err = result(__func__, true, "bytestream response",
                 gpkt.key, KEY_RESULT, 0, OP_EQ, false);
    if (err)
        goto out_close;

    err = result(__func__, true, "bytestream response",
                 gpkt.value, 0, 0, OP_EQ, false);
    if (err)
        goto out_close;

    guest_open_port(nr);
    gpkt.key = KEY_GUEST_CSUM;
    gpkt.value = nr;
    guest_cmd_only(&gpkt);
    /* Compute checksum here while the guest does the same */
    ret = system("sha1sum /tmp/virtserial/guest-big-file > /tmp/virtserial/guest-csumfile");
    err = result(__func__, true, "csum1",
                 ret, -1, 0, OP_GT, false);
    if (err)
        goto out_close;

    err = result(__func__, true, "csum2",
                 WIFEXITED(ret), true, 0, OP_EQ, false);
    if (err)
        goto out_close;

    err = result(__func__, true, "csum3",
                 WEXITSTATUS(ret), 0, 0, OP_EQ, false);
    if (err)
        goto out_close;

    csum_fd = open("/tmp/virtserial/guest-csumfile", O_RDONLY);
    err = result(__func__, true, "open csumfd",
                 csum_fd, -1, 0, OP_GT, false);
    if (err)
        goto out_close;

    read(csum_fd, csum, BUF_LENGTH);
    close(csum_fd);

    get_guest_response(&gpkt);
    err = result(__func__, true, "csum response",
                 gpkt.key, KEY_RESULT, 0, OP_EQ, false);
    if (err)
        goto out_close;

    err = result(__func__, true, "guest csum",
                 gpkt.value, 0, 0, OP_GT, false);
    if (err)
        goto out_close;

    /* Guest sent its computed checksum on the same port */
    read(chardevs[nr].sock, buf, gpkt.value);
    ret = strncmp(csum, buf, gpkt.value);
    err = result(__func__, true, "csum", ret, 0, 0, OP_EQ, true);
    if (err) {
        debug("guest csum: %s\n", buf);
        debug("host csum : %s\n", csum);
    }

out_close:
    host_close_chardev(nr);
    guest_close_port(nr);
    return err;
}

enum {
    TEST_H_FILE_SEND = 0,
    TEST_G_FILE_SEND,
    TEST_END
};

static struct test_parameters {
    int (*test_function)(int);
    bool enabled;
    bool needs_guestok;
} tests[TEST_END] = {
    {
        .test_function = test_host_file_send,
        .needs_guestok = true,
        .enabled = true,
    },
    {
        .test_function = test_guest_file_send,
        .needs_guestok = true,
        .enabled = true,
    },
};

static int run_test(int test_nr, int nr)
{
    int ret = 0;

    if (tests[test_nr].enabled) {
        if (tests[test_nr].needs_guestok && !guest_ok)
            return 0;
        ret = tests[test_nr].test_function(nr);
        //post_test_cleanup(nr);
    }
    return ret;
}

static int start_tests(void)
{
    /* Sends a big file across, compares sha1sums */
    run_test(TEST_H_FILE_SEND, 2);

    /* Sends a big file across, compares sha1sums */
    run_test(TEST_G_FILE_SEND, 2);

    return 0;
}

int main(int argc, const char *argv[])
{
    struct guest_packet gpkt;
    struct pollfd pollfd[1];
    int i, ret;

    /* Check if host char drvs are ok */
    for (i = 1; chardevs[i].path; i++) {
        ret = access(chardevs[i].path, R_OK|W_OK);
        if (ret)
            error(errno, errno, "access %s", chardevs[i].path);
        if (strlen(chardevs[i].path) > UNIX_PATH_MAX)
            error(E2BIG, E2BIG, "%s", chardevs[i].path);
    }

    /* Open the control port on "/tmp/test1" */
    ret = host_connect_chardev(1);
    if (ret < 0) 
        return ret;

    /* Waiting 90s max. for initial guest OK message */
    pollfd[0].fd = chardevs[1].sock;
    pollfd[0].events = POLLIN;

    ret = poll(pollfd, 1, 90000);
    if (ret == -1)
        error(errno, errno, "poll %s", chardevs[1].path);
    if (ret == 0) {
        fprintf(stderr, "timeout!\n");
        return -1;
    }

    if (pollfd[0].revents & POLLIN) {
        ret = read(chardevs[1].sock, &gpkt, sizeof(gpkt));
        if (ret < sizeof(gpkt))
            error(EINVAL, EINVAL, "Read error");
        if (gpkt.key == KEY_STATUS_OK && gpkt.value) {
            guest_ok = true;
            debug("Guest is up %d\n", gpkt.value);
        } else  if (gpkt.key == KEY_GUEST_ERR) {
            error(EINVAL, EINVAL, "Guest error");
        }
    }

    /* Ready, perform tests */
    start_tests();

#if GUEST_SHUTDOWN
    /* Send guest a command to shut itself down. */
    guest_shutdown();
#endif

    host_close_chardev(1);

    return nr_failed;
}
