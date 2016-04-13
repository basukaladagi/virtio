/*
 * auto-virtserial: Exercise various options for virtio-serial ports
 *
 * This program is the controlling program to be run on the host.
 *
 * Assumptions:
 * - The first port, that'll get seen as /dev/vcon1, will be the port
 *   for control information
 * - The second port (vcon2) is started with no extra params (cache_buffers=1)
 * - The third port (vcon3) is started with cache_buffers=0
 * - The fourth port (vcon4) is started with host and guest limits to 1MB.
 *
 * Most of these tests have been described in the test-virtserial.c file
 *
 * Some information on the virtio serial ports is available at
 *  http://www.linux-kvm.org/page/VMchannel_Requirements
 *  https://fedoraproject.org/wiki/Features/VirtioSerial
 *
 * Copyright (C) 2009, Red Hat, Inc.
 *
 * Author(s):
 *  Amit Shah <amit.shah@redhat.com>
 *
 * Licensed under the GNU General Public License v2. See the file COPYING
 * for more details.
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
#include "virtserial.h"

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
		.path = "/tmp/amit/test0",
		.caching = false,
		.throttled = false,
	}, {
		.path = "/tmp/amit/test1",
		.caching = true,
		.throttled = false,
	}, {
		.path = "/tmp/amit/test2",
		.caching = true,
		.throttled = false,
	}, {
		.path = "/tmp/amit/test3",
		.caching = false,
		.throttled = false,
	}, {
		.path = "/tmp/amit/test4",
		.caching = true,
		.throttled = true,
	}, {
		NULL,
	}
};

static void handle_guest_error(struct guest_packet *gpkt)
{
	char *buf;

	buf = malloc(gpkt->value);
	if (!buf)
		error(ENOMEM, ENOMEM, "Guest err");
	read(chardevs[1].sock, buf, gpkt->value);
	fprintf(stderr, "guest error: %s\n", buf);
	free(buf);
}

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
	/*
	 * It's ok if we can't connect to the control port in case
	 * we're running on old qemu
	 */
	if (ret < 0 && nr == 1 && !guest_ok) {
		debug("%s: Can't open connection to %s\n",
		      __func__, chardevs[nr].path);
	} else {
		if (ret < 0)
			error(errno, errno, "connect: %s", chardevs[nr].path);
	}
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
	write(chardevs[1].sock, gpkt, sizeof(*gpkt));
	get_guest_response(gpkt);
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

static int guest_read(int nr, int len)
{
	struct guest_packet gpkt;
	int ret;

	ret = guest_set_length(nr, len);
	if (ret)
		return ret;

	gpkt.key = KEY_READ;
	gpkt.value = nr;

	return guest_cmd(&gpkt);
}

static int guest_write(int nr, int len)
{
	struct guest_packet gpkt;
	int ret;

	ret = guest_set_length(nr, len);
	if (ret)
		return ret;

	gpkt.key = KEY_WRITE;
	gpkt.value = nr;

	return guest_cmd(&gpkt);
}

static int guest_set_poll_events(int nr, int events)
{
	struct guest_packet gpkt;

	gpkt.key = KEY_POLL_EVENTS;
	gpkt.value = events;
	return guest_cmd(&gpkt);
}

static int guest_poll(int nr, int events, int timeout)
{
	struct guest_packet gpkt;

	guest_set_poll_events(nr, events);

	gpkt.key = KEY_POLL;
	gpkt.value = timeout;
	return guest_cmd(&gpkt);
}

static int guest_lseek(int nr)
{
	struct guest_packet gpkt;

	gpkt.key = KEY_LSEEK;
	gpkt.value = nr;
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

static int guest_create_read_thread(int nr)
{
	struct guest_packet gpkt;

	gpkt.key = KEY_CREATE_READ_THREAD;
	gpkt.value = nr;
	return guest_cmd(&gpkt);
}

static int guest_join_read_thread(int nr)
{
	struct guest_packet gpkt;

	gpkt.key = KEY_JOIN_READ_THREAD;
	gpkt.value = nr;
	return guest_cmd(&gpkt);
}

static int guest_get_sigio_poll_result(int nr)
{
	struct guest_packet gpkt;

	gpkt.key = KEY_GET_SIGIO_RESULT;
	gpkt.value = nr;
	return guest_cmd(&gpkt);
}

static void guest_shutdown(void)
{
	struct guest_packet gpkt;

	gpkt.key = KEY_SHUTDOWN;
	guest_cmd_only(&gpkt);
	return;
}

static void show_stats(void)
{
	fprintf(stderr, "-----\n");
	fprintf(stderr, "Total tests passed: %u\n", nr_passed);
	fprintf(stderr, "Total tests failed: %u\n", nr_failed);
	fprintf(stderr, "-----\n");
}

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

static int test_open_close(int nr)
{
	int ret;

	ret = guest_open_port(nr);
	result(__func__, true, "open", ret, -1, -1, OP_GT, true);

	ret = guest_close_port(nr);
	return result(__func__, true, "close", ret, 0, 0, OP_EQ, true);
}

static int test_multiple_open(int nr)
{
	int err, ret;

	ret = guest_open_port(nr);
	err = result(__func__, true, "single", ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	ret = guest_open_port(nr);
	err = result(__func__, true, "multiple", ret, 0, 0, OP_LT, true);
	ret = guest_close_port(nr);
	if (ret)
		debug("%s: close return: %d\n", __func__, ret);

	return err;
}

static int test_sysfs_and_udev(int nr)
{
	struct guest_packet gpkt;
	int err, ret;

	gpkt.key = KEY_CHECK_SYSFS;
	gpkt.value = nr;
	ret = guest_cmd(&gpkt);
	err = result(__func__, true, "sysfs", ret, 0, 0, OP_EQ, false);
	if (err)
		return err;

	gpkt.key = KEY_CHECK_UDEV;
	gpkt.value = nr;
	ret = guest_cmd(&gpkt);
	err = result(__func__, true, "udev", ret, 0, 0, OP_EQ, true);

	return err;
}

/* Reads should return 0 when host chardev isn't connected */
static int test_read_without_host(int nr)
{
	int err, ret;

	ret = guest_open_port(nr);
	err = result(__func__, true, "open", ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	ret = guest_read(nr, 0);
	err = result(__func__, true, "read", ret, 0, 0, OP_EQ, true);
	guest_close_port(nr);

	return err;
}

static int test_blocking_read(int nr)
{
	struct guest_packet gpkt;
	struct pollfd pollfd[1];
	int err, ret;

	ret = guest_open_port(nr);
	err = result(__func__, true, "open", ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	host_connect_chardev(nr);

	guest_set_length(nr, sizeof(gpkt));
	/* Reads should block now that the host is connected */
	gpkt.key = KEY_READ;
	gpkt.value = nr;
	guest_cmd_only(&gpkt);

	/*
	 * We'll try to be a little smart here: The guest is blocked
	 * on read, so we can't start a poll() request in the same
	 * thread. so either we spawn off the blocking read in a
	 * different thread or we poll our controlling port for the
	 * response from the read syscall (the guest will immediately
	 * write the return value from the read() syscall once it
	 * comes out of its blocking state).
	 *
	 * So what we do here is poll on the control port for the read
	 * response. If there is any, it means the guest came out of
	 * its blocking read.
	 */
	pollfd[0].fd = chardevs[1].sock;
	pollfd[0].events = POLLIN;
	/* See if we get something in 5s -- we shouldn't. */
	ret = poll(pollfd, 1, 5000);
	if (ret == -1)
		error(errno, errno, "%s: poll", __func__);
	err = result(__func__, true, "poll", ret, 0, 0, OP_EQ, false);
	if (err)
		goto out;

	/* Write out anything -- doesn't matter what it is */
	write(chardevs[nr].sock, &gpkt, sizeof(gpkt));
	ret = poll(pollfd, 1, 5000);
	err = result(__func__, true, "poll", ret, 1, 0, OP_EQ, false);
	if (err)
		goto out;

	get_guest_response(&gpkt);
	if (gpkt.key != KEY_RESULT)
		error(EINVAL, EINVAL, "%s: guest response\n", __func__);

	err = result(__func__, true, "read",
		     gpkt.value, sizeof(gpkt), 0, OP_EQ, true);
out:
	guest_close_port(nr);
	host_close_chardev(nr);

	return err;
}

static int test_nonblocking_read(int nr)
{
	struct guest_packet gpkt;
	struct pollfd pollfd[1];
	int err, ret;

	ret = guest_open_port(nr);
	err = result(__func__, true, "open", ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	host_connect_chardev(nr);

	ret = guest_set_port_nonblocking(nr, true);
	err = result(__func__, true, "blocking", ret, 0, 0, OP_EQ, false);
	if (err)
		goto out;

	guest_set_length(nr, sizeof(gpkt));
	/* Reads should block now that the host is connected */
	gpkt.key = KEY_READ;
	gpkt.value = nr;
	guest_cmd_only(&gpkt);

	pollfd[0].fd = chardevs[1].sock;
	pollfd[0].events = POLLIN;
	/* See if we get something in 5s -- we should. */
	ret = poll(pollfd, 1, 5000);
	if (ret == -1)
		error(errno, errno, "%s: poll", __func__);
	err = result(__func__, true, "host poll", ret, 1, 0, OP_EQ, false);
	if (err)
		goto out;

	get_guest_response(&gpkt);
	err = result(__func__, true, "guest poll",
		     gpkt.value, -EAGAIN, 0, OP_EQ, false);
	if (err)
		goto out;

	/* Write out anything -- doesn't matter what it is */
	write(chardevs[nr].sock, &gpkt, sizeof(gpkt));

	/* Give the guest a chance to be scheduled in and react */
	sleep(2);

	ret = guest_read(nr, sizeof(gpkt));
	err = result(__func__, true, "read", ret, sizeof(gpkt), 0, OP_EQ, true);
out:
	guest_close_port(nr);
	host_close_chardev(nr);

	return err;
}

/*
 * Similar to test_nonblocking_write(): open guest port, write
 * lots of data.  We should be put to sleep once the host
 * can't accept any more data.  Then read some data from host,
 * we should be writable again.
 */
static int test_blocking_write(int nr)
{
	void *buf;
	unsigned int i;
	int err, ret;

	ret = guest_open_port(nr);
	err = result(__func__, true, "guest open", ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	host_connect_chardev(nr);

	/*
	 * We currently have 128 buffers in a virtqueue --
	 * hw/virtio-serial-bus.c, so this while loop should stop when
	 * i is 128.  However, the loop actually stops when i is 158
	 * -- the qemu chardev itself can buffer some data.
	 */
	for (i = 0; i < 200; i++) {
		ret = guest_poll(nr, 0, 0);
		if (i && ret == 0) {
			/* vq full.  Next write will block. */
			break;
		}
		err = result(__func__, true, "guest poll", ret,
			     POLLOUT, POLLOUT, OP_EQ, false);
		if (err)
			goto out;

		ret = guest_write(nr, BUF_LENGTH);
		err = result(__func__, true, "guest write",
			     ret, BUF_LENGTH, BUF_LENGTH, OP_EQ, false);
		if (err)
			goto out;
	}

	buf = malloc(BUF_LENGTH);
	for (i = 0; i < 32; i++) {
		/*
		 * One last thing: read out some buffers from host
		 * (more than the qemu-chardev buffer limit).  See if
		 * guest gets POLLOUT set.
		 */
		read(chardevs[nr].sock, buf, BUF_LENGTH);
	}
	free(buf);

	sleep(2);

	ret = guest_poll(nr, 0, 0);
	err = result(__func__, true, "read-poll",
		     ret, POLLOUT, POLLOUT, OP_EQ, true);
out:
	host_close_chardev(nr);
	guest_close_port(nr);
	return err;
}

static int test_nonblocking_write(int nr)
{
	void *buf;
	unsigned int i;
	int err, ret;
	bool test_done;

	ret = guest_open_port(nr);
	err = result(__func__, true, "guest open", ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	ret = guest_set_port_nonblocking(nr, true);
	err = result(__func__, true, "blocking", ret, 0, 0, OP_EQ, false);
	if (err)
		goto out;

	host_connect_chardev(nr);

	test_done = false;
	/*
	 * We currently have 128 buffers in a virtqueue --
	 * hw/virtio-serial-bus.c, so this while loop should stop when
	 * i is 128.  However, the loop actually stops when i is 158
	 * -- the qemu chardev itself can buffer some data.
	 */
	for (i = 0; i < 200 && !test_done; i++) {
		ret = guest_poll(nr, 0, 0);
		if (i && ret == 0) {
			/* vq full. Nonblocking IO and poll for that works. */

			test_done = true;

			/* Now try writing to the guest. That should fail too */
		}
		err = result(__func__, test_done, "guest poll", ret,
			     0, POLLOUT, OP_EQ, false);
		if (err)
			goto out;

		ret = guest_write(nr, BUF_LENGTH);
		err = result(__func__, test_done, "guest write",
			     ret, -EAGAIN, BUF_LENGTH, OP_EQ, false);
		if (err)
			goto out;
	}

	buf = malloc(BUF_LENGTH);
	for (i = 0; i < 32; i++) {
		/*
		 * One last thing: read out some buffers from host
		 * (more than the qemu-chardev buffer limit).  See if
		 * guest gets POLLOUT set.
		 */
		read(chardevs[nr].sock, buf, BUF_LENGTH);
	}
	free(buf);

	sleep(2);

	ret = guest_poll(nr, 0, 0);
	err = result(__func__, true, "read-poll",
		     ret, POLLOUT, POLLOUT, OP_EQ, true);
out:
	ret = guest_set_port_nonblocking(nr, false);
	if (!err)
		err = result(__func__, true, "non-block", ret, 0, 0, OP_EQ, true);
	host_close_chardev(nr);
	guest_close_port(nr);
	return err;
}

static int test_poll(int nr)
{
	int err, ret;

	guest_open_port(nr);
	ret = guest_poll(nr, 0, 0);
	ret &= ~POLLIN;
	err = result(__func__, true, "POLLHUP", ret, POLLHUP, 0, OP_EQ, true);
	if (err)
		goto out;

	/*
	 * Give the guest a chance to be scheduled in and give correct
	 * results for the previous test -- else it'll find the host
	 * chardev connected.
	 */
	sleep(2);
	host_connect_chardev(nr);
	/* Give the guest a chance to be scheduled in and react */
	sleep(2);
	ret = guest_poll(nr, 0, 0);
	err = result(__func__, true, "POLLOUT", ret, POLLOUT, 0, OP_EQ, true);
	if (err)
		goto out_close;

	write(chardevs[nr].sock, &ret, sizeof(ret));
	/* Give the guest a chance to be scheduled in and react */
	sleep(2);
	ret = guest_poll(nr, 0, 0);
	err = result(__func__, true, "POLLIN",
		     ret, POLLIN|POLLOUT, 0, OP_EQ, true);

out_close:
	host_close_chardev(nr);
out:
	guest_close_port(nr);
	return err;
}

/* lseek in guest - -ESPIPE is the desired result. */
static int test_lseek(int nr)
{
	int err, ret;

	ret = guest_open_port(nr);
	err = result(__func__, true, "open", ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	ret = guest_lseek(nr);
	err = result(__func__, true, "lseek",
		     ret, -ESPIPE, -ESPIPE, OP_EQ, true);

	guest_close_port(nr);
	return err;
}

/*
 * Tests if writes to guest get throttled after sending 1M data
 * The invert parameter specifies the test should pass for ports
 * that don't have throttling enabled
 */
static int test_guest_throttle(int nr)
{
	char *buf;
	struct pollfd pollfd[1];
	size_t size, copied;
	int err, ret;

	/* Open guest */
	ret = guest_open_port(nr);
	err = result(__func__, chardevs[nr].throttled, "open",
		     ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	buf = malloc(BUF_LENGTH);
	if (!buf)
		error(ENOMEM, ENOMEM, "%s\n", __func__);

	memset(buf, 0, BUF_LENGTH);
	host_connect_chardev(nr);

	pollfd[0].fd = chardevs[nr].sock;
	pollfd[0].events = POLLOUT;
	ret = poll(pollfd, 1, 0);
	if (ret == -1)
		error(errno, errno, "%s: poll\n", __func__);
	if (!(pollfd[0].revents & POLLOUT))
		error(ENOSPC, ENOSPC, "%s: can't write\n", __func__);

	copied = 0;
	do {
		size = write(chardevs[nr].sock, buf, BUF_LENGTH);
		if (size == -1)
			error(errno, errno, "%s: write", __func__);
		copied += size;

		ret = poll(pollfd, 1, 2000);
		if (ret == -1)
			error(errno, errno, "%s: poll\n", __func__);
	} while ((pollfd[0].revents & POLLOUT) && (copied < 1078672));

	err = result(__func__, chardevs[nr].throttled, "throttle",
		     pollfd[0].revents & POLLOUT, 0, POLLOUT, OP_EQ, true);
	if (err)
		debug("%s: copied = %zu\n", __func__, copied);

	free(buf);
	guest_close_port(nr);
	host_close_chardev(nr);

	return err;
}

static int test_host_throttle(int nr)
{
	size_t copied;
	int err, ret;

	ret = guest_open_port(nr);
	err = result(__func__, chardevs[nr].throttled, "open",
		     ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	copied = 0;
	do {
		ret = guest_write(nr, BUF_LENGTH);
		if (ret > 0)
			copied += ret;
	} while ((copied < 1054672) && (ret > 0));

	err = result(__func__, chardevs[nr].throttled, "throttle",
		     ret, 0, -ENOSPC, OP_NE, true);

	guest_close_port(nr);
	host_close_chardev(nr);

	return err;
}

static int test_guest_caching(int nr)
{
	char *buf;
	int err, ret;

	ret = guest_open_port(nr);
	err = result(__func__, chardevs[nr].caching, "open",
		     ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	host_connect_chardev(nr);

	buf = malloc(BUF_LENGTH);
	if (!buf)
		error(ENOMEM, ENOMEM, "%s\n", __func__);

	memset(buf, 0, BUF_LENGTH);
	ret = write(chardevs[nr].sock, buf, BUF_LENGTH);
	if (ret == -1)
		error(errno, errno, "%s: write", __func__);

	/* Make sure the data made its way to the port in the guest */
	sleep(2);
	ret = guest_poll(nr, 0, 10000);
	err = result(__func__, chardevs[nr].caching, "guest poll",
		     ret, POLLIN|POLLOUT, POLLIN|POLLOUT, OP_EQ, false);

	guest_close_port(nr);
	host_close_chardev(nr);
	free(buf);
	if (err < 0)
		return err;

	guest_open_port(nr);
	ret = guest_read(nr, BUF_LENGTH);
	err = result(__func__, chardevs[nr].caching, "caching",
		     ret, BUF_LENGTH, 0, OP_EQ, true);
	guest_close_port(nr);

	return err;
}

static int test_host_caching(int nr)
{
	char *buf;
	struct pollfd pollfds[1];
	int err, ret;

	guest_open_port(nr);
	ret = guest_write(nr, BUF_LENGTH);
	err = result(__func__, chardevs[nr].caching, "guest_write",
		     ret, BUF_LENGTH, BUF_LENGTH, OP_EQ, false);
	if (err)
		goto out;

	host_connect_chardev(nr);

	pollfds[0].fd = chardevs[nr].sock;
	pollfds[0].events = POLLIN;
	ret = poll(pollfds, 1, 2000);

	/*
	 * Ensure:
	 *  ret >= 0
	 *      == 1 if caching enabled
	 *      == 0 if caching disabled
	 */
	err = result(__func__, chardevs[nr].caching, "poll",
		     ret, 1, 0, OP_EQ, false);
	if (err)
		goto out;

	/* Handle the noncaching case first */
	if (!chardevs[nr].caching) {
		/*
		 *  We know the test has passed above. Take that into
		 *  account now (pass 'true' as the last arg)
		 */
		result(__func__, chardevs[nr].caching, "caching",
		       0, 0, 0, OP_EQ, true);
		goto out;
	}
	/* Caching case */
	/*
	 * poll worked fine -- but do we also read the length that we wrote?
	 */
	buf = malloc(BUF_LENGTH);
	ret = read(chardevs[nr].sock, buf, BUF_LENGTH);
	free(buf);

	err = result(__func__, chardevs[nr].caching, "caching",
		     ret, BUF_LENGTH, 0, OP_EQ, true);
out:
	host_close_chardev(nr);
	guest_close_port(nr);
	return err;
}

static int test_console(int nr)
{
	char buf[1024], *str;
	struct pollfd pollfds[1];
	int err, ret;

	if (guest_ok) {
		ret = guest_open_port(nr);
		err = result(__func__, true, "open",
			     ret, -ENXIO, 0, OP_EQ, false);
	}
	host_connect_chardev(nr);

	pollfds[0].fd = chardevs[nr].sock;
	pollfds[0].events = POLLIN;

	/*
	 * A console in the guest at /dev/hvc0 is spawned by
	 * auto-virtserial-guest.c so we don't have to do that here
	 */

	/* Send a \n character to get the login prompt as that would
	 * have already been sent by the guest when the console was
	 * spawned and we would have missed it because caching is
	 * disabled on the port.
	 */
	str = "\n";
	write(chardevs[nr].sock, str, strlen(str));

	/* Skip any text before we're presented the login prompt */
	while (poll(pollfds, 1, 5000) == 1)
		read(chardevs[nr].sock, buf, 1024);

	str = strstr(buf, "login: ");
	if (!str) {
		err = result(__func__, true, "login", 0, 1, 0, OP_EQ, false);
		goto out;
	}
	str = "amit\n";
	write(chardevs[nr].sock, str, strlen(str));

	/* Skip any text before we're presented the password prompt */
	while (poll(pollfds, 1, 5000) == 1)
		read(chardevs[nr].sock, buf, 1024);

	str = strstr(buf, "Password: ");
	if (!str) {
		err = result(__func__, true, "password", 0, 1, 0, OP_EQ, false);
		goto out;
	}
	str = "123456\n";
	write(chardevs[nr].sock, str, strlen(str));

	/* Skip any text before we're presented the shell prompt */
	while (poll(pollfds, 1, 5000) == 1)
		read(chardevs[nr].sock, buf, 1024);

	/* Check if we have a prompt */
	str = strstr(buf, "~]$");
	if (!str) {
		err = result(__func__, true, "console", 0, 1, 0, OP_EQ, false);
		goto out;
	}
	/* 'ls' in the current dir */
	str = "ls\n";
	write(chardevs[nr].sock, str, strlen(str));

	/* Skip ls output */
	while (poll(pollfds, 1, 5000) == 1) {
		read(chardevs[nr].sock, buf, 1024);
	}
	/*
	 * 'find /' - time-consuming operation. Had exposed a locking bug
	 * in the guest kernel with > 1 vcpu, found by Christian.
	 */
	str = "find /\n";
	write(chardevs[nr].sock, str, strlen(str));

	ret = 0;
	while (poll(pollfds, 1, 5000) == 1)
		ret = read(chardevs[nr].sock, buf, 1024);

	/* Check if we're back to a prompt again */
	str = strstr(buf, "~]$");
	if (!str) {
		/*
		 * We got the login prompt, passwd prompt, etc. but
		 * didn't finish the 'ls' and 'find /' tests. That's
		 * failure.
		 */
		err = result(__func__, true, "console", 0, 1, 0, OP_EQ, true);
		debug("%s: didn't drop to bash prompt\n", __func__);
		debug("%s: last buf (%d) was %s\n", __func__, ret, buf);
	} else {
		err = result(__func__, true, "console", 0, 0, 0, OP_EQ, true);
	}
	if (!guest_ok) {
		/*
		 * Shut down the guest -- as the guest doesn't have
		 * the agent listening that'll parse the KEY_SHUTDOWN
		 * message.
		 */
		str = "su -\n";
		write(chardevs[nr].sock, str, strlen(str));
		sleep(2);

		str = "123456\n";
		write(chardevs[nr].sock, str, strlen(str));
		sleep(2);

		str = "shutdown -h now\n";
		write(chardevs[nr].sock, str, strlen(str));
	}
out:
	host_close_chardev(nr);
	return err;
}

static int test_host_file_send(int nr)
{
	char buf[BUF_LENGTH];
	char csum[BUF_LENGTH];
	struct guest_packet gpkt;
	int err, ret, fd, csum_fd;

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
	ret = system("sha1sum /tmp/amit/host-big-file > /tmp/amit/host-csumfile");
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

	csum_fd = open("/tmp/amit/host-csumfile", O_RDONLY);
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
	fd = open("/tmp/amit/guest-big-file", O_RDWR | O_CREAT);
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
	ret = system("sha1sum /tmp/amit/guest-big-file > /tmp/amit/guest-csumfile");
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

	csum_fd = open("/tmp/amit/guest-csumfile", O_RDONLY);
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

/*
 * Tests guest's ability to be blocked on read in one thread while
 * writing to the same chardev in another thread
 *
 * - Open guest port
 * - Call threaded test
 * - Wait for POLLOUT from guest for a specific timeout
 * - Collect result.
 *
 * If POLLOUT doesn't get set, that means the test failed and the
 * guest is stuck in a blocking read anyway. So this should be the
 * last test to run.
 */
static int test_threaded_read_write(int nr)
{
	struct pollfd pollfd[1];
	struct guest_packet gpkt;
	int err, ret;

	ret = guest_open_port(nr);
	err = result(__func__, true, "open", ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	host_connect_chardev(nr);

	guest_set_length(nr, sizeof(gpkt));

	ret = guest_create_read_thread(nr);
	err = result(__func__, true, "create thread",
		     ret, -1, -1, OP_GT, false);
	if (err)
		goto out;

	ret = guest_write(nr, BUF_LENGTH);
	err = result(__func__, chardevs[nr].caching, "guest_write",
		     ret, BUF_LENGTH, BUF_LENGTH, OP_EQ, false);
	if (err)
		goto out;

	pollfd[0].fd = chardevs[nr].sock;
	pollfd[0].events = POLLOUT;
	/* Wait for 10s to see if guest writes out something */
	ret = poll(pollfd, 1, 10000);
	if (ret == -1)
		error(errno, errno, "%s: poll\n", __func__);
	if (!(pollfd[0].revents & POLLOUT))
		error(EIO, EIO, "%s: no response from guest\n", __func__);

	/*
	 * Write out something - doesn't matter what. This should make
	 * the guest read thread unblock and return.
	 */
	write(chardevs[nr].sock, &gpkt, sizeof(gpkt));

	ret = guest_join_read_thread(nr);
	err = result(__func__, true, "read", ret,
		     sizeof(gpkt), sizeof(gpkt), OP_EQ, true);

	host_close_chardev(nr);
out:
	guest_close_port(nr);
	return err;
}

/*
 * The virtio_console guest kernel driver sends a SIGIO each time the
 * host-side connection status is changed (connected, disconnected) to
 * a process that has a virtserial port open.
 *
 * Tests:
 *  - open a port in the guest, connect host chardev. Should receive SIGIO.
 *  - open a port in host, then open in guest, disconnect host chardev.
 *  - write from the host to a guest port. Should receive SIGIO.
 *  - open multiple ports in guest, open corresponding host chardevs.
 *  - similar to above for host chardev disconnects
 *  - let the guest poll on some fd, then cause SIGIO. Make sure prev. poll
 *    works fine.
 */
static int test_sigio_handler(int nr)
{
	struct guest_packet gpkt;
	int ret, err;

	guest_open_port(nr);
	/* Give time to the guest to schedule in and perform the open() */
	sleep(2);

	host_connect_chardev(nr);

	/* Give time to the guest to schedule in and to receive the signal */
	sleep(2);

	ret = guest_get_sigio_poll_result(nr);
	err = result(__func__, true, "open",
		     ret, POLLOUT, POLLOUT, OP_EQ, true);

	/* Write something; guest should receive a POLLIN SIGIO */
	write(chardevs[nr].sock, &ret, sizeof(ret));

	ret = guest_get_sigio_poll_result(nr);
	err = result(__func__, true, "in",
		     ret, POLLIN|POLLOUT, POLLIN|POLLOUT, OP_EQ, true);

	guest_read(nr, sizeof(ret));
	host_close_chardev(nr);
	sleep(2);

	ret = guest_get_sigio_poll_result(nr);
	ret &= ~POLLIN;
	err = result(__func__, true, "close",
		     ret, POLLHUP, POLLHUP, OP_EQ, true);

	guest_close_port(nr);

	/* Now opening multiple ports and watching for multiple SIGIOs */
	guest_open_port(2);
	guest_open_port(3);
	guest_open_port(4);

	sleep(2);

	host_connect_chardev(2);
	host_connect_chardev(3);
	host_connect_chardev(4);

	sleep(2);

	ret = guest_get_sigio_poll_result(2);
	err = result(__func__, true, "multi-o2",
		     ret, POLLOUT, POLLOUT, OP_EQ, false);
	ret = guest_get_sigio_poll_result(3);
	err = result(__func__, true, "multi-o3",
		     ret, POLLOUT, POLLOUT, OP_EQ, false);
	ret = guest_get_sigio_poll_result(4);
	err = result(__func__, true, "multi-o4",
		     ret, POLLOUT, POLLOUT, OP_EQ, false);

	host_close_chardev(2);
	host_close_chardev(3);
	host_close_chardev(4);

	sleep(2);

	ret = guest_get_sigio_poll_result(2);
	ret &= ~POLLIN;
	err = result(__func__, true, "multi-c2",
		     ret, POLLHUP, POLLHUP, OP_EQ, true);
	ret = guest_get_sigio_poll_result(3);
	ret &= ~POLLIN;
	err = result(__func__, true, "multi-c3",
		     ret, POLLHUP, POLLHUP, OP_EQ, true);
	ret = guest_get_sigio_poll_result(4);
	ret &= ~POLLIN;
	err = result(__func__, true, "multi-c4",
		     ret, POLLHUP, POLLHUP, OP_EQ, true);

	guest_close_port(2);
	guest_close_port(3);
	guest_close_port(4);

	/*
	 * Now for the poll test: poll for pollin, send data, both
	 * sigio and pollin should get set.
	 */
	ret = guest_open_port(nr);
	err = result(__func__, true, "guest open", ret, -1, -1, OP_GT, false);
	if (err)
		return err;

	host_connect_chardev(nr);

	sleep(2);
	guest_set_poll_events(nr, POLLIN);

	gpkt.key = KEY_POLL;
	gpkt.value = -1;
	guest_cmd_only(&gpkt);
	sleep(2);

	/* Now the guest is blocking on data from us. */
	write(chardevs[nr].sock, &ret, sizeof(ret));
	sleep(2);

	/* Guest should have now come out of poll and also received SIGIO */
	get_guest_response(&gpkt);
	err = result(__func__, true, "poll", gpkt.value,
		     POLLIN, POLLIN, OP_EQ, false);

	ret = guest_get_sigio_poll_result(nr);
	err = result(__func__, true, "poll-sigio",
		     ret, POLLIN|POLLOUT, POLLIN|POLLOUT, OP_EQ, true);

	guest_read(nr, sizeof(ret));
	guest_close_port(nr);
	host_close_chardev(nr);

	return err;
}

enum {
	TEST_OPEN_CLOSE = 0,
	TEST_MULTI_OPEN,
	TEST_SYSFS_UDEV,
	TEST_READ_WO_HOST,
	TEST_BLOCKING_READ,
	TEST_NOBLOCK_READ,
	TEST_BLOCKING_WRITE,
	TEST_NONBLOCK_WRITE,
	TEST_POLL,
	TEST_LSEEK,
	TEST_G_THROTTLE,
	TEST_H_THROTTLE,
	TEST_G_CACHING,
	TEST_H_CACHING,
	TEST_H_FILE_SEND,
	TEST_G_FILE_SEND,
	TEST_CONSOLE,
	TEST_THREADED_READ_WRITE,
	TEST_SIGIO_HANDLER,
	TEST_END
};

static struct test_parameters {
	int (*test_function)(int);
	bool enabled;
	bool needs_guestok;
} tests[TEST_END] = {
	{
		.test_function = test_open_close,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_multiple_open,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_sysfs_and_udev,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_read_without_host,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_blocking_read,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_nonblocking_read,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_blocking_write,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_nonblocking_write,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_poll,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_lseek,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_guest_throttle,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_host_throttle,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_guest_caching,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_host_caching,
		.needs_guestok = true,
		.enabled = true,
	},
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
	{
		.test_function = test_console,
		.needs_guestok = false,
		.enabled = true,
	},
	{
		.test_function = test_threaded_read_write,
		.needs_guestok = true,
		.enabled = true,
	},
	{
		.test_function = test_sigio_handler,
		.needs_guestok = true,
		.enabled = true,
	},
};

static void post_test_cleanup(int nr)
{
	char buf[BUF_LENGTH];
	struct pollfd pollfds[1];
	int ret;

	/* Flush out any data that was left in the guest port */
	if (!guest_ok)
		goto skip_guest;
	ret = guest_open_port(nr);
	if (ret < 0 && ret != -EMFILE)
		goto skip_guest;
	while ((ret = guest_poll(nr, 0, 0))) {
		if ((ret > 0) && (ret & POLLIN)) {
			if (!guest_read(nr, BUF_LENGTH))
				break;
		} else {
			break;
		}
	}
	guest_close_port(nr);

skip_guest:
	/* Flush out any data that was left in the host chardev */
	host_connect_chardev(nr);
	pollfds[0].fd = chardevs[nr].sock;
	pollfds[0].events = POLLIN;
	while ((poll(pollfds, 1, 0) > 0) && (pollfds[0].revents & POLLIN))
		read(chardevs[nr].sock, buf, BUF_LENGTH);
	host_close_chardev(nr);
}

static int run_test(int test_nr, int nr)
{
	int ret = 0;

	if (tests[test_nr].enabled) {
		if (tests[test_nr].needs_guestok && !guest_ok)
			return 0;
		ret = tests[test_nr].test_function(nr);
		post_test_cleanup(nr);
	}
	return ret;
}

static int start_tests(void)
{
	int ret;

	/*
	 * These tests can only be tried when the guest program is
	 * up. The guest program will terminate in case we're running
	 * on an incompatible kernel or qemu version.
	 */

	ret = run_test(TEST_OPEN_CLOSE, 2);
	if (ret)
		return ret;

	ret = run_test(TEST_MULTI_OPEN, 2);
	if (ret)
		return ret;

	run_test(TEST_SYSFS_UDEV, 2);

	ret = run_test(TEST_READ_WO_HOST, 2);
	if (ret)
		return ret;

	ret = run_test(TEST_BLOCKING_READ, 2);
	if (ret)
		return ret;

	ret = run_test(TEST_NOBLOCK_READ, 2);
	if (ret)
		return ret;

#if 0
	ret = run_test(TEST_BLOCKING_WRITE, 2);
	if (ret)
		return ret;

	run_test(TEST_NONBLOCK_WRITE, 2);
#endif

	run_test(TEST_POLL, 2);

	run_test(TEST_LSEEK, 2);

#if 0
	/*
	 * Guest throttling isn't needed anymore after design changes
	 * in the kernel module: each port has its own IO vqs and
	 * outstanding buffers are stored in the vqs themselves.
	 */
	/* Throttling is not enabled on this port */
	run_test(TEST_G_THROTTLE, 2);
	/* Throttling is enabled on this port */
	run_test(TEST_G_THROTTLE, 4);

	/*
	 * Host throttling is also not included in the upstream
	 * code. If this code is pushed upstream, these tests will be
	 * re-added.
	 */
	/* Throttling is not enabled on this port */
	run_test(TEST_H_THROTTLE, 2);
	/* Throttling is enabled on this port */
	run_test(TEST_H_THROTTLE, 4);

	/*
	 * Guest caching is not included in the upstream code as of
	 * now
	 */
	/* Caching is enabled on this port */
	run_test(TEST_G_CACHING, 2);
#endif
	/* Caching is not enabled on this port */
	run_test(TEST_G_CACHING, 3);

#if 0
	/*
	 * Host caching is not included in the upstream code as of now
	 */
	/* Caching is enabled on this port */
	run_test(TEST_H_CACHING, 2);

	/* Caching is not enabled on this port */
	run_test(TEST_H_CACHING, 3);
#endif

	/* Sends a big file across, compares sha1sums */
	run_test(TEST_H_FILE_SEND, 2);

	/* Sends a big file across, compares sha1sums */
	run_test(TEST_G_FILE_SEND, 2);

	/* The console test should work in any case. */
	run_test(TEST_CONSOLE, 0);

	run_test(TEST_THREADED_READ_WRITE, 2);

	run_test(TEST_SIGIO_HANDLER, 2);
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
	ret = host_connect_chardev(1);
	if (ret < 0) {
		/* old qemu case -- Give the guest time to finish its bootup */
		debug("%s: Old qemu?\n", __func__);
		sleep(20);
		goto next;
	}

	/* Now wait till we receive the first message from the guest. */
	pollfd[0].fd = chardevs[1].sock;
	pollfd[0].events = POLLIN;

	/* Wait for 90s max. to see if guest tries to reach us */
	ret = poll(pollfd, 1, 90000);
	if (ret == -1)
		error(errno, errno, "poll %s", chardevs[1].path);
	if (ret == 0) {
		/*
		 * This perhaps is an old kernel or an old qemu -
		 * guest won't contact us.
		 */
		debug("%s: No contact from Guest - Old kernel?\n",
		      __func__);
		goto next;
	}
	if (pollfd[0].revents & POLLIN) {
		ret = read(chardevs[1].sock, &gpkt, sizeof(gpkt));
		if (ret < sizeof(gpkt))
			error(EINVAL, EINVAL, "Read error");
		if (gpkt.key == KEY_STATUS_OK && gpkt.value) {
			guest_ok = true;
			debug("Guest is up %d\n", gpkt.value);
		} else 	if (gpkt.key == KEY_GUEST_ERR) {
			handle_guest_error(&gpkt);
			error(EINVAL, EINVAL, "Guest error");
		}
	}
next:
	/* Now we're all set to start our tests. */
	start_tests();

	/* Send guest a command to shut itself down. */
	guest_shutdown();

	show_stats();
	host_close_chardev(1);

	return nr_failed;
}
