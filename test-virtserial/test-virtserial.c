/*
 * test-virtserial: Exercise various options for virtio-serial ports
 *
 * This program itself isn't resistant to user errors so handle with care!
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

/*
 * Invocation on the host:
 *  $ qemu ... -device virtio-serial-pci                \
 *    -chardev socket,host=localhost,port=1234,id=1234  \
 *    -chardev socket,host=localhost,port=1235,id=1235  \
 *    -device virtserialport,chardev=1234,name=port1234 \
 *    -device virtserialport,chardev=1235,name=port1235,cache_buffers=0
 *
 * Verify on the guest:
 *  $ ls /dev/vcon*
 * 'name' properties of ports:
 *  $ cat /sys/class/virtio-console/ * /name <without spaces>
 *
 *
 * Playing around:
 * On the host:
 * Writing to the guest via 'nc':
 *  $ nc localhost 1234 (uses stdin)
 *  $ nc localhost 1234 < /path/to/some/file
 * Reading from the guest:
 *  $ nc localhost 1234 (uses stdout)
 *  $ nc localhost 1234 > /path/to/some/file
 *
 * Running this program in the guest:
 *  $ ./test-virtserial /dev/vcon1
 *
 *
 * This program can be used to test quite a few paths in the guest as
 * well as the host implementations. Each of the tests mentioned below
 * is a standalone test and can be executed independently of any other
 * test.
 *
 * 1. Open
 *
 *   a. Without connecting the host chardev (nc), run this program on the
 *      guest with a port, eg,
 *       $ ./test-virtserial /dev/vcon1
 *      opening should succeed. Any other action should instantly return
 *      to the prompt as the host is not connected.
 *
 *   b. Connect the host chardev, eg,
 *       $ nc localhost 1234
 *      opening the port in the guest should succeed.
 *
 *
 * 2. Poll
 *
 *   a. Without connecting the host chardev, run the program and
 *      select (p)oll. It should return instantly.
 *
 *   b. Connect the host chardev, run the program and select
 *      (p)oll. It should wait indefinitely till some input is given
 *      on the host.
 *
 *   c. An asterisk (*) is shown next to read or write if the port can
 *      be read from or written to without blocking. Try this by
 *      writing something to the host chardev.
 *
 *
 * 3. Read
 *
 *   a. Select (r)ead without having entered anything from the
 *      host. It should wait till it receives input. When something is
 *      entered on the host, it should be displayed here. It should
 *      exit back at the prompt only when the host closes down the
 *      connection (EOF).
 *
 *   b. Select non(b)locking. Then select (r)ead. If there's nothing
 *      to be read, return back to the prompt. If there is something,
 *      display it and go back to the prompt.
 *
 *   c. Caching / not caching of buffers: initialise a port on the
 *      host with the ,cache_buffers=0 option (default is
 *      enabled). Open the port on the guest, open the chardev on the
 *      host. Write something to the port from the host. On the guest,
 *      select (o)pen. (r)ead should be marked with a * indicating
 *      data is available to be read. (c)lose the port. (o)pen it
 *      again. There should be no * against (r)ead.
 *
 *      Repeat the same with a port started with the default value of
 *      cache_buffers=1. After re-opening the port on the guest, the
 *      data should still be available for (r)eading.
 *
 *   d. Guest Throttling: Pass on ,guest_throttle=1048600 (or any
 *      value greater than 1MB) to a serial port on its qemu command
 *      line. This should be higher than 1MB, that's the minimum
 *      number of bytes allowed.
 *
 *      For a port without throttling: (o)pen the port in the guest,
 *      from the host, pass on a file > 1MB, eg via:
 *       $ nc localhost 1234 < /path/to/big/file
 *      The nc process should return as soon as the contents are
 *      transferred over to the guest.
 *
 *      Now repeat the same process for a port with throttling enabled
 *      as described before. The nc process will not return
 *      immediately but wait for the guest to read some bytes and as
 *      room becomes available in the guest, the remaining data is
 *      sent out.
 *
 *      The memory consumption in the guest can also be observed: for
 *      a port with no throttling, the guest memory consumption will
 *      increase as data is pumped in. For a port with throttling
 *      enabled, the amount of free memory will stabilise once the
 *      limit is reached (assuming there's nothing else happening in
 *      the guest).
 *
 *   e. Host Throttling: Similar to the guest throttling test above,
 *      test by pumping a big file from the guest to the host. For a
 *      port with throttling on, the guest process should wait till
 *      the host consumes the data. For a port with throttling off,
 *      the guest process should finish the write request as soon as
 *      all the data is transferred.
 *
 *
 * 4. Write
 *
 *   a. For a port that has caching enabled (,cache_buffers=1), writes
 *      to the port when host is disconnected should be available when
 *      the host chardev is connected.
 *
 *   b. For a port that has caching disabled (,cache_buffers=0),
 *      writes to the port when host is disconnected should not be
 *      available when the host connects.
 */

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef DEBUG
#define debug(fmt, ...) 			\
	do {					\
		printf(fmt, __VA_ARGS__);	\
	} while(0)
#else
#define debug(fmt, ...) do { } while (0)
#endif

/* Vars used for poll() status */
bool can_read;
bool can_write;

/* Vars used for file permissions */
bool read_ok;
bool write_ok;
bool is_blocking = true;

int read_all(int fd)
{
	int ret;
	char buf[4097];

	while ((ret = read(fd, buf, sizeof(buf) - 1)) > 0) {
		buf[ret] = 0;
		printf("%s", buf);
	}
	return ret;
}

int write_line(int fd)
{
	char *buf;
	size_t size;
	int ret;

	printf("write> ");
	buf = NULL;
	ret = getline(&buf, &size, stdin);
	if (ret == -1)
		return ret;
	ret = write(fd, buf, size);
	free(buf);
	return ret;
}

int present_menu(char *name)
{
	struct pollfd fds[1];
	long flags;
	int  fd, c, ret, timeout;
	bool closed = true;

start:
	while (closed) {
		printf("(o)pen port, (q)uit\n> ");
		c = getchar();
		getchar(); /* Forget the 'Enter' */
		if (c == 'o') {
			int mode;

			mode = O_RDWR;
			if (!write_ok)
				mode = O_RDONLY;
			fd = open(name, mode);
			if (fd == -1)
				error(errno, errno, "open %s", name);
			closed = false;
		} else if (c == 'q') {
			return 0;
		}
	}
	is_blocking = false;
	/* File is opened. */
	fds[0].fd = fd;
	fds[0].events = POLLIN|POLLOUT;

	/* By default, make poll only query for current status */
	timeout = 0;
	while (1) {
		can_read = can_write = false;

		/* Check if port is open to read/write */
		ret = poll(fds, 1, timeout);
		timeout = 0;
		debug("poll ret %d, events %u revents %u\n",
		      ret, fds[0].events, fds[0].revents);
		if (ret == -1) {
			close(fd);
			error(errno, errno, "poll %s\n", name);
		}
		if (fds[0].revents & POLLIN)
			can_read = true;
		if (fds[0].revents & POLLOUT)
			can_write = true;
		printf("%c(r)ead, %c(w)rite, %s(b)locking, (c)lose, (p)oll, (q)uit\n> ",
		       can_read ? '*' : ' ', can_write ? '*' : ' ',
		       is_blocking ? "non" : "");
		c = getchar();
		getchar(); /* Forget the 'Enter' */
		switch (c) {
		case 'p':
			timeout = -1;
			continue;
			break;
		case 'q':
			goto out;
			break;
		case 'c':
			closed = true;
			goto out;
			break;
		case 'b':
			flags = fcntl(fd, F_GETFL);
			if (flags < 0)
				perror("ERR: fcntl getfl");

			if (!is_blocking)
				flags &= ~O_NONBLOCK;
			else
				flags |= O_NONBLOCK;
			ret = fcntl(fd, F_SETFL, flags);
			if (!ret)
				is_blocking = !is_blocking;
			else
				perror("ERR fcntl");
			break;
		case 'r':
			ret = read_all(fd);
			if (ret == -1)
				perror("ERR: read");
			break;
		case 'w':
			ret = write_line(fd);
			if (ret == -1)
				perror("ERR: write");
			break;
		}
	}
out:
	close(fd);
	if (closed)
		goto start;
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 2) {
		errno = EINVAL;
		printf("Usage: %s /path/to/virtioserial/port\n", argv[0]);
		error(errno, errno, NULL);
	}
	ret = access(argv[1], F_OK);
	if (ret) {
		error(errno, errno, "%s", argv[1]);
	}
	ret = access(argv[1], R_OK);
	if (!ret)
		read_ok = true;
	ret = access(argv[1], W_OK);
	if (!ret)
		write_ok = true;
	ret = access(argv[1], X_OK);
	if (!ret)
		fprintf(stderr, "WARN: Port %s executable\n", argv[1]);

	if (!read_ok)
		error(EACCES, EACCES, "%s", argv[1]);

	present_menu(argv[1]);

	return 0;
}
