/*
 * auto-virtserial-guest: Exercise various options for virtio-serial ports
 *
 * This program accepts commands from the controlling program on the
 * host.  It then spawns tests on the other virtio-serial ports as per
 * the host's orders.
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
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "virtserial.h"

#define CONTROL_PORT "/dev/virtio-ports/test1"
#define CONTROL_PORT2 "/dev/vport0p1"
#define MAX_PORTS 10

/* The fd to work with for read / write requests. Set by the open message */
static int g_fd;
/* The events to poll for */
static int g_poll_events;
/* The fd to stuff in bytes for a big file receive command */
static int g_bigfile_fd;
/* The length to read / write. Set by the length message. Unset at close */
static int g_length;
/* The 'name' field in the sysfs port info */
static char g_sysfs_name[1024];
/* The thread that performs a blocking read operation */
static pthread_t g_read_thread_id;
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

static int set_poll_events(int events)
{
	return g_poll_events = events;
}

static int poll_port(int timeout)
{
	struct pollfd pollfds[1];
	int ret;

	pollfds[0].fd = g_fd;
	pollfds[0].events = g_poll_events ? : POLLIN | POLLOUT;
	ret = safepoll(pollfds, 1, timeout);
	if (ret <= 0)
		return ret;

	return pollfds[0].revents;
}

static int read_port(int nr)
{
	char *buf;
	int ret;

	if (!g_length) {
		/*
		 * Host just wants to read something. In this case, read
		 * a default length of 1024 bytes.
		 */
		g_length = 1024;
	}
	buf = malloc(g_length);
	if (!buf)
		return -ENOMEM;
	ret = saferead(g_open_fds[nr], buf, g_length, true);
	free(buf);
	return ret;
}

static int write_port(int nr)
{
	char *buf;
	int ret;

	if (!g_length)
		return 0;

	buf = malloc(g_length);
	if (!buf)
		return -ENOMEM;
	ret = safewrite(g_open_fds[nr], buf, g_length, true);
	free(buf);
	return ret;
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

static int seek_port(int nr)
{
	int ret;

	ret = lseek(g_open_fds[nr], 20, SEEK_SET);
	if (ret < 0)
		ret = -errno;

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

static int spawn_console(int val)
{
	/* Currently only works on hvc0 */
	int ret;

	ret = vfork();
	if (!ret) {
		/* Child */
		char *argv[] = { "/sbin/agetty", "/dev/hvc0", "9600", "vt100" };
		char *envp[] = { NULL };

		execve("/sbin/agetty", argv, envp);
		error(errno, errno, "execve");
	}
	return 0;
}

static int open_host_bigfile(int val)
{
	g_bigfile_fd = open(HOST_BIG_FILE, O_RDWR | O_CREAT);
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

	ret = system("sha1sum /tmp/amit/host-big-file > /tmp/amit/host-csumfile");
	if (ret == -1)
		return -errno;
	if (WIFEXITED(ret) != true)
		return -1;
	if (WEXITSTATUS(ret) != 0)
		return -WEXITSTATUS(ret);

	csum_fd = open("/tmp/amit/host-csumfile", O_RDONLY);
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

	ret = system("sha1sum /tmp/amit/guest-big-file > /tmp/amit/guest-csumfile");
	if (ret == -1)
		return -errno;
	if (WIFEXITED(ret) != true)
		return -1;
	if (WEXITSTATUS(ret) != 0)
		return -WEXITSTATUS(ret);

	csum_fd = open("/tmp/amit/guest-csumfile", O_RDONLY);
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

static int check_sysfs(int nr)
{
	char filename[1024];
	int fd, ret;

	sprintf(filename, "/sys/class/virtio-ports/vport0p%u/name", nr);
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -errno;

	ret = saferead(fd, g_sysfs_name, 1024, false);
	if (ret < 0)
		goto out_close;
	ret = 0;

out_close:
	close(fd);
	return ret;
}

static int check_udev(int nr)
{
	char filename[1024], buf[1024];
	char *str;
	int ret, i;

	str = strstr(g_sysfs_name, "\n");
	if (str)
		*str = 0;

	sprintf(filename, "/dev/virtio-ports/%s", g_sysfs_name);
	ret = readlink(filename, buf, 1024);
	if (ret < 0) {
		ret = -errno;
		goto out;
	}
	sprintf(filename, "../vport0p%u", nr);
	for (i = 0; i < ret; i++) {
		if (buf[i] != filename[i]) {
			ret = -ERANGE;
			goto out;
		}
	}
	ret = 0;
out:
	return ret;
}

static void *t_blocked_read(void *arg)
{
	int port_nr = *(int *)arg;
	int *ret;

	ret = malloc(sizeof(int));
	if (!ret)
		return NULL;

	*ret = read_port(port_nr);

	return ret;
}

static int create_read_thread(int nr)
{
	int ret;

	ret = pthread_create(&g_read_thread_id, NULL, &t_blocked_read, &nr);
	if (ret)
		return -errno;

	/* Give a chance to the thread to start and block */
	sleep(2);

	return 0;
}

static int join_read_thread(int nr)
{
	int ret;
	void *ret2;

	ret = pthread_join(g_read_thread_id, &ret2);
	if (ret)
		return ret;

	ret = *(int *)ret2;

	free(ret2);

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

static int get_sigio_result(int nr)
{
	return g_poll_results[nr];
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
	 * Just spawn a console on the default console port -
	 * /dev/hvc0.  This helps in the case of running on new
	 * kernel-old qemu combination or old kernel-new qemu
	 * combination so that the console port test can be run and
	 * the other tests will just fail.
	 */
	spawn_console(0);

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
		case KEY_READ:
			ret = read_port(gpkt.value);
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
		case KEY_WRITE:
			ret = write_port(gpkt.value);
			send_report(cfd, ret);
			break;
		case KEY_POLL_EVENTS:
			ret = set_poll_events(gpkt.value);
			send_report(cfd, ret);
			break;
		case KEY_POLL:
			ret = poll_port(gpkt.value);
			send_report(cfd, ret);
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
		case KEY_CHECK_SYSFS:
			ret = check_sysfs(gpkt.value);
			send_report(cfd, ret);
			break;
		case KEY_CHECK_UDEV:
			ret = check_udev(gpkt.value);
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
		case KEY_CREATE_READ_THREAD:
			ret = create_read_thread(gpkt.value);
			send_report(cfd, ret);
			break;
		case KEY_JOIN_READ_THREAD:
			ret = join_read_thread(gpkt.value);
			send_report(cfd, ret);
			break;
		case KEY_GET_SIGIO_RESULT:
			ret = get_sigio_result(gpkt.value);
			send_report(cfd, ret);
			break;
		case KEY_SHUTDOWN:
			system("shutdown -h now");
			break;
		case KEY_LSEEK:
			ret = seek_port(gpkt.value);
			send_report(cfd, ret);
			break;
		default:
			send_report(cfd, -ERANGE);
			break;
		}
	}
	return 0;
}
