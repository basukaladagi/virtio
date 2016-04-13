#define KEY_STATUS_OK		1
#define KEY_GUEST_ERR		2
#define KEY_OPEN		3
#define KEY_CLOSE		4
#define KEY_RESULT		5
#define KEY_READ		6
#define KEY_NONBLOCK		7
#define KEY_LENGTH		8
#define KEY_WRITE		9
#define KEY_POLL		10
#define KEY_OPEN_HOST_BIGFILE	11
#define KEY_HOST_BYTESTREAM	12
#define KEY_HOST_CSUM		13
#define KEY_CHECK_SYSFS		14
#define KEY_CHECK_UDEV		15
#define KEY_OPEN_GUEST_BIGFILE	16
#define KEY_GUEST_BYTESTREAM	17
#define KEY_GUEST_CSUM		18
#define KEY_CREATE_READ_THREAD	19
#define KEY_JOIN_READ_THREAD	20
#define KEY_GET_SIGIO_RESULT	21
#define KEY_POLL_EVENTS		22
#define KEY_SHUTDOWN		23
#define KEY_LSEEK		24

#define HOST_BIG_FILE "/tmp/amit/host-big-file"
#define GUEST_BIG_FILE "/tmp/amit/guest-big-file"

struct guest_packet {
	unsigned int key;
	int value;
};
