/* Amit Shah <amit.shah@redhat.com>
 *      git://fedorapeople.org/home/fedora/amitshah/public_git/test-virtserial.git
 *
 *      Copyright (C) 2009, Red Hat, Inc.
 *
 *      Licensed under the GNU General Public License v2. See the file COPYING
 *      for more details.
 *
 * Siro Mugabi, nairobi-embedded.org
 */

#ifndef __VIRTSERIAL_DEMO_H__
#define __VIRTSERIAL_DEMO_H__

#define KEY_STATUS_OK       1
#define KEY_GUEST_ERR       2
#define KEY_OPEN        3
#define KEY_CLOSE       4
#define KEY_RESULT      5
#define KEY_NONBLOCK        7
#define KEY_LENGTH      8
#define KEY_OPEN_HOST_BIGFILE   11
#define KEY_HOST_BYTESTREAM 12
#define KEY_HOST_CSUM       13
#define KEY_OPEN_GUEST_BIGFILE  16
#define KEY_GUEST_BYTESTREAM    17
#define KEY_GUEST_CSUM      18
#define KEY_POLL_EVENTS     22
#define KEY_SHUTDOWN        23

#define HOST_BIG_FILE "/tmp/virtserial/host-big-file"
#define GUEST_BIG_FILE "/tmp/virtserial/guest-big-file"

struct guest_packet {
    unsigned int key;
    int value;
};

#endif /* __VIRTSERIAL_DEMO_H__ */
