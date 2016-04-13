CFLAGS=-Wall -g
LDFLAGS=-lpthread

all: test-virtserial auto-virtserial auto-virtserial-guest

clean:
	-rm -f test-virtserial auto-virtserial auto-virtserial-guest *.plist

.PHONY: all clean

test-virtserial:

auto-virtserial: virtserial.h

auto-virtserial-guest: virtserial.h
