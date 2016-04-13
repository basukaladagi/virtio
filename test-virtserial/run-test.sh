#!/bin/bash

QEMU_DEF=/home/amit/build/qemu/x86_64-softmmu/qemu-system-x86_64
QEMU_OLD_DEF=/home/amit/build/qemu-0.12/x86_64-softmmu/qemu-system-x86_64
KERNEL_DEF=/home/amit/src/linux/arch/x86/boot/bzImage
VCPUS_DEF=2
GUEST_DEF=/guests/f11-auto.qcow2

QEMU=${QEMU:-$QEMU_DEF}
QEMU_OLD=${QEMU_OLD:-$QEMU_OLD_DEF}
KERNEL=${KERNEL:-$KERNEL_DEF}
VCPUS=${VCPUS:-$VCPUS_DEF}
GUEST=${GUEST:-$GUEST_DEF}

KERNEL="-kernel $KERNEL"
#KERNELARG="-append \"root=/dev/sda2 console=tty0 console=ttyS0\""
KERNELARG="-append root=/dev/vda2"

CHARDEVS="-chardev socket,path=/tmp/amit/test0,server,nowait,id=test0 \
          -chardev socket,path=/tmp/amit/test1,server,nowait,id=test1 \
          -chardev socket,path=/tmp/amit/test2,server,nowait,id=test2 \
          -chardev socket,path=/tmp/amit/test3,server,nowait,id=test3 \
          -chardev socket,path=/tmp/amit/test4,server,nowait,id=test4"
VIRTSER="-device virtio-serial \
         -device virtconsole,chardev=test0,name=console.0 \
         -device virtserialport,chardev=test1,name=test1 \
         -device virtserialport,chardev=test2,name=test2 \
         -device virtserialport,chardev=test3,name=test3 \
         -device virtserialport,chardev=test4,name=test4"
VNC="-vnc :1"
MISCOPT="-net none -enable-kvm -m 1G -serial file:/tmp/amit/test-serial.log \
         -monitor unix:/tmp/amit/test-monitor,server,nowait"
KVMOPT="-smp $VCPUS"
SNAPSHOT="-snapshot"
DRIVE="-drive file=$GUEST,if=none,id=guest,cache=unsafe \
       -device virtio-blk-pci,drive=guest"

QEMU_PIDFILE=/tmp/amit/qemu.pid

function kill_qemu {

    if [ -s $QEMU_PIDFILE ]; then
	# If file exists and has size greater than zero
	declare -i qemu_pid

	qemu_pid=`cat $QEMU_PIDFILE`
	rm $QEMU_PIDFILE
	kill -9 $qemu_pid
	qemu_pid=
    fi
}

function do_test {
    declare -i qemu_pid

    pkill -9 auto-virtserial
    kill_qemu

    # Let prev. instance of qemu be killed, if any.  Without this
    # sleep, the prev. qemu / auto-virtserial instance could be killed
    # after we start our next test, which is a bad thing.
    sleep 5;

    echo $QEMU $QEMU_OPTS
    $QEMU $QEMU_OPTS &
    qemu_pid=$!
    echo $qemu_pid > $QEMU_PIDFILE
    qemu_pid=

    # Give some time for the guest to come up
    sleep 5

    > /tmp/amit/guest-big-file
    > /tmp/amit/guest-csumfile
    time ./auto-virtserial

    kill_qemu
}

# -- Iteration 1: new kernel, new qemu --
QEMU_OPTS="$DRIVE $KERNEL $KERNELARG $CHARDEVS $VIRTSER $VNC $MISCOPT \
           $SNAPSHOT $KVMOPT"

do_test

# -- Iteration 2: old kernel, new qemu --

QEMU_OPTS="$DRIVE $CHARDEVS $VIRTSER $VNC $MISCOPT $SNAPSHOT $KVMOPT"

do_test

# -- Iteration 3: new kernel, old qemu --

CHARDEVS=
VIRTSER="-virtioconsole unix:/tmp/amit/test0,server,nowait"

QEMU_OPTS="$DRIVE $KERNEL $KERNELARG $CHARDEVS $VIRTSER $VNC $MISCOPT $SNAPSHOT"

do_test
