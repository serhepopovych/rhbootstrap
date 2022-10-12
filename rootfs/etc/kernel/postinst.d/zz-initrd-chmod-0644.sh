#!/bin/sh

export LANG=C

KERNEL_VERSION="${1:?missing KERNEL_VERSION}"
KERNEL_IMAGE="${2:?missing KERNEL_IMAGE}"

KERNEL_IMAGE_DIR="${KERNEL_IMAGE%/*}"

for INITRD_IMAGE in \
    'initramfs' \
    'initrd' \
    #
do
    INITRD_IMAGE="${KERNEL_IMAGE_DIR}/${INITRD_IMAGE}-${KERNEL_VERSION}.img"
    if [ -f "$INITRD_IMAGE" ]; then
        chmod 0644 "$INITRD_IMAGE"
        break
    fi
done
