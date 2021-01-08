#!/bin/sh

export LANG=C

KERNEL_VERSION="${1:?missing KERNEL_VERSION}"

  if t='/vmlinuz' && [ -L "$t" ] && t="$(readlink "$t")" &&
    [ -z "${t##*/vmlinuz-$KERNEL_VERSION}" ]
then
    rm -f '/vmlinuz' '/initrd.img' ||:

    mv -f '/vmlinuz.old' '/vmlinuz' 2>/dev/null ||:
    mv -f '/initrd.img.old' '/initrd.img' 2>/dev/null ||:
elif t='/vmlinuz.old' && [ -L "$t" ] && t="$(readlink "$t")" &&
    [ -z "${t##*/vmlinuz-$KERNEL_VERSION}" ]
then
    rm -f '/vmlinuz.old' '/initrd.img.old' ||:
fi

exit 0
