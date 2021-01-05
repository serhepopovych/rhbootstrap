#!/bin/sh

# Requires: tar(1), gzip(1), base64(1), find(1), sed(1), cat(1)
#           mktemp(1), md5sum(1)

# Set option(s)
set -e
set -u
#set -x

this_prog='bundle.sh'

if [ ! -e "$0" -o "$0" -ef "/proc/$$/exe" ]; then
    # Executed script is
    #  a) read from stdin through pipe
    #  b) specified via -c option
    #  d) sourced
    this="$this_prog"
    this_dir='./'
else
    # Executed script exists and it's inode differs
    # from process exe symlink (Linux specific)
    this="$0"
    this_dir="${this%/*}/"
fi
this_dir="$(cd "$this_dir" && echo "$PWD")"

################################################################################

cd "$this_dir"

exit_handler()
{
    local rc=$?

    # Do not interrupt exit handler
    set +e

    [ -z "${t-}" ] || rm -f "$t" ||:

    cd - >/dev/null ||:

    return $rc
}
trap 'exit_handler' EXIT

p="${this##*/}" && p="${p%.sh}.tgz.base64"
t="$(mktemp -p '' "$p.XXXXXXXX")"

find -type d -a ! \( -name '.' -o -name '..' \) | tar -zcf - -T - | base64 >"$t"

{
    echo "# md5($p) = $(md5sum "$t" | { read t _ && echo $t; })"
    echo "base64 -d -i <<'$p' | tar -zxf /dev/stdin -C \"\$rpm_gpg_dir\""
    cat "$t"
    echo "$p"
} | \
{
    sed -i '../rhbootstrap.sh' \
        -e "/^# md5($p) =/,/^$p$/!b" \
        -e "/^$p$/!d" \
        -e 'r /dev/stdin' \
        -e "/^$p$/d" \
        #
}

exit 0
