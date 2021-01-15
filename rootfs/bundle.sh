#!/bin/sh

# Requires: tar(1), gzip(1), base64(1), find(1), sed(1), grep(1), cat(1)
#           mktemp(1), md5sum(1), tee(1)

# Environment:
#   batch=1 # batch run
#   debug=1 # copy archive output to temporary file for analysis

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

# Set program name unless already set
[ -n "${prog_name-}" ] || prog_name="${this##*/}"

# See how we're called
case "$prog_name" in
    'bundle-all.sh')
        export ${debug+debug='1'} batch='1'
        exec find "$this_dir" \
            -type l -a -executable -a -path '*/.bundle/*.sh' -a -exec {} \;
        exit 1
        ;;
    'bundle.sh')
        echo >&2 "$prog_name: shouldn't be called directly"
        exit 1
        ;;
    *.sh)
        [ -z "${this_dir##*/.bundle}" ] ||
        echo >&2 "$prog_name: must be in .bundle subdirectory"
        ;;
    *)
        echo >&2 "$prog_name: must have name format \"*.sh\""
        exit 1
        ;;
esac

# Usage: fatal <fmt> ...
fatal()
{
    local rc=$?

    local func="${FUNCNAME:-msg}"

    local fmt="${1:?missing 1st arg to ${func}() (<fmt>)}"
    shift

    printf >&2 -- "%s: $fmt" "$prog_name" "$@"

    exit $rc
}

# Usage: find_up <path> [<name>]
find_up()
{
    local func="${FUNCNAME:-find_up}"

    local path="${1:?missing 1st arg to ${func}() <path>}"
    if [ -d "$path" ]; then
        local name="${2:?missing 2d arg to ${func}() <name>}"
    else
        local name="${path##*/}"
        path="${path%/$name}"
        path="${path:-/}"
        [ -d "$path" ] || return
    fi

    local t
    while path="$(cd "$path" && echo "$PWD")"; do
        t="$path/$name"
        if [ -e "$t" ]; then
            echo "$t"
            return 0
        fi
        path="${path%/*}" && [ -d "$path" ] || break
    done

    return 1
}

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

n="${prog_name%.sh}"
# config
c="$this_dir/$n.conf" && [ -r "$c" ] || fatal 'no config file "%s"' "$c"
# output
z="$n.tgz"
b="$z.b64"
t="$(mktemp -p '' "$b.XXXXXXXX")"
# script to patch
r="$(find_up "$this_dir/rhbootstrap.sh")"

tar 2>/dev/null \
    -zcf - \
    -T "$c" \
    --exclude='.placeholder' \
    --owner='root' \
    --group='root'  | \
tee ${debug+${TMPDIR:-/tmp}/$z} | \
base64 >"$t"

# begin/end signature block
sign_begin="# md5($b) = "
sign_end="$b"

# begin/end patch block
patch_begin="$sign_begin$(md5sum "$t" | { read t _ && echo $t; })"
patch_end="$sign_end"

# patch
{
    echo "$patch_begin"
    echo "[ -d \"\$unpack_dir\" ] || install -d \"\$unpack_dir\""
    echo "base64 -d -i <<'$patch_end' | tar -zxf - -C \"\$unpack_dir\""
    cat "$t"
    echo "$patch_end"
} | \
{
    sed -i "$r" \
        -e "/^$sign_begin/,/^$sign_end$/!b" \
        -e "/^$sign_end$/!d" \
        -e 'r /dev/stdin' \
        -e "/^$sign_end$/d" \
        #
}

# report
if [ -n "${batch+x}" ]; then
    i=25
    n="$n "
else
    i=0
    n="$prog_name"
fi

if grep -q "^$patch_begin$" "$r"; then
    printf -- '%*s: patch applied successfully\n' $i "$n"
    exit 0
else
    printf -- '%*s: patch does not apply\n' $i "$n"
    [ -n "${batch+x}" ] || cat <<EOF

Help
----
Make sure that patched file has signature block or
insert lines below to appropriate place in file:

$sign_begin
$sign_end

File
----
$r

EOF
    exit 1
fi
