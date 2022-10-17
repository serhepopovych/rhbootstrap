#!/bin/sh

# Requires: sed(1), mv(1), rm(1), ln(1)

# Usage: return_var() <rc> <result> [<var>]
return_var()
{
	local func="${FUNCNAME:-return_var}"

	local rv_rc="${1:?missing 1st arg to ${func}() (<rc>)}"
	local rv_result="${2-}"
	local rv_var="${3-}"

	if [ -n "${rv_var}" ]; then
		eval "${rv_var}='${rv_result}'"
	else
		echo "${rv_result}"
	fi

	return ${rv_rc}
}

# Usage: normalize_path() <path> [<var_result>]
normalize_path()
{
	local func="${FUNCNAME:-normalize_path}"

	local path="${1:?missing 1st arg to ${func}() (<path>)}"
	local file=''

	if [ ! -d "${path}" ]; then
		file="${path##*/}"
		[ -n "$file" ] || return
		path="${path%/*}/"
		[ -d "$path" ] || return
	fi

	cd "${path}" &&
		path="${PWD%/}/${file}" &&
	cd - >/dev/null

	return_var $? "$path" "${2-}"
}

# Usage: relative_path <src> <dst> [<var_result>]
relative_path()
{
	local func="${FUNCNAME:-relative_path}"

	local rp_src="${1:?missing 1st arg to ${func}() (<src>)}"
	local rp_dst="${2:?missing 2d arg to ${func}() (<dst>)}"

	# add last component from src if dst ends with '/'
	[ -n "${rp_dst##*/}" ] || rp_dst="${rp_dst}${rp_src##*/}"

	# normalize pathes first
	normalize_path "${rp_src}" rp_src || return
	normalize_path "${rp_dst}" rp_dst || return

	# strip leading and add trailing '/'
	rp_src="${rp_src#/}/"
	rp_dst="${rp_dst#/}/"

	while :; do
		[ "${rp_src%%/*}" = "${rp_dst%%/*}" ] || break

		rp_src="${rp_src#*/}" && [ -n "${rp_src}" ] || return
		rp_dst="${rp_dst#*/}" && [ -n "${rp_dst}" ] || return
	done

	# strip trailing '/'
	rp_dst="${rp_dst%/}"
	rp_src="${rp_src%/}"

	# add leading '/' for dst only: for src we will add with sed(1) ../
	rp_dst="/${rp_dst}"

	# add leading '/' to dst, replace (/[^/])+ with ../
	rp_dst="$(echo "${rp_dst%/*}" | \
		  sed -e 's|\(/[^/]\+\)|../|g')${rp_src}" || \
		return

	return_var 0 "${rp_dst}" "${3-}"
}

################################################################################

# Usage: exit_handler
exit_handler()
{
    local rc=$?

    set +e

    if [ $rc -ne 0 ]; then
        if [ -n "$has_vmlinuz_old" ]; then
            mv -f '/vmlinuz.old' '/vmlinuz' 2>/dev/null
        fi
        if [ -n "$has_initrd_old" ]; then
            mv -f '/initrd.img.old' '/initrd.img' 2>/dev/null
        fi
    fi

    return $rc
}
trap 'exit_handler' EXIT

# Usage: symlink <src> <dst> [<rc_base>]
symlink()
{
    local func="${FUNCNAME:-symlink}"

    local src="${1:?missing 1st arg to ${func}() <src>}"
    local dst="${2:?missing 2d arg to ${func}() <dst>}"
    local rc_base="${3:-0}"

    [ -f "$src" ] ||
        return $((rc_base + 1))

    local has_old=''
    local old="$dst.old"
    local t

    # Backup current symlink if exists
    if mv -f "$dst" "$old" 2>/dev/null; then
        has_old='1'
    fi

    # Prepare and create relative symlink from $src to $dst not using
    # ln(1) -r option as it might not be available old systems.
    relative_path "$src" "$dst" t ||
        return $((rc_base + 2))
    ln -sf "$t" "$dst" ||
        return $((rc_base + 3))

    # Remove backup symlink if it points to same $src
    if [ -e "$dst" -a "$dst" -ef "$old" ]; then
        rm -f "$old" ||:
        has_old=''
    fi

    eval "has_${dst#/}_old='$has_old'"
}
has_vmlinuz_old=''
has_initrd_old=''

export LANG=C

KERNEL_VERSION="${1:?missing KERNEL_VERSION}"
KERNEL_IMAGE="${2:?missing KERNEL_IMAGE}"

KERNEL_IMAGE_DIR="${KERNEL_IMAGE%/*}"

for INITRD_IMAGE in \
    'initramfs' \
    'initrd' \
    '' \
    #
do
    [ -n "$INITRD_IMAGE" ] || exit

    INITRD_IMAGE="${KERNEL_IMAGE_DIR}/${INITRD_IMAGE}-${KERNEL_VERSION}.img"
    [ -f "$INITRD_IMAGE" ] || continue

    break
done

# kernel
symlink "$KERNEL_IMAGE" '/vmlinuz' 50 || exit
# initrd
symlink "$INITRD_IMAGE" '/initrd' 60 || exit

exit 0
