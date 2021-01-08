#!/bin/sh

# Requires: sed(1), mv(1), ln(1)

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

export LANG=C

KERNEL_VERSION="${1:?missing KERNEL_VERSION}"
KERNEL_IMAGE="${2:?missing KERNEL_IMAGE}"

INITRD_IMAGE="${KERNEL_IMAGE%/*}/initramfs-${KERNEL_VERSION}.img"

# Usage: exit_handler
exit_handler()
{
    local rc=$?

    set +e

    [ $rc -lt 125 ] ||
        mv -f '/vmlinuz.old' '/vmlinuz' 2>/dev/null
    [ $rc -lt 126 ] ||
        mv -f '/initrd.img.old' '/initrd.img' 2>/dev/null

    return $rc
}
trap 'exit_handler' EXIT

## kernel

[ -f "$KERNEL_IMAGE" ] || exit 51

relative_path "$KERNEL_IMAGE" '/vmlinuz' t || exit 52
mv -f '/vmlinuz' '/vmlinuz.old' 2>/dev/null && rc=125 || rc=53
ln -sf "$t" '/vmlinuz' || exit $rc

## initrd

[ -f "$INITRD_IMAGE" ] || exit 61

relative_path "$INITRD_IMAGE" '/initrd.img' t || exit 62
mv -f '/initrd.img' '/initrd.img.old' 2>/dev/null && rc=126 || rc=63
ln -sf "$t" '/initrd.img' || exit $rc

exit 0
