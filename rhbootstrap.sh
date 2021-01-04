#!/bin/sh

# MIT License
#
# Copyright (c) 2020 Serhey Popovych <serhe.popovych@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Requires: mountpoint(1), chroot(1), find(1), xargs(1), install(1), dd(1),
#           sed(1), mv(1), rm(1), ln(1), cat(1), rpm(1), yum(1), curl(1), id(1),
#           uname(1), mount(8), umount(8), setarch(8), chmod(1)

# Set option(s)
set -e
set -u
#set -x

this_prog='rhbootstrap.sh'

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
prog_version='1.0'

# Verbosity: report errors by default
[ -n "${V-}" ] && [ "$V" -le 0 -o "$V" -ge 0 ] 2>/dev/null || V=1

# Normalize umask(1)
umask 0022

## Global helpers and steps

true()  {   :; }
false() { ! :; }

# Usage: msg <fmt> ...
msg()
{
    local rc=$?

    local func="${FUNCNAME:-msg}"

    local fmt="${1:?missing 1st arg to ${func}() (<fmt>)}"
    shift

    [ $V -le 0 ] || printf -- "$fmt" "$@"

    return $rc
}

# Usage: info <fmt> ...
info()
{
    msg "$@"
}

# Usage: error <fmt> ...
error()
{
    msg "$@" >&2
}

# Usage: error_exit
error_exit()
{
    error "$@" || exit
}

# Usage: fatal <fmt> ...
fatal()
{
    local rc=$?
    printf >&2 -- '%s: ' "$prog_name"
    error "$@"
    exit $rc
}

# Usage: abort <fmt> ...
abort()
{
    local rc=$?
    trap - EXIT
    V=1 error "$@"
    exit $rc
}

# Usage: _exit [<rc>]
_exit()
{
    local _rc=$?
    trap - EXIT
    local rc="${1:-${_rc}}"
    [ "$rc" -ge 0 -o "$rc" -lt 0 ] 2>/dev/null || rc=${_rc}
    exit $rc
}

# Usage: pkg_name <pkg_name>
pkg_name()
{
    local func="${func:-${FUNCNAME:-pkg_name}}"

    local pkg_name="${1:?missing 1st arg to ${func}() <pkg_name>}"

    pkg_name="${pkg_name#pkg_}"
    [ -n "$pkg_name" ] || return
    pkg_name="pkg_$pkg_name"

    echo "pkg_name='$pkg_name'"
}

# Usage: pkg_val <pkg_name>
pkg_val()
{
    local func="${func:-${FUNCNAME:-pkg_val}}"

    local pkg_name
    eval "$(pkg_name "${1-}")" || return

    eval "local pkg_val=\"\${$pkg_name-}\""

    echo "$pkg_val"
}

# Usage: pkg_switch <pkg_name> [<0|1>]
pkg_switch()
{
    local pkg_name
    eval "$(pkg_name "${1-}")" || return
    local on_off="${2-}"

    eval "local pkg_val=\"\${$pkg_name-}\""

    case "$on_off" in
       '') on_off="$pkg_val" ;;
       0)  on_off='' ;;
       *)  on_off=1 ;;
    esac

    eval "
        [ '$pkg_val' -eq 0 ] 2>/dev/null &&
            $pkg_name='' || $pkg_name='$on_off'
    "
}

# Usage: pkg_enable <pkg_name>
pkg_enable()
{
    local func="${FUNCNAME:-pkg_enable}"
    pkg_switch "${1-}" 1
}

# Usage: pkg_disable <pkg_name>
pkg_disable()
{
    local func="${FUNCNAME:-pkg_disable}"
    pkg_switch "${1-}" 0
}

# Usage: pkg_is_installed <pkg_name>
pkg_is_installed()
{
    local func="${FUNCNAME:-pkg_is_installed}"

    local pkg_name="${1:?missing 1st arg to ${func}() <pkg_name>}"
    pkg_name="${pkg_name#pkg_}"

    rpm -q "$pkg_name" >/dev/null 2>&1 || return
}

# Usage: _in_chroot <dir> <cmd> [<arg> ...]
_in_chroot()
{
    local func="${func:-${FUNCNAME:-_in_chroot}}"

    local dir="${1:?missing 1st arg to ${func}() <dir>}" && shift
    [ $# -gt 0 ] || return

    local _in_chroot_exec="${_in_chroot_exec-}"
    [ -z  "${_in_chroot_exec}" ] || _in_chroot_exec='exec'

    ${_in_chroot_exec} setarch "$basearch" \
        chroot "$dir" /bin/sh -c "$@" ||
    return
}

# Usage: in_chroot <dir> <cmd> [<arg> ...]
in_chroot()
{
    local func="${FUNCNAME:-in_chroot}"
    local _in_chroot_exec=''
    _in_chroot "$@" || return
}

# Usage: in_chroot_exec <dir> <cmd> [<arg> ...]
in_chroot_exec()
{
    local func="${FUNCNAME:-in_chroot_exec}"
    local _in_chroot_exec='1'
    _in_chroot "$@" || return
}

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

# Usage: version_cmp <v1> <v2> [<var_result>]
version_cmp()
{
    local func="${FUNCNAME:-version_cmp}"

    local v1="${1:?missing 1st arg to ${func}() <v1>}"
    local v2="${2:?missing 2d arg to ${func}() <v2>}"

    # Test cases:
    # -----------
    # version_cmp 5 5.0 -> 0
    # version_cmp 5.10 5.a -> 1
    # version_cmp 5a 5.0 -> -1
    # version_cmp 5.0a 5.0 -> -1
    # version_cmp 5alpha1 5.0 -> -1
    # version_cmp 5beta1 5.0alpha1 -> 1
    # version_cmp 5rc1 5-rc1 -> 0
    # version_cmp 5.0-rc1 5.0rc1 -> 0
    # version_cmp 5.0rc1 5beta1 -> 1
    # version_cmp 5.0rc1 5.0 -> -1
    # version_cmp 5.01 5.1 -> -1
    # version_cmp 4.99 5.0 -> -1
    # version_cmp 5.10 30 -> -1
    # version_cmp 5.a.b.c 5.a.b.c -> 0
    # version_cmp 5.a.b.c 5.a.b.d -> -1
    # version_cmp a.b.c d.e.f -> -1
    #
    # Uncomment to make output like above:
    # ------------------------------------
    #echo -n "${func} $v1 $v2 -> "

    # Only supported characters
    [ -n "${v1##*[^[:alnum:].-]*}" ] || return
    [ -n "${v2##*[^[:alnum:].-]*}" ] || return

    # Translate '-' to '.'; make sure there is no empty subversion (..)
    v1="$(echo "$v1" | sed 'y/-/./')" &&
    v1=".$v1." && [ -n "${v1##*..*}" ] && v1="${v1#.}" && v1="${v1%.}" || return
    v2="$(echo "$v2" | sed 'y/-/./')" &&
    v2=".$v2." && [ -n "${v2##*..*}" ] && v2="${v2#.}" && v2="${v2%.}" || return

    # Strip release type (i.e. a, alpha1, b, beta2, rc5, etc); end with '.'
    local p1 p2 t

    p1="${v1##*.}" && while :
    do
        t="${p1#[[:digit:]]}" && [ "$t" != "$p1" ] && p1="$t" || break
    done
    v1="${v1%$p1}" && v1="${v1%.}" && v1="$v1."

    p2="${v2##*.}" && while :
    do
        t="${p2#[[:digit:]]}" && [ "$t" != "$p2" ] && p2="$t" || break
    done
    v2="${v2%$p2}" && v2="${v2%.}" && v2="$v2."

    # Pad with '0.' to make version length equal
    local c1 c2

    c1=$(IFS='.' && set -- $v1 && echo $#)
    c2=$(IFS='.' && set -- $v2 && echo $#)

    t=$((c1 - c2))
    while [ $t -ne 0 ]; do
        if [ $t -lt 0 ]; then
            v1="${v1}0."
            : $((t += 1))
        else
            v2="${v2}0."
            : $((t -= 1))
        fi
    done

    # Append release type creating one if missing using 'z'
      if [ -z "$p1" ]; then
        t=${#p2}
        while [ $((t -= 1)) -ge 0 ]; do
            p1="${p1}z"
        done
    elif [ -z "$p2" ]; then
        t=${#p1}
        while [ $((t -= 1)) -ge 0 ]; do
            p2="${p2}z"
        done
    fi
    v1="${v1}${p1:+$p1.}"
    v2="${v2}${p2:+$p2.}"

    # For each subversion: compare
    while :; do
        c1="${v1%%.*}" && v1="${v1#$c1.}"
        c2="${v2%%.*}" && v2="${v2#$c2.}"

        [ "$c1" = "$c2" ] || break

        if [ -z "$v1" ]; then
            return_var 0 '0' "${3-}" && return
        fi
    done

    # Force lexicographical comparison in expr(1) when value starts with '0'
    [ -n "${c1##0*}" ] || c1="$c1."
    [ -n "${c2##0*}" ] || c2="$c2."

    expr "$c1" '>' "$c2" >/dev/null && return_var $?  '1' "${3-}" && return ||:
    expr "$c1" '<' "$c2" >/dev/null && return_var $? '-1' "${3-}" && return ||:

    # Never reached
    return 3
}

is_centos() { [ "${distro-}" = 'centos' ] || return; }
is_fedora() { [ "${distro-}" = 'fedora' ] || return; }

# Usage: centos_version_cmp <v1> <v2>
centos_version_cmp()
{
    is_centos && version_cmp "${1-}" "${2-}" || return
}

centos_version_lt() { [ "$(centos_version_cmp "$@")" = '-1' ] || return; }
centos_version_eq() { [ "$(centos_version_cmp "$@")" =  '0' ] || return; }
centos_version_gt() { [ "$(centos_version_cmp "$@")" =  '1' ] || return; }

centos_version_le()
{
    centos_version_lt "$@" || centos_version_eq "$@" || return
}
centos_version_ge()
{
    centos_version_gt "$@" || centos_version_eq "$@" || return
}

centos_version_neq() { ! centos_version_eq "$@" || return; }

# Usage: fedora_version_cmp <v1> <v2>
fedora_version_cmp()
{
    is_fedora && version_cmp "${1-}" "${2-}" || return
}

fedora_version_lt() { [ "$(fedora_version_cmp "$@")" = '-1' ] || return; }
fedora_version_eq() { [ "$(fedora_version_cmp "$@")" =  '0' ] || return; }
fedora_version_gt() { [ "$(fedora_version_cmp "$@")" =  '1' ] || return; }

fedora_version_le()
{
    fedora_version_lt "$@" || fedora_version_eq "$@" || return
}
fedora_version_ge()
{
    fedora_version_gt "$@" || fedora_version_eq "$@" || return
}

fedora_version_neq() { ! fedora_version_eq "$@" || return; }

## Parse options

# Distribution to install/setup
distro='centos'
# System processor (CPU) architecture (default: running system)
arch="$(uname -m)"
# CentOS release version (default: 8)
releasever=8

# rpm(8) install options (default: all)
install_langs=''
nodocs=''

# yum(8) repo mirrorlist variable cc (country code) variable (default: none)
cc=''

# Configuration file with packages/groups definitions
config=''
# Exit after installing minimal system
minimal_install=''

# External repositories (e.g. EPEL, ELRepo and RPM Fusion)
repo_epel=1
repo_virtio_win=''
repo_advanced_virtualization=''
repo_openstack=''
repo_ovirt=''
repo_elrepo=''
repo_rpm_fusion=''

# NFS root
nfs_root=''
# SELinux
selinux=''
# Read-only root
readonly_root=''
# Passwordless root
passwordless_root=''
# Autopassword root
autopassword_root=''
# Mount /tmp as tmpfs with up to ${_tmp_mount} of system RAM in size
_tmp_mount_min=10
_tmp_mount=25
_tmp_mount_max=50
tmp_mount=${_tmp_mount}
# Serial line console
_serial_console='console=ttyS0,115200n8'
serial_console=''
# Add "zswap.enabled=1" to kernel command line option list
zswap_enabled=''
# Add "nosmt" to kernel command line option list
nosmt=''
# Update login banners
login_banners=''
# SELinux context autorelabel
autorelabel=''
# Recursive name (DNS) resolution servers
_nameservers='1.1.1.1'
nameservers=''

# KVM nesting
kvm_nested=''
# libvirt qemu user to run as
_libvirt_qemu_user='qemu'
libvirt_qemu_user=''
# libvirt UNIX socket group ownership
_libvirt_unix_group='libvirt'
libvirt_unix_group=''
# libvirt UNIX R/O socket permissions
_libvirt_unix_ro_perms='0777'
libvirt_unix_ro_perms=''
# libvirt UNIX R/W socket permissions
_libvirt_unix_rw_perms='0770'
libvirt_unix_rw_perms=''
# libvirt UNIX R/O authentication
_libvirt_unix_auth_ro='none'
libvirt_unix_auth_ro=''
# libvirt UNIX R/W authentication
_libvirt_unix_auth_rw='none'
libvirt_unix_auth_rw=''

# Force
force=''
# Build information
build_info=1

# Install packages to directory (chroot) instead of running system
install_root=''

# Usage: usage
usage()
{
    local rc=$?
    local fd

    [ $rc -eq 0 ] && fd=1 || fd=2

    cat >&$fd <<EOF
Usage: $prog_name [options] [<install_root>]
Options and their defaults:
    --distro=$distro
        Distribution to install to chroot or setup.
        Only centos and fedora supported at the moment.
    --arch=$arch
        System processor (CPU) architecture to install packages for.
        Only AMD64 (x86_64) and i386 supported at the moment
    --releasever=$releasever
        Supported CentOS release version

    --install-langs=${install_langs:-<all>}
        (rpm) install localization files for given languages (e.g. 'en:ru:uk')
    --nodocs
        (rpm) do not install documentation (i.e. one in /usr/share/doc)

    --cc=${cc:-<none>}
        (yum) country code variable for yum(8) repo mirrorlist URL
              to restrict selected mirrors to given country

    --config=${config:-<none>}
        File with packages and/or groups to install
    --minimal-install
        Short cut to install only base set of packages regardless of --config

    --no-repo-epel, --repo-epel
        Disable/enable EPEL repository and selected packages from it
    --repo-virtio-win, --no-repo-virtio-win
        Enable/disable VirtIO-Win repository and selected
        packages from it, ignored if oVirt repository enabled
    --repo-advanced-virtualization, --no-repo-advanced-virtualization
        Enable/disable Advanced Virtualization repository and senected
        packages from it, ignored if oVirt or OpenStack repository enabled
    --repo-openstack, --no-repo-openstack
        Enable/disable OpenStack repository and selected
        packages from it, ignored if oVirt repository enabled
    --repo-ovirt, --no-repo-ovirt
        Enable/disable oVirt repository and selected packages
        from it, ignored if OpenStack repository enabled
    --repo-elrepo, --no-repo-elrepo
        Enable/disable ELRepo and selected packages from it
    --repo-rpm-fusion, --no-repo-rpm-fusion
        Enable/disable RPM Fusion and selected packages from it

    --nfs-root
        Prepare bootstrapped system for use as NFS root and make initramfs
        capable of network boot (e.g. via PXE); inhibits --minimal-install,
        makes --selinux=permissive if --readonly-root is given; omits
        boot loader (e.g. grub2 and shim) packages, adds dracut-generic-config
    --selinux=${selinux:-<unmodified>}
        Configure SELinux mode in /etc/sysconfig/selinux to one of the
        following values: enforcing, permissive or disabled
    --readonly-root
        Enable read-only root filesystem support via
        /etc/sysconfig/readonly-root \$READONLY and other variables; enables
        --autopassword-root unless --passwordless-root is set
    --passwordless-root, --no-passwordless-root
        Make root user passwordless to enable login without password; remote
        logins via ssh to root will be unavailable (see PermitEmptyPasswords
        option in sshd_config(8)); option --autopassword-root overrides it
    --autopassword-root, --no-autopassword-root
        Make root user password autogenerated from /dev/urandom data
        on each system boot and shown by getty from /etc/issue on local
        (e.g. serial and/or virtual) consoles; enabled if --readonly-root
        set and --passwordless-root is unset, enables remote logins via ssh
    --no-tmp-mount, --tmp-mount=${tmp_mount:-<value>}
        Mount /tmp as regular filesystem or tmpfs with size up to
        ${tmp_mount:-<value>}% of system RAM. Valid value range is
        [${_tmp_mount_min}...${_tmp_mount_max}]
    --serial-console=${serial_console:-<console=name,options|1>}, --no-serial-console
        Enable/disable console on serial line; if value is 1 use default console
        settings (${_serial_console})
    --zswap-enabled, --no-zswap-enabled
        Add zswap.enabled=1 to kernel command line options to enable zSwap kernel
        memory management subsystem feature. This could improve overall system
        responsiveness on systems with high memory usage by delaying swap to disk;
        has no effect if grub2 is not installed (e.g. when --nfs-root is given)
    --nosmt, --no-nosmt
        Add nosmt to kernel command line options to disable SMT (Hyper-Threading)
        that could be useful for some workloads as well as help to mitigate
        certain CPU bugs (e.g. l1tf); has no effect if grub2 is not installed
        (e.g. when --nfs-root is given)
    --login-banners, --no-login-banners
        Modify/keep login banners in /etc/issue, /etc/issue.net and /etc/motd
        making them (e.g. /etc/issue) to provide host useful information
        (e.g. IPv4 and IPv6 addresses matching hostname) hiding kernel version
    --autorelabel
        Add .autorelabel to <install_root> or / if <install_root> not given
    --nameservers=${nameservers:-<value>}, --no-nameservers
        Configure or do not configure resolv.conf with specified nameserver(s)

    --kvm-nested, --no-kvm-nested
        Enable/disable KVM nested virtualization via /etc/modprobe.d/kvm.conf.
        Will require module (or system) reload to take effect.
    --libvirt-qemu-user=${libvirt_qemu_user:-<unmodified>}
        Update user and group directives in /etc/libvirt/qemu.conf with user
        name to run qemu-kvm system instance as; value is either user name or
        integer greather than or equal to zero, otherwise default
        ${_libvirt_qemu_user} is used
    --libvirt-unix-group=${libvirt_unix_group:-<unmodified>}
        Local UNIX socket group ownership. Together with --libvirt-unix-ro-perms
        and --libvirt-unix-rw-perms controls access type to libvirt sockets by
        users membered in specified group
    --libvirt-unix-ro-perms=${libvirt_unix_ro_perms:-<unmodified>}
        Local UNIX read-only socket permissions. Used together with
        --libvirt-unix-group to restrict users who can access libvirt R/O socket
    --libvirt-unix-rw-perms=${libvirt_unix_rw_perms:-<unmodified>}
        Local UNIX read-write socket permissions. Used together with
        --libvirt-unix-group to restrict users who can access libvirt R/W socket
    --libvirt-unix-auth-ro=${libvirt_unix_auth_ro:-<unmodified>}
        Set libvirt UNIX R/O socket authentication scheme to "none", "sasl"
        or "polkit" (default)
    --libvirt-unix-auth-rw=${libvirt_unix_auth_rw:-<unmodified>}
        Set libvirt UNIX R/W socket authentication scheme to "none", "sasl"
        or "polkit" (default)

    --force
        Force bootstrap and remove <install_root> if it already exists
    --no-build-info
        Do not add .rhbootstrap/ with build information to <install_root>;
        implied when no <install_root> is given

    --help, --usage
        This help/usage message
    --version
        This program version

If <install_root> is given perform chrooted installation to that directory.
Otherwise install into system we running on (default).
EOF
    return $rc
}
trap 'usage' EXIT

argv=''
while [ $# -gt 0 ]; do
    arg=''
    case "$1" in
        --distro)
            [ -n "${2-}" ] || exit
            distro="$2"
            arg="--distro '$distro'"
            shift
            ;;
        --distro=*)
            distro="${1##--distro=}"
            [ -n "$distro" ] || exit
            arg="--distro='$distro'"
            ;;
        --arch)
            [ -n "${2-}" ] || exit
            arch="$2"
            arg="--arch '$arch'"
            shift
            ;;
        --arch=*)
            arch="${1##--arch=}"
            [ -n "$arch" ] || exit
            arg="--arch='$arch'"
            ;;
        --releasever)
            [ -n "${2-}" ] || exit
            releasever="$2"
            arg="--releasever '$releasever'"
            shift
            ;;
        --releasever=*)
            releasever="${1##--releasever=}"
            [ -n "$releasever" ] || exit
            arg="--releasever='$releasever'"
            ;;

        --install-langs)
            [ -n "${2-}" ] || exit
            install_langs="$2"
            arg="--install-langs '$install_langs'"
            shift
            ;;
        --install-langs=*)
            install_langs="${1##--install-langs=}"
            [ -n "$install_langs" ] || exit
            arg="--install-langs='$install_langs'"
            ;;
        --nodocs)
            nodocs=1
            ;;

        --cc)
            [ -n "${2-}" ] || exit
            cc="$2"
            arg="--cc '$cc'"
            shift
            ;;
        --cc=*)
            cc="${1##--cc=}"
            [ -n "$cc" ] || exit
            arg="--cc='$cc'"
            ;;

        --config)
            [ -n "${2-}" ] || exit
            config="$2"
            arg=' '
            shift
            ;;
        --config=*)
            config="${1##--config=}"
            [ -n "$config" ] || exit
            arg=' '
            ;;
        --minimal-install)
            minimal_install=1
            ;;

        # EPEL
        --no-repo-epel)
            repo_epel=''
            ;;
        --repo-epel)
            repo_epel=1
            ;;
        # VirtIO-Win
        --no-repo-virtio-win)
            repo_virtio_win=''
            ;;
        --repo-virtio-win)
            repo_virtio_win=1
            ;;
        # Advanced Virtualization
        --no-repo-advanced-virtualization)
            repo_advanced_virtualization=''
            ;;
        --repo-advanced-virtualization)
            repo_advanced_virtualization=1
            ;;
        # OpenStack
        --no-repo-openstack)
            repo_openstack=''
            ;;
        --repo-openstack)
            repo_openstack=1
            ;;
        # oVirt
        --no-repo-ovirt)
            repo_ovirt=''
            ;;
        --repo-ovirt)
            repo_ovirt=1
            ;;
        # ELRepo
        --no-repo-elrepo)
            repo_elrepo=''
            ;;
        --repo-elrepo)
            repo_elrepo=1
            ;;
        # RPM Fusion
        --no-repo-rpm-fusion)
            repo_rpm_fusion=''
            ;;
        --repo-rpm-fusion)
            repo_rpm_fusion=1
            ;;

        --nfs-root)
            nfs_root=1
            ;;
        --selinux)
            [ -n "${2-}" ] || exit
            selinux="$2"
            arg="--selinux '$selinux'"
            shift
            ;;
        --selinux=*)
            selinux="${1##--selinux=}"
            [ -n "$selinux" ] || exit
            arg="--selinux='$selinux'"
            ;;
        --readonly-root)
            readonly_root=1
            ;;
        --passwordless-root)
            passwordless_root=1
            ;;
        --no-passwordless-root)
            passwordless_root=0
            ;;
        --autopassword-root)
            autopassword_root=1
            ;;
        --no-autopassword-root)
            autopassword_root=0
            ;;
        --tmp-mount)
            [ -n "${2-}" ] || exit
            tmp_mount="$2"
            arg="--tmp-mount '$tmp_mount'"
            shift
            ;;
        --tmp-mount=*)
            tmp_mount="${1##--tmp-mount=}"
            [ -n "$tmp_mount" ] || exit
            arg="--tmp-mount='$tmp_mount'"
            ;;
        --no-tmp-mount)
            tmp_mount=''
            ;;
        --serial-console)
            [ -n "${2-}" ] || exit
            serial_console="$2"
            arg="--serial-console '$serial_console'"
            shift
            ;;
        --serial-console=*)
            serial_console="${1##--serial-console=}"
            [ -n "$serial_console" ] || exit
            arg="--serial-console='$serial_console'"
            ;;
        --no-serial-console)
            serial_console=''
            ;;
        --zswap-enabled)
            zswap_enabled=1
            ;;
        --no-zswap-enabled)
            zswap_enabled=''
            ;;
        --nosmt)
            nosmt=1
            ;;
        --no-nosmt)
            nosmt=''
            ;;
        --login-banners)
            login_banners=1
            ;;
        --no-login-banners)
            login_banners=''
            ;;
        --autorelabel)
            autorelabel=1
            ;;
        --no-nameservers)
            nameservers=''
            ;;
        --nameservers)
            [ -n "${2-}" ] || exit
            nameservers="$2"
            arg="--nameservers '$nameservers'"
            shift
            ;;
        --nameservers=*)
            nameservers="${1##--nameservers=}"
            [ -n "$nameservers" ] || exit
            arg="--nameservers='$nameservers'"
            ;;

        --kvm-nested)
            kvm_nested=1
            ;;
        --no-kvm-nested)
            kvm_nested=0
            ;;
        --libvirt-qemu-user)
            [ -n "${2-}" ] || exit
            libvirt_qemu_user="$2"
            arg="--libvirt-qemu-user '$libvirt_qemu_user'"
            shift
            ;;
        --libvirt-qemu-user=*)
            libvirt_qemu_user="${1##--libvirt-qemu-user=}"
            [ -n "$libvirt_qemu_user" ] || exit
            arg="--libvirt-qemu-user='$libvirt_qemu_user'"
            ;;
        --libvirt-unix-group)
            [ -n "${2-}" ] || exit
            libvirt_unix_group="$2"
            arg="--libvirt-unix-group '$libvirt_unix_group'"
            shift
            ;;
        --libvirt-unix-group=*)
            libvirt_unix_group="${1##--libvirt-unix-group=}"
            [ -n "$libvirt_unix_group" ] || exit
            arg="--libvirt-unix-group='$libvirt_unix_group'"
            ;;
        --libvirt-unix-ro-perms)
            [ -n "${2-}" ] || exit
            libvirt_unix_ro_perms="$2"
            arg="--libvirt-unix-ro-perms '$libvirt_unix_ro_perms'"
            shift
            ;;
        --libvirt-unix-ro-perms=*)
            libvirt_unix_ro_perms="${1##--libvirt-unix-ro-perms=}"
            [ -n "$libvirt_unix_ro_perms" ] || exit
            arg="--libvirt-unix-ro-perms='$libvirt_unix_ro_perms'"
            ;;
        --libvirt-unix-rw-perms)
            [ -n "${2-}" ] || exit
            libvirt_unix_rw_perms="$2"
            arg="--libvirt-unix-rw-perms '$libvirt_unix_rw_perms'"
            shift
            ;;
        --libvirt-unix-rw-perms=*)
            libvirt_unix_rw_perms="${1##--libvirt-unix-rw-perms=}"
            [ -n "$libvirt_unix_rw_perms" ] || exit
            arg="--libvirt-unix-rw-perms='$libvirt_unix_rw_perms'"
            ;;
        --libvirt-unix-auth-ro)
            [ -n "${2-}" ] || exit
            libvirt_unix_auth_ro="$2"
            arg="--libvirt-unix-auth-ro '$libvirt_unix_auth_ro'"
            shift
            ;;
        --libvirt-unix-auth-ro=*)
            libvirt_unix_auth_ro="${1##--libvirt-unix-auth-ro=}"
            [ -n "$libvirt_unix_auth_ro" ] || exit
            arg="--libvirt-unix-auth-ro='$libvirt_unix_auth_ro'"
            ;;
        --libvirt-unix-auth-rw)
            [ -n "${2-}" ] || exit
            libvirt_unix_auth_rw="$2"
            arg="--libvirt-unix-auth-rw '$libvirt_unix_auth_rw'"
            shift
            ;;
        --libvirt-unix-auth-rw=*)
            libvirt_unix_auth_rw="${1##--libvirt-unix-auth-rw=}"
            [ -n "$libvirt_unix_auth_rw" ] || exit
            arg="--libvirt-unix-auth-rw='$libvirt_unix_auth_rw'"
            ;;

        --force)
            force=1
            ;;
        --no-build-info)
            build_info=''
            ;;

        --help|--usage)
            exit
            ;;
        --version)
            echo "$prog_name $prog_version"
            _exit 0
            ;;

        # errors
        --*)
            printf >&2 -- '%s: unknown option: %s\n' "$prog_name" "$1"
            _exit 1
            ;;
        *)
            break
            ;;
    esac
    [ -n "$arg" ] || arg="$1"
    [ -z "${arg% }" ] || argv="${argv:+$argv }$arg"
    shift
done

# Handle <install_root> if given
[ $# -eq 1 ] && [ -n "$1" ] && install_root="$1" && shift || [ $# -lt 1 ] || exit

# Finish argument parsing
trap - EXIT

# Must be started by root (uid 0)
[ "$(id -u)" = 0 ] || fatal 'Only root (uid 0) can use this service\n'

# $distro
case "$distro" in
    centos) ;;
    fedora) ;;
    *)      fatal 'Unsupported distribution "%s"\n' "$distro" ;;
esac

# $arch, $basearch
case "$arch" in
    x86_64) basearch='x86_64' ;;
    i?86)   basearch='i386'   ;;
    *)      fatal 'Unsupported architecture "%s"\n' "$arch" ;;
esac

# $selinux
case "$selinux" in
    enforcing|permissive|disabled|'') ;;
    *) fatal 'Unknown SELinux mode "%s"\n' "$selinux" ;;
esac

# $cc handled after release package(s) installation

# $config
if [ -n "$config" ]; then
    if [ -z "${config##*://*}" ]; then
        url="$config"
        config="$this_dir/${config##*/}"
        curl -s -o "$config" "$url" ||
            fatal 'unable to fetch "%s" config\n' "$url"
        unset url
    fi
    if [ -f "$config" ]; then
        . "$config" || fatal 'unable to include "%s" config\n' "$config"
    else
        fatal 'canot find "%s" config\n' "$config"
    fi
else
    minimal_install=1
fi

# reset internal variables
has_de=''
has_dm=''
gtk_based_de=''

# $install_root
if [ -n "$install_root" ]; then
    if [ -e "$install_root" ]; then
        if [ -n "$force" ]; then
            info 'Cleanup existing install root "%s" ...\n' "$install_root"
            rm -rf "$install_root" ||
                fatal 'failed to remove existing install root\n'
        else
            fatal 'install root "%s" already exists: skipping\n' "$install_root"
        fi
    else
        # Remove broken symlink
        rm -f "$install_root" ||:
    fi

    # Make directory
    install -d "$install_root" ||
        fatal 'fail to create install root "%s"\n' "$install_root"

    # Make path absolute
    install_root="$(cd "$install_root" >/dev/null 2>&1 && echo "$PWD")" ||
        fatal 'fail to resolve install root to absolute path'
    install_root="${install_root%/}"
fi
[ -n "$install_root" ] || build_info=''

# Install build information
if [ -n "$build_info" ]; then
    d="$install_root/.${prog_name%.sh}"

    # $this
    if [ -e "$this" ]; then
        install -D "$this" "$d/$prog_name"
    fi

    # $config
    if [ -n "$config" ]; then
        f="${config##*/}" &&
            install -D -m 0644 "$config" "$d/$f" &&
        f="${f:+--config=\"\$this_dir/$f\"}"
    else
        f=''
    fi

    # run.sh
    d="$d/run.sh.$$"
    cat >"$d" <<EOF
#!/bin/sh

# Set option(s)
set -e
set -u
#set -x

build_info_dir='${d%/*}'
this_prog='run.sh'

if [ ! -e "\$0" -o "\$0" -ef "/proc/\$\$/exe" ]; then
    # Executed script is
    #  a) read from stdin through pipe
    #  b) specified via -c option
    #  d) sourced'
    this="\$this_prog"
    this_dir='./'
else
    # Executed script exists and it's inode differs
    # from process exe symlink (Linux specific)
    this="\$0"
    this_dir="\${this%/*}/"
fi

this_dir="\$(cd "\$this_dir" && echo "\$PWD")"

if [ "\$this_dir" -ef "\$build_info_dir" ]; then
    if [ "\${RUN_IN_TEMP-}" = "\$this_prog" ]; then
        echo >&2 "\$0: recursive call detected, exiting."
        exit 126
    fi

    this_dir="\$(cd "\$build_info_dir/../.." && echo "\$PWD")"
    this_dir="\$this_dir/\${build_info_dir##*/}.\$\$"

    mv -f "\$build_info_dir" "\$this_dir"

    this="\$this_dir/\${this##*/}"

    RUN_IN_TEMP="\$this_prog" exec "\$this" "\$@"
else
    if [ "\${RUN_IN_TEMP-}" = "\$this_prog" ]; then
        trap 'rm -rf "\$this_dir" ||:' EXIT
    fi

    "\$this_dir/$prog_name" $argv \\
         $f \\
        '$install_root' \\
        #
fi
EOF
    # install(1) sets executable bits
    install -D "$d" "${d%.*}"
    rm -f "$d" ||:

    unset f d e
fi

# $passwordless_root or $autopassword_root

if [ "$passwordless_root" -eq 1 ] 2>/dev/null; then
    ! [ "$autopassword_root" -eq 1 ] 2>/dev/null || passwordless_root=0
else
    [ -z "$readonly_root" ] ||
    [ "$autopassword_root" -eq 0 ] 2>/dev/null || autopassword_root=1
fi

[ "$passwordless_root" != '0' ] || passwordless_root=''
[ "$autopassword_root" != '0' ] || autopassword_root=''

# $libvirt_qemu_user

if [ -n "$libvirt_qemu_user" ]; then
    if [ -z "${libvirt_qemu_user##*[^a-zA-Z0-9_-]*}" ] ||
       [ "$libvirt_qemu_user" -lt 0 ] 2>/dev/null
    then
        libvirt_qemu_user=${_libvirt_qemu_user}
    fi
fi

# $libvirt_unix_group

if [ -n "$libvirt_unix_group" ]; then
    if [ -z "${libvirt_unix_group##*[^a-zA-Z0-9_-]*}" ]; then
        libvirt_unix_group=${_libvirt_unix_group}
    fi
fi

# $libvirt_unix_ro_perms

if [ -n "$libvirt_unix_ro_perms" ]; then
    [ "$libvirt_unix_ro_perms" -le $((0777)) ] 2>/dev/null ||
        libvirt_unix_ro_perms=${_libvirt_unix_ro_perms}
fi

# $libvirt_unix_rw_perms

if [ -n "$libvirt_unix_rw_perms" ]; then
    [ "$libvirt_unix_rw_perms" -le $((0777)) ] 2>/dev/null ||
        libvirt_unix_rw_perms=${_libvirt_unix_rw_perms}
fi

# $libvirt_unix_auth_ro

case "$libvirt_unix_auth_ro" in
    none|sasl|polkit|'') ;;
    *) libvirt_unix_auth_ro=${_libvirt_unix_auth_ro} ;;
esac

# $libvirt_unix_auth_rw

case "$libvirt_unix_auth_rw" in
    none|sasl|polkit|'') ;;
    *) libvirt_unix_auth_rw=${_libvirt_unix_auth_rw} ;;
esac

################################################################################

## Initial setups

exit_handler()
{
    local rc=$?
    local t
    local systemctl_helper="$install_root/bin/systemctl"

    # Do not interrupt exit handler
    set +e

    if [ $rc -eq 0 ]; then
        ## Add helpers

        t='type systemctl >/dev/null 2>&1'
        if [ -e "$systemctl_helper" ] ||
           $(in_chroot_exec "$install_root" "$t"); then
            systemctl_helper=''
        else
            install -d "${systemctl_helper%/*}" ||:
            cat >"$systemctl_helper" <<'_EOF'
#!/bin/sh

set -e
set -u
#set -x

# See how we are called
case "${1-}" in
    'mask'|'disable'|'stop')   cmd='off' ;;
    'unmask'|'enable'|'start') cmd='on'  ;;
    *) exit 1
esac

while :; do
    shift || exit
    name="${1-}" && name="${name%.*}"
    [ -z "$name" ] || chkconfig "$name" "$cmd"
done

exit 0
_EOF
            chmod a+rx "$systemctl_helper" ||:
        fi

        ## Finish installation

        if [ -n "${pkg_grub2-}" ]; then
            # Add default GRUB config
            t="$install_root/etc/default/grub"

            if [ ! -s "$t" ]; then
                cat >"$t" <<'_EOF'
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="$(sed 's, release .*$,,g' /etc/system-release)"
GRUB_DEFAULT=saved
GRUB_DISABLE_SUBMENU=true
GRUB_TERMINAL="console"
GRUB_CMDLINE_LINUX="crashkernel=auto rhgb quiet"
GRUB_DISABLE_RECOVERY="true"
GRUB_ENABLE_BLSCFG=true
_EOF
            fi

            # Add "zswap.enabled=1" to kernel command line options list
            if [ -n "$zswap_enabled" ]; then
                $(
                    # Source in subshell to not pollute environment
                    . "$t"

                    if v="${GRUB_CMDLINE_LINUX-}" &&
                       [ "${v##*zswap.enabled=*}" = "$v" ] &&
                       v="${GRUB_CMDLINE_LINUX_DEFAULT-}" &&
                       [ "${v##*zswap.enabled=*}" = "$v" ]
                    then
                        cat >>"$t" <<'_EOF'
GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT-} zswap.enabled=1"
_EOF
                    fi
                )
            fi

            # Add "nosmt" to kernel command line options list
            if [ -n "$nosmt" ]; then
                $(
                    # Source in subshell to not pollute environment
                    . "$t"

                    if v="${GRUB_CMDLINE_LINUX-}" &&
                       [ "${v##*nosmt*}" = "$v" ] &&
                       v="${GRUB_CMDLINE_LINUX_DEFAULT-}" &&
                       [ "${v##*nosmt*}" = "$v" ]
                    then
                        cat >>"$t" <<'_EOF'
GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX-} nosmt"
_EOF
                    fi
                )
            fi
        fi # [ -n "${pkg_grub2-}" ]

        # Add helper that generates boot menu entries for iPXE
        t="$install_root/etc/grub.d"
        install -d "$t"

        t="$t/20_ipxe.$$"
        cat >"$t" <<'_EOF'
#!/bin/sh

set -e

. /usr/share/grub/grub-mkconfig_lib

# iPXE is only supported on x86
case $(uname -m) in
	i?86|x86_64) ;;
	*) exit 0 ;;
esac

prepare_boot_cache="$(prepare_grub_to_access_device ${GRUB_DEVICE_BOOT} | sed -e "s/^/\t/")"

if [ -d /sys/firmware/efi ]; then
  IPXE=/boot/ipxe.efi
else
  IPXE=/boot/ipxe.lkrn
fi

if test -e "$IPXE" ; then
  IPXEPATH=$( make_system_path_relative_to_its_root "$IPXE" )
  echo "Found iPXE image: $IPXE" >&2
  if [ -d /sys/firmware/efi ]; then
    cat <<EOF
menuentry "Network boot (iPXE)" --users "" --class network {
${prepare_boot_cache}
	chainloader $IPXEPATH
}
EOF
  else
    cat <<EOF
menuentry "Network boot (iPXE)" --users "" --class network {
${prepare_boot_cache}
	linux16 $IPXEPATH
}
EOF
  fi
fi
_EOF
        # install(1) sets executable bits
        install -D "$t" "${t%.*}"
        rm -f "$t" ||:

        # Add support for iPXE on BIOS and EFI systems
        if [ -n "${pkg_ipxe_bootimgs-}" ]; then
            copy_ipxe_file()
            {
                local func="${FUNCNAME:-copy_ipxe_file}"

                local ipxe="${1:?missing 1st argument to ${func}() (boot_ipxe)}"
                local ipxe_name="${2:-$ipxe}"
                local ipxe_iter

                for ipxe_iter in \
                    "$install_root/usr/share/ipxe/$ipxe" \
                    "$install_root/usr/lib/ipxe/$ipxe" \
                    #
                do
                    if [ -f "$ipxe_iter" ]; then
                        install -D -m 0644 \
                            "$ipxe_iter" "$install_root/boot/$ipxe_name"
                        return
                    fi
                done

                return 1
            }

            if ! copy_ipxe_file 'ipxe.efi'; then
                if [ -n "$grp_efi_ia32" ]; then
                    copy_ipxe_file 'ipxe-i386.efi' 'ipxe.efi'
                else
                    copy_ipxe_file 'ipxe-x86_64.efi' 'ipxe.efi'
                fi
            fi
            copy_ipxe_file 'ipxe.lkrn'
        fi # [ -n "${pkg_ipxe_bootimgs-}" ]

        # Add helper that generates terminfo commands for serial
        t="$install_root/etc/grub.d"
        install -d "$t"

        t="$t/05_serial_terminfo.$$"
        cat >"$t" <<'_EOF'
#!/bin/sh

set -e

serial='s,^GRUB_SERIAL_COMMAND=.*\(\(--unit=\|efi\)[0-9]\+\).*,\1,p'
serial="$(sed -n -e "$serial" '/etc/default/grub')"

if [ -n "$serial" ]; then
    t="$serial"

    serial="${serial#--unit=}"
    serial="${serial#efi}"

    if [ -z "${t##efi*}" ]; then
        cat <<EOF
terminfo serial_efi$serial vt100-color -u
terminfo serial_com$serial vt100-color -u
EOF
    else
        cat <<EOF
terminfo serial      vt100-color -u
terminfo serial_com$serial vt100-color -u
EOF
    fi
fi
_EOF
        # install(1) sets executable bits
        install -D "$t" "${t%.*}"
        rm -f "$t" ||:

        # Enable serial line console
        if [ -n "${pkg_grub2-}" -a -n "$serial_console" ]; then
            # From grub-installer udeb (Debian)
            get_serial_console()
            {
                local serial=

                # Get the last 'console=' entry (if none,
                # the whole string is returned)
                while [ $# -gt 0 ]; do
                    case "$1" in
                        console=ttyS*|console=ttyUSB*|console=com*)
                            serial="$1" ;;
                    esac
                    shift
                done

                if [ -n "$serial" ]; then
                     echo "$serial"
                fi
            }

            grub_serial_console()
            {
                local serconsole="$1"
                serconsole="${serconsole##console=ttyS}"
                serconsole="${serconsole##console=com}"
                local unit="${serconsole%%,*}"
                local speed parity word
                local options="${serconsole##*,}"

                if [ -z "$unit" ]; then
                    return
                fi
                if [ "$unit" != "$options" ]; then
                    # Take optional 1st (parity) and 2nd (word) characters after speed
                    set -- `echo "$options" | sed -e 's,^\([0-9]*\)\(.\?\)\(.\?\).*$,\1 \2 \3,'`
                    speed="$1"
                    parity="$2"
                    word="$3"
                fi
                [ -n "$speed" ] || speed='115200'
                case "$parity" in
                    n) parity='--parity=no'   ;;
                    e) parity='--parity=even' ;;
                    o) parity='--parity=odd'  ;;
                    *) parity=''              ;;
                esac
                [ -z "$word" ] || word="--word=$word"

                echo "serial --unit=$unit --speed=$speed $word $parity --stop=1"
            }

            t="$install_root/etc/default/grub"

            eval $(
                # Hide stdout to /dev/null prevent evaluation
                # of potential output from sourced file.
                exec 3>&1 >/dev/null

                . "$t"

                exec >&3 3>&-

                grub_cmdline_linux_append=1

                if [ "$serial_console" = '1' ]; then
                    serial_console="$(get_serial_console ${GRUB_CMDLINE_LINUX-})"
                    grub_cmdline_linux_append=''
                fi

                serial="$(grub_serial_console "$serial_console")"
                if [ -z "$serial" ]; then
                    # From grub-efi.cfg (Debian)
                    serial_console="${_serial_console}"
                    serial="$(grub_serial_console "$serial_console")"
                    grub_cmdline_linux_append=1
                fi
                echo "serial_console='$serial_console'"
                echo "serial='$serial'"

                if [ -n "$grub_cmdline_linux_append" ]; then
                    echo "GRUB_CMDLINE_LINUX=\"\${GRUB_CMDLINE_LINUX-} $serial_console\"" >>"$t"
                fi
            )

            if grep -q '^GRUB_TERMINAL=' "$t"; then
                # it is set by installer or by default in config
                sed -i "$t" -e "s,^\(GRUB_TERMINAL\)=.*,\1=\"serial console\",g"
            else
                echo "GRUB_TERMINAL=\"serial console\"" >> "$t"
            fi

            # Add serial command
            if grep -q '^GRUB_SERIAL_COMMAND=' "$t"; then
                # it is set by installer or by default in config
                sed -i "$t" -e "s,^\(GRUB_SERIAL_COMMAND\)=.*,\1=\"$serial\",g"
            else
                echo "GRUB_SERIAL_COMMAND=\"$serial\"" >> "$t"
            fi
            if [ -n "$grp_efi" ]; then
                # replace --unit=<u> with efi<u> on EFI systems to fix artifacts
                sed -i "$t" -e '/^GRUB_SERIAL_COMMAND=/s,--unit=\([0-9]\+\),efi\1,g'
            fi

            unset serial
        fi # [ -n "${pkg_grub2-}" -a -n "$serial_console" ]

        # Update /etc/issue, /etc/issue.net and /etc/motd banners
        if [ -n "$login_banners" ]; then
            $(
                # Source in subshell to not pollute environment
                t="$install_root/etc/os-release"
                [ -f "$t" ] && . "$t" >/dev/null 2>&1 || PRETTY_NAME=

                [ -n "$PRETTY_NAME" ] || PRETTY_NAME="$(uname -s)"

                # /etc/issue
                banner="$install_root/etc/issue"
                if [ -f "$banner" ]; then
                    cat >"$banner" <<_EOF
$PRETTY_NAME

  Hostname : \n
  TTY      : \l${nfs_root:+
  IPv4     : \4
  IPv6     : \6}

_EOF
                fi

                # /etc/issue.net
                banner="$install_root/etc/issue.net"
                if [ -f "$banner" ]; then
                    cat >"$banner" <<'_EOF'
_EOF
                fi

                # /etc/motd
                banner="$install_root/etc/motd"
                if [ -f "$banner" ]; then
                    cat >"$banner" <<'_EOF'
_EOF
                fi
            )
        fi # [ -n "$login_banners" ]

        # Disable lvmetad on CentOS/RHEL 7- to conform to 8+
        if centos_version_le $releasemaj 7; then
            t="$install_root/etc/lvm/lvm.conf"
            if [ -f "$t" ]; then
                sed -i "$t" \
                    -e '/^\s*use_lvmetad\s*=\s*[0-9]\+\s*$/s/[0-9]/0/' \
                    #
                in_chroot "$install_root" \
                    'systemctl mask lvm2-lvmetad.service lvm2-lvmetad.socket'
                in_chroot "$install_root" \
                    'systemctl stop lvm2-lvmetad.service lvm2-lvmetad.socket'
            fi
        fi

        if [ -n "${grp_virt_host-}" ]; then
            if [ -n "${pkg_qemu_kvm-}" ]; then
                # Enable/disable KVM nested virtualization
                t="$install_root/etc/modprobe.d/kvm.conf"
                if [ -f "$t" ]; then
                    local r='s/^#\?\($n\)=[0-9]\+\(.*\)/\1=$v\4/'
                    local r1
                    local n='options\s\+\(kvm_\(intel\|amd\)\)\s\+nested'
                    local v="$kvm_nested"

                    if [ -n "$v" ] ; then
                        [ "$v" -eq 1 ] 2>/dev/null || v=0

                        eval "r1=\"$r\""

                        sed -i "$t" \
                            ${r1:+-e "$r1"} \
                            #
                    fi
                fi
            fi

            if [ -n "${pkg_libvirt-}" ]; then
                # Configure libvirt-daemon-driver-qemu
                t="$install_root/etc/libvirt/qemu.conf"
                if [ -f "$t" ]; then
                    local r='s/^#\?\($n\s*=\s*\)\"\w*\"\(\s*\)/\1\"$v\"\3/'
                    local r1
                    local n='\(user\|group\)'
                    local v="$libvirt_qemu_user"

                    if [ -n "$v" ] ; then
                        eval "r1=\"$r\""

                        sed -i "$t" \
                            ${r1:+-e "$r1"} \
                            #
                    fi
                fi

                # Configure libvirt-daemon
                t="$install_root/etc/libvirt/libvirtd.conf"
                if [ -f "$t" ]; then
                    local r='s/^#\?\($n\s*=\s*\)\"\w*\"\(\s*\)/\1\"$v\"\2/'
                    local r1 r2 r3 r4 r5
                    local n v i=0

                    local var_libvirt_unix_group='unix_sock_group'
                    local var_libvirt_unix_ro_perms='unix_sock_ro_perms'
                    local var_libvirt_unix_rw_perms='unix_sock_rw_perms'
                    local var_libvirt_unix_auth_ro='auth_unix_ro'
                    local var_libvirt_unix_auth_rw='auth_unix_rw'

                    for n in \
                        'libvirt_unix_group' \
                        'libvirt_unix_ro_perms' \
                        'libvirt_unix_rw_perms' \
                        'libvirt_unix_auth_ro' \
                        'libvirt_unix_auth_rw' \
                        #
                    do
                        eval "
                            if v=\"\$$n\" && [ -n \"\$v\" ]; then
                                n=\"\$var_${n}\"
                                v=\"$r\"
                            else
                                v=''
                            fi
                            r$((++i))=\"\$v\"
                        "
                    done

                    if [ -n "$r1$r2$r3$r4" ]; then
                        sed -i "$t" \
                            ${r1:+-e "$r1"} \
                            ${r2:+-e "$r2"} \
                            ${r3:+-e "$r3"} \
                            ${r4:+-e "$r4"} \
                            ${r5:+-e "$r5"} \
                            #
                    fi
                fi
            fi
        fi

        # Configure nameserver(s) in resolv.conf
        t="$install_root/etc/resolv.conf"
        if [ -n "${nameservers}${install_root%/}" ]; then
            : >"$t"
        fi
        if [ -n "${nameservers}" ]; then
            local n
            for n in ${nameservers}; do
                echo "nameserver $n" >>"$t"
            done
        fi

        # Enable tmp.mount with up to $tmp_mount percents of system RAM
        if [ -n "$tmp_mount" ]; then
            t="$install_root/usr/lib/systemd/system/tmp.mount"
            if [ -s "$t" ]; then
                [ "$tmp_mount" -ge ${_tmp_mount_min} -a \
                  "$tmp_mount" -le ${_tmp_mount_max} ] 2>/dev/null ||
                    tmp_mount=${_tmp_mount}
                sed -e "s/^\(Options=.\+\)$/\1,size=$tmp_mount%/" "$t" \
                    >"$install_root/etc/systemd/system/${t##*/}"
                in_chroot "$install_root" 'systemctl enable tmp.mount'
            fi
        fi

        # Enable iptables and ip6tables if given
        if [ -n "${pkg_iptables-}" ]; then
            in_chroot "$install_root" 'systemctl enable iptables.service'
            in_chroot "$install_root" 'systemctl enable ip6tables.service'
        fi

        if [ -x "$install_root/etc/init.d/network" ]; then
            if [ -n "${pkg_network_scripts-}" ]; then
                # Enable legacy network scripts if they was explicitly enabled
                in_chroot "$install_root" 'systemctl enable network.service'
            else
                # Disable legacy network scripts if NetworkManager enabled
                if [ -n "${pkg_nm-}" ]; then
                    in_chroot "$install_root" \
                        'systemctl disable network.service'
                fi
            fi
        fi

        # Disable lm_sensors as they require explicit configuration
        if [ -n "${pkg_lm_sensors-}" ]; then
            in_chroot "$install_root" 'systemctl disable lm_sensors.service'
        fi

        # Enable display-manager.service and set-default to graphical.target
        if [ -n "$has_dm" ]; then
            in_chroot "$install_root" "systemctl enable '$has_dm.service'"
            in_chroot "$install_root" 'systemctl set-default graphical.target'
        fi

        # Enable postfix as it might be disabled (e.g. on CentOS/RHEL 8)
        in_chroot "$install_root" 'systemctl enable postfix.service'

        if [ -n "$readonly_root" ]; then
            # Make postfix readonly root aware
            if pkg_is_installed postfix; then
                t="$install_root/etc/rwtab.d/postfix"
                [ -s "$t" ] || {
                    echo 'dirs /var/lib/postfix'
                } >"$t"
            fi

            # Make rsyslog readonly root aware
            if pkg_is_installed rsyslog; then
                t="$install_root/etc/rwtab.d/rsyslog"
                [ -s "$t" ] || {
                    echo 'dirs /var/lib/rsyslog'
                } >"$t"
            fi

            # Make gssproxy readonly root aware
            if pkg_is_installed gssproxy; then
                t="$install_root/etc/rwtab.d/gssproxy"
                [ -s "$t" ] || {
                    echo 'dirs /var/lib/gssproxy'
                } >"$t"
            fi

            # Make /etc writable to update config files (mainly /etc/passwd)
            t="$install_root/etc/rwtab.d/_etc"
            [ -s "$t" ] || {
                echo 'files /etc'
                # required by systemd-journal-catalog-update.service
                # started when /etc is writable
                echo 'empty /var/lib/systemd/catalog'
            } >"$t"

            # Fix systemd-tmpfiles-setup.service on CentOS/RHEL 7;
            # see https://bugzilla.redhat.com/show_bug.cgi?id=1207083
            if centos_version_eq $releasemaj 7; then
                # /usr/lib/tmpfiles.d/legacy.conf: /var/lock -> ../run/lock
                ln -sf '../run/lock' "$install_root/var/lock"

                t="$install_root/usr/lib/tmpfiles.d/legacy.conf"
                if [ -s "$t" ]; then
                    sed -e 's,^\(L\s\+/var/lock\),#\1,' "$t" \
                        >"$install_root/etc/tmpfiles.d/${t##*/}"
                fi

                # /usr/lib/tmpfiles.d/rpm.conf: rm -f /var/lib/rpm/__db.*
                rm -f "$install_root/var/lib/rpm"/__db.*

                t="$install_root/usr/lib/tmpfiles.d/rpm.conf"
                if [ -s "$t" ]; then
                    sed -e 's,^\(r\s\+/var/lib/rpm/__db\.\*\),#\1,' "$t" \
                        >"$install_root/etc/tmpfiles.d/${t##*/}"
                fi
            fi
        fi

        # Usage: ssh_agent_start4bashrc() [<user1>|<file1>] [<user2>|<file1>] ...
        ssh_agent_start4bashrc()
        {
            local func="${FUNCNAME:-ssh_agent_start4bashrc}"

            local t f

            for f in "$@"; do
                # Skip empty arguments
                [ -n "$f" ] || continue

                # Resolve username or directory to .bashrc file
                t=''
                while :; do
                      if [ -f "$f" ]; then
                        t=''
                        break
                    elif [ -d "$f" ]; then
                        f="$f/.bashrc"
                    else
                        # Stop on non-first attempt
                        [ -z "$t" ] || break

                        # User or it's home does not exist
                        t="~$f" && eval "f=$t" && [ "$f" != "$t" ] || break
                    fi
                done
                [ -z "$t" ] || continue

                # Skip already patched files
                t="$(sed -n -e '/^# Start ssh-agent for non-X11 session/{p;q}' "$f")"
                [ -z "$t" ] || continue

                # Keep it disabled by default for compatibility
                t="${f%/.bashrc}/.ssh/ssh-agent.env"
                rm -f "$t" ||:
                install -D -m 0644 /dev/null "$t" ||:

                # Patch .bashrc file at known location instead of appending
                sed -i "$f" \
                    -e 'N' \
                    -e '/^\s\+\. \/etc\/bashrc\s\+fi$/!{P;D}' \
                    -e 'r /dev/stdin' \
                <<'_EOF'

# Start ssh-agent for non-X11 session unless ...
if [ -z "${DISPLAY-}" ]; then
    ssh_agent=''
    # Note that is is up to user to ensure that ~/.ssh isn't world writeable.
    ssh_agent_env=~/.ssh/ssh-agent.env

    while :; do
        # Socket by agent or sshd forwarded connection.
        # In latter case SSH_AGENT_PID isn't available.
        if [ -S "${SSH_AUTH_SOCK-}" ]; then
            break
        fi
        # Cleanup if not running or running but no socket.
        if [ -n "${ssh_agent##*/*}" ]; then
            unset SSH_AUTH_SOCK SSH_AGENT_PID
            break
        fi
        # Source environment.
        if [ -r "$ssh_agent_env" ]; then
            eval $(
                . "$ssh_agent_env" >/dev/null

                [ -z "${SSH_AGENT_PID-}" ] ||
                [ -z "${SSH_AGENT_PID##*\'*}" ] ||
                    echo "export SSH_AGENT_PID='$SSH_AGENT_PID'"

                [ -z "${SSH_AUTH_SOCK-}" ] ||
                [ -z "${SSH_AUTH_SOCK##*\'*}" ] ||
                    echo "export SSH_AUTH_SOCK='$SSH_AUTH_SOCK'"
            )
        fi

        if [ -n "${SSH_AGENT_PID-}" ] &&
           kill -0 "$SSH_AGENT_PID" 2>/dev/null
        then
            # ... already running
            ssh_agent='running'
        else
            # ... first attempt to start failed.
            [ -z "$ssh_agent" ] &&
            # ... disabled (e.g. with ln -sf /dev/null ~/.ssh/ssh-agent.env).
            [ ! -e "$ssh_agent_env" -o -s "$ssh_agent_env" ] &&
            # ... it exists and started successfuly.
            ssh_agent="$(command -v ssh-agent)" &&
                [ -x "$ssh_agent" ] &&
                mkdir -p "${ssh_agent_env%/*}" &&
                rm -f "$ssh_agent_env" &&
                (
                    # Make sure agent settings readable only by user
                    umask 0077 && "$ssh_agent" -s >"$ssh_agent_env"
                ) ||
            ssh_agent='not running'

            # Make sure we source environment.
            unset SSH_AUTH_SOCK
        fi
    done

    unset ssh_agent ssh_agent_env
fi
_EOF
            done
        }

        # Usage: mc_ini <homedir>
        mc_ini()
        {
            local d

            d="$1/.cache/mc"
            [ -d "$d" ] || install -d "$d"
            d="$1/.local/share/mc"
            [ -d "$d" ] || install -d "$d"
            d="$1/.config/mc"
            [ -d "$d" ] || install -d "$d"

            cat >"$d/ini" <<'_EOF'
[Midnight-Commander]
auto_save_setup=1
use_internal_view=1
use_internal_edit=1
confirm_exit=1
editor_tab_spacing=8
editor_word_wrap_line_length=72
editor_fill_tabs_with_spaces=0
editor_return_does_auto_indent=1
editor_fake_half_tabs=0
editor_option_save_position=1
editor_option_typewriter_wrap=0
editor_edit_confirm_save=1
editor_syntax_highlighting=1
editor_visible_tabs=1
editor_visible_spaces=1
editor_group_undo=0

[Layout]
message_visible=0
keybar_visible=1
xterm_title=1
command_prompt=1
menubar_visible=0
free_space=1
horizontal_split=0
vertical_equal=1
horizontal_equal=1
top_panel_size=1
_EOF
        }

        # Usage: screenrc <homedir>
        screenrc()
        {
            local d="$1"

            [ -d "$d" ] || install -d "$d"

            cat >"$d/.screenrc" <<'_EOF'
# GNU Screen - main configuration file
# All other .screenrc files will source this file to inherit settings.
# Author: Christian Wills - cwills.sys@gmail.com

## Allow bold colors - necessary for some reason
#attrcolor b ".I"

## Tell screen how to set colors. AB = background, AF=foreground
termcapinfo xterm 'Co#256:AB=\E[48;5;%dm:AF=\E[38;5;%dm'

## Enables use of shift-PgUp and shift-PgDn
#termcapinfo xterm|xterms|xs|rxvt ti@:te@

## Erase background with current bg color
#defbce "on"

## Enable 256 color term
#term xterm-256color

# Cache 30000 lines for scroll back
defscrollback 30000

hardstatus alwayslastline
# Very nice tabbed colored hardstatus line
hardstatus string '%{= Kd} %{= Kd}%-w%{= Kr}[%{= KW}%n %t%{= Kr}]%{= Kd}%+w %-= %{KG} %H%{KW}|%{KY}%S%{KW}|%D %M %d %Y%{= Kc} %C%A%{-}'

# change command character from ctrl-a to ctrl-b (emacs users may want this)
#escape ^Bb

# Hide hardstatus: ctrl-a f
bind f eval "hardstatus ignore"
# Show hardstatus: ctrl-a F
bind F eval "hardstatus alwayslastline"
_EOF
        }

        # /root
        t="$(in_chroot_exec "$install_root" 't=~root; echo "t='\''$t'\''"')"
        if eval "$t" && t="$install_root/$t" && [ -d "$t" ]; then
            install -d \
                "$t/.local" "$t/.local/share" "$t/.local/bin" \
                "$t/.cache" "$t/.config"
            install -d -m 0700 \
                "$t/.ssh" \
                "$t/tmp"
            ln -sf '.local/bin' "$t/bin"
        fi
        mc_ini "$t"
        screenrc "$t"
        ssh_agent_start4bashrc "$t"

        # /etc/skel
        t="$install_root/etc/skel"
        install -d \
            "$t/.local" "$t/.local/share" "$t/.local/bin" \
            "$t/.cache" "$t/.config"
        install -d -m 0700 \
            "$t/.ssh" \
            "$t/tmp"
        ln -sf '.local/bin' "$t/bin"
        mc_ini "$t"
        screenrc "$t"
        ssh_agent_start4bashrc "$t"

        # Termiate bash after given seconds of inactivity (auto-logout)
        if [ -x '/bin/bash' ]; then
            t="$install_root/etc/profile.d/shell-timeout.sh"
            cat >"$t" <<'_EOF'
# Set non-X11 login shell session auto-logout after timeout
[ -n "$DISPLAY" ] || export TMOUT=$((20 * 60))
_EOF
        fi

        # Make sure /var/log/lastlog is here
        t="$install_root/var/log/lastlog" && [ -f "$t" ] || : >"$t"
        # Make sure /etc/sysconfig/network is here
        t="$install_root/etc/sysconfig/network" && [ -f "$t" ] || : >"$t"
        # Make sure /var/lib/systemd/random-seed is here and empty
        t="$install_root/var/lib/systemd" && [ ! -d "$t" ] || : >"$t/random-seed"
        # Make sure /etc/machine-id is here and empty
        t="$install_root/etc/machine-id" && : >"$t"

        # Update GRUB configuration file
        if [ -n "${pkg_grub2-}" ]; then
            in_chroot "$install_root" '
                 [ ! -L /etc/grub2.cfg ] ||
                    grub2-mkconfig -o "$(readlink /etc/grub2.cfg)"
                 [ ! -L /etc/grub2-efi.cfg ] ||
                    grub2-mkconfig -o "$(readlink /etc/grub2-efi.cfg)"
            '
        fi

        if [ -n "$nodocs" ]; then
            # Directories not excluded from install. They are empty.
            find "$install_root/usr/share/doc" -type d -a -empty -a -delete
        fi

        # Clean yum(1) packages and cached data
        in_chroot "$install_root" 'yum -y clean all'

        # Clean /var/log files
        clean_dir()
        {
            local func="${FUNCNAME:-clean_dir}"

            local e="${1:-$PWD}"
            local rc=0

            if [ -d "$e" ]; then
                local d="$PWD"

                cd "$e" || return

                for e in *; do
                    if "$func" "$e"; then
                        continue
                    else
                        rc=$?
                        break
                    fi
                done

                cd "$d" || return $((rc + $?))
            else
                [ ! -e "$e" ] || :> "$e" || rc=$?
            fi

            return $rc
        }
        clean_dir "$install_root/var/log"
    fi

    if [ -n "$systemctl_helper" ]; then
        rm -f "$systemctl_helper" ||:
    fi

    if [ -n "${install_root%/}" ]; then
        # Unmount bind-mounted filesystems
        for t in '/proc/1' '/proc' '/sys' '/dev'; do
            t="$install_root$t"
            ! mountpoint -q "$t" || umount "$t"
        done

        t="$install_root/.tmp"
        rm -rf "$t" ||:
    fi

    return $rc
}
trap 'exit_handler' EXIT

if [ -n "$install_root" ]; then
    # Bind mount proc, sys and dev filesystems
    for f in '/proc' '/sys' '/dev'; do
        d="$install_root$f"
        install -d "$d" && mount --bind "$f" "$d"
    done

    # Point /etc/mtab to /proc/self/mounts unless it already exist
    f="$install_root/etc/mtab"
    if [ ! -f "$f" ]; then
        install -D -m 0644 /dev/null "$f"
        ln -sf '../proc/self/mounts' "$f"
    fi

    # Hide /proc/1 from target (e.g. for rpm pre/post scripts)
    f="$install_root/proc/1"
    d="$install_root/.tmp/1"

    [ -d "$f" ] && install -d "$d" && mount --bind "$d" "$f" ||:

    if [ -n "${install_root%/}" ]; then
        # Need access to resolvers: prefer system, fall back to public
        f='/etc/resolv.conf'
        d="$install_root$f"

        if [ -s "$f" ]; then
            install -D -m 0644 "$f" "$d"
        else
            for f in ${nameservers:-${_nameservers}}; do
                echo "nameserver $f" >>"$d"
            done
        fi
    fi

    unset f d
else
    install_root='/'
fi

## Install core components

# repository URLs
baseurl=''
updatesurl=''
# yum(1) does not support certain options
nogpgcheck=''
# current or archive version
is_archive=''
# has specific feature
has_glibc_langpack=''
has_repo=''

# Usage: distro_disable_extra_repos
distro_disable_extra_repos()
{
    # Except EPEL
    repo_virtio_win=''
    repo_advanced_virtualization=''
    repo_openstack=''
    repo_ovirt=''
    repo_elrepo=''
    repo_rpm_fusion=''
}

# Usage: distro_centos
distro_centos()
{
    # Usage: distro_post_core_hook
    distro_post_core_hook()
    {
        if [ -n "$is_archive" ]; then
            # Releases available at $baseurl
            local url="${baseurl%/$releasever/*}"

            local baseurl_p1='^#\?\(baseurl\)=.\+/\$releasever/\(.\+\)$'
            local baseurl_p2="\1=$url/$releasever/\2"

            find "$install_root/etc/yum.repos.d" \
                -name 'CentOS-*.repo' -a -type f -a -exec \
            sed -i \
                -e 's,^\(mirrorlist\|metalink\)=,#\1=,' \
                -e "s,$baseurl_p1,$baseurl_p2," \
            {} \+
        fi

        if [ $releasemaj -lt 6 ]; then
            # Add gpgkey= to local file://
            local t="$install_root"
            local url
            url="$t/etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-$releasemaj"
            if [ ! -f "$url" ]; then
                url="$t/usr/share/doc/centos-release-$releasemaj/RPM-GPG-KEY"
                if [ ! -f "$url" ]; then
                    url=''
                fi
            fi
            if [ -n "$url" ]; then
                find "$install_root/etc/yum.repos.d" \
                    -name 'CentOS-*.repo' -a -type f -a -exec \
                sed -i \
                    -e '/^gpgkey=/d' \
                    -e "/^gpgcheck=1/a gpgkey=file://${url#$t}" \
                {} \+
            fi
        fi

        if [ -n "${releasever_orig-}" ]; then
            # Update to target version
            if [ $releasever_orig = '6.10' ]; then
                find "$install_root/etc/yum.repos.d" \
                    -name 'CentOS-*.repo' -a -type f -a -exec \
                sed -i \
                    -e '/^baseurl=/!b' \
                    -e "s,/$releasever/,/$releasever_orig/,g" \
                {} \+
                in_chroot "$install_root" 'yum -y update'
            fi
        fi

        local EPEL_URL EPEL_RELEASE_RPM EPEL_RELEASE_URL
        local ELREPO_URL ELREPO_RELEASE_RPM ELREPO_RELEASE_URL
        local ADVANCED_VIRTUALIZATION_RELEASE_RPM
        local OPENSTACK_RELEASE_RPM
        local OVIRT_RELEASE_RPM
        local RPM_FUSION_URL RPM_FUSION_RELEASE_RPM RPM_FUSION_RELEASE_URL
        local VIRTIO_WIN_URL

        # VirtIO-Win
        VIRTIO_WIN_URL='https://fedorapeople.org/groups/virt/virtio-win/virtio-win.repo'

          if [ $releasemaj -eq 8 ]; then
            # EPEL
            EPEL_URL='http://dl.fedoraproject.org/pub/epel'
            EPEL_RELEASE_RPM='epel-release-latest-8.noarch.rpm'
            EPEL_RELEASE_URL="$EPEL_URL/$EPEL_RELEASE_RPM"

            # ELRepo
            ELREPO_URL='https://www.elrepo.org'
            ELREPO_RELEASE_RPM='elrepo-release-8.el8.elrepo.noarch.rpm'
            ELREPO_RELEASE_URL="$ELREPO_URL/$ELREPO_RELEASE_RPM"

            # Advanced Virtualization
            ADVANCED_VIRTUALIZATION_RELEASE_RPM='centos-release-advanced-virtualization'

            # OpenStack
            OPENSTACK_RELEASE_RPM='centos-release-openstack-ussuri'

            # oVirt
            OVIRT_RELEASE_RPM='centos-release-ovirt44'

            # RPM Fusion
            RPM_FUSION_URL='https://download1.rpmfusion.org/free/el'
            RPM_FUSION_RELEASE_RPM='rpmfusion-free-release-8.noarch.rpm'
            RPM_FUSION_RELEASE_URL="$RPM_FUSION_URL/$RPM_FUSION_RELEASE_RPM"
        elif [ $releasemaj -eq 7 ]; then
            # EPEL
            EPEL_URL='http://dl.fedoraproject.org/pub/epel'
            EPEL_RELEASE_RPM='epel-release-latest-7.noarch.rpm'
            EPEL_RELEASE_URL="$EPEL_URL/$EPEL_RELEASE_RPM"

            # ELRepo
            ELREPO_URL='https://www.elrepo.org'
            ELREPO_RELEASE_RPM='elrepo-release-7.el7.elrepo.noarch.rpm'
            ELREPO_RELEASE_URL="$ELREPO_URL/$ELREPO_RELEASE_RPM"

            # Advanced Virtualization
            ADVANCED_VIRTUALIZATION_RELEASE_RPM='centos-release-qemu-ev'

            # OpenStack
            OPENSTACK_RELEASE_RPM='centos-release-openstack-train'

            # oVirt
            OVIRT_RELEASE_RPM='centos-release-ovirt43'

            # RPM Fusion
            RPM_FUSION_URL='https://download1.rpmfusion.org/free/el'
            RPM_FUSION_RELEASE_RPM='rpmfusion-free-release-7.noarch.rpm'
            RPM_FUSION_RELEASE_URL="$RPM_FUSION_URL/$RPM_FUSION_RELEASE_RPM"
        else
            # On old/new CentOS we do

            # ... support only EPEL as external repository
            if [ -n "$repo_epel" ]; then
                # EPEL
                EPEL_URL='http://archives.fedoraproject.org/pub/archive/epel'

                  if [ $releasemaj -eq 6 ]; then
                    EPEL_RELEASE_RPM='epel-release-6-8.noarch.rpm'
                elif [ $releasemaj -eq 5 ]; then
                    EPEL_RELEASE_RPM='epel-release-5-4.noarch.rpm'
                elif [ $releasemaj -eq 4 ]; then
                    EPEL_RELEASE_RPM='epel-release-4-10.noarch.rpm'
                else
                    repo_epel=''
                fi

                if [ -n "$repo_epel" ]; then
                    EPEL_RELEASE_URL="$EPEL_URL/$releasemaj/$basearch"
                    EPEL_RELEASE_URL="$EPEL_RELEASE_URL/$EPEL_RELEASE_RPM"
                else
                    unset EPEL_URL EPEL_RELEASE_RPM EPEL_RELEASE_URL
                fi
            fi

            # ... not support nfs-root
            nfs_root=''

            # ... support only minimal install
            minimal_install=1
        fi

        # $repo_ovirt
        if [ -n "$repo_ovirt" ]; then
            repo_openstack=''
            repo_virtio_win=''
            repo_advanced_virtualization=''
        fi

        # $repo_openstack
        if [ -n "$repo_openstack" ]; then
            repo_ovirt=''
            repo_virtio_win=''
            repo_advanced_virtualization=''
        fi

        # $repo_epel, $repo_rpm_fusion
        if [ -n "$repo_rpm_fusion" ]; then
            repo_epel=1
        fi

        # EPEL
        if [ -n "$repo_epel" ]; then
            if [ $releasemaj -eq 8 -a $releasemin -lt 3 ]; then
                # Enable PowerTools if EPEL is enabled to satisfy dependencies
                in_chroot "$install_root" \
                    'yum config-manager --set-enabled PowerTools' \
                    #
            fi

            in_chroot "$install_root" "
                rpm -i '$EPEL_RELEASE_URL'
            " && has_repo=1

            if [ -n "$is_archive" ]; then
                # Unsupported releases available at $url
                local url="http://archives.fedoraproject.org/pub/archive/epel"
                local t="\$releasever\|$releasemaj"

                local baseurl_p1="^#\?\(baseurl\)=.\+/\($t\)/\(.\+\)$"
                local baseurl_p2="\1=$url/\$releasever/\3"

                find "$install_root/etc/yum.repos.d" \
                    -name 'epel*.repo' -a -type f -a -exec \
                sed -i \
                    -e 's,^\(mirrorlist\|metalink\)=,#\1=,' \
                    -e "s,$baseurl_p1,$baseurl_p2," \
                {} \+
            fi

            if [ $releasemaj -eq 4 -a $releasemin -le 3 ]; then
                # Backup /etc/yum.conf since yum(1) from epel does not have one
                local t="$install_root/etc/yum.conf"
                ln -nf "$t" "$t.rpmorig" ||:
            fi
        fi

        # ELRepo
        if [ -n "$repo_elrepo" ]; then
            in_chroot "$install_root" "
                rpm -i '$ELREPO_RELEASE_URL'
            " && has_repo=1 || repo_elrepo=''
        fi

        # VirtIO-Win
        if [ -n "$repo_virtio_win" ]; then
            curl -s -o "$install_root/etc/yum.repos.d/virtio-win.repo" \
                "$VIRTIO_WIN_URL" \
            && has_repo=1 || repo_virtio_win=''
        fi

        # Advanced Virtualization
        if [ -n "$repo_advanced_virtualization" ]; then
            in_chroot "$install_root" "
                yum -y $nogpgcheck install '$ADVANCED_VIRTUALIZATION_RELEASE_RPM'
            " && has_repo=1 || repo_advanced_virtualization=''
        fi

        # OpenStack
        if [ -n "$repo_openstack" ]; then
            in_chroot "$install_root" "
                yum -y $nogpgcheck install '$OPENSTACK_RELEASE_RPM'
            " && has_repo=1 || repo_openstack=''
        fi

        # oVirt
        if [ -n "$repo_ovirt" ]; then
            in_chroot "$install_root" "
                yum -y $nogpgcheck install '$OVIRT_RELEASE_RPM'
            " && has_repo=1 || repo_ovirt=''
        fi

        # RPM Fusion
        if [ -n "$repo_rpm_fusion" ]; then
            in_chroot "$install_root" "
                rpm -i '$RPM_FUSION_RELEASE_URL'
            " && has_repo=1 || repo_rpm_fusion=''
        fi
    }

    local host subdir url
    local _releasemin=255

    # $releasever
    releasever_orig="$releasever"
    if [ -z "$releasever" ]; then
        # Default CentOS version is latest
        releasever=8
        releasemaj=8
        releasemin=${_releasemin}
    else
        # There is some incompatibility with rpmdb(1)
        # format that can't be addressed with rpmdb_dump/load
        # helpers: install last supported and then update.
        [ $releasever != '6.10' ] ||
            releasever='6.9'

        releasemaj="${releasever%%.*}"

        [ $releasemaj -ge 4 ] ||
            fatal 'no support for CentOS before 4 (no yum?)'


        if [ "$releasemaj" != "$releasever" ]; then
            releasemin="${releasever#$releasemaj.}"
            releasemin="${releasemin%%.*}"
        else
            releasemin=${_releasemin}
        fi
    fi

    # $subdir
    subdir='centos'
    case "$basearch" in
        'i386')
            # Pick CentOS 7 AltArch, which is last with i386 support,
            # unless default release version is older.
            if [ $releasemaj -ge 7 ]; then
                if [ $releasemaj -gt 7 ]; then
                    releasever=7
                    releasemaj=7
                    releasemin=${_releasemin}
                fi
                subdir='altarch'
                # Disable all external repositories
                repo_epel=''
                distro_disable_extra_repos
            fi
            ;;
        # Add more secondary architectures here.
        # Note that supported set varies between releases.
    esac

    # $baseurl, $updatesurl
    release_url()
    {
        local subdir="${subdir:+$subdir/}"

        local templ='http://%s.centos.org/%s%s/%s'
        local base updates

        base="$(
            [ $releasemaj -le 7 ] &&
                arch="os/$basearch" || arch="BaseOS/$basearch/os"

            printf -- "$templ" \
                "$host" "$subdir" "$releasever" "$arch"
        )"
        [ -n "$base" ] &&
            curl -L -f -s -o /dev/null "$base" &&
        echo "baseurl='$base'" || return

        updates="$(
            [ $releasemaj -le 7 ] &&
                arch="updates/$basearch" || arch="AppStream/$basearch/os"

            printf -- "$templ" \
                "$host" "$subdir" "$releasever" "$arch"
        )"
        [ "$base" != "$updates" ] &&
            curl -L -f -s -o /dev/null "$updates" &&
        echo "updatesurl='$updates'" ||:
    }
      if url="$(host='mirror' release_url)"; then
        # Current
        is_archive=''
    elif url="$(host='vault' subdir="${subdir#centos}" release_url)"; then
        # Archive
        is_archive='1'
    else
        fatal "CentOS $releasever isn't available for download"
    fi
    eval "$url"

    if [ -n "$is_archive" ]; then
        # No country/continent mirrors
        cc=''
        # Disable external repositories, except EPEL
        distro_disable_extra_repos
    fi

    [ $releasemaj -lt 8 ] || has_glibc_langpack=1

    if [ $releasemaj -lt 6 ]; then
        PKGS="${PKGS:+$PKGS }vixie-cron sysklogd ntp"
        # Make sure yum(1) is there for CentOS < 5.x
        [ $releasemaj -ge 5 ] || PKGS="$PKGS yum"
    else
        PKGS="${PKGS:+$PKGS }cronie rsyslog"
        if [ $releasemaj -gt 6 ] ||
           [ $releasemaj -eq 6 -a $releasemin -gt 7 ]
        then
            PKGS="${PKGS:+$PKGS }chrony"
        else
            PKGS="${PKGS:+$PKGS }ntp"
        fi
        # yum(1) supports --nogpgcheck
        nogpgcheck='--nogpgcheck'
    fi

    # Additional packages that are (not) in @core package group
    PKGS="${PKGS:+$PKGS }postfix logrotate sudo"
}

# Usage: distro_fedora
distro_fedora()
{
    # Usage: distro_post_core_hook
    distro_post_core_hook()
    {
        if [ -n "$is_archive" ]; then
            # Releases available at $baseurl
            local url="${baseurl%/*/$releasever/*}"

            local baseurl_p1='^#\?\(baseurl\)=.\+/\([^/]\+/\$releasever/.\+\)$'
            local baseurl_p2="\1=$url/\2"

            find "$install_root/etc/yum.repos.d" \
                -name 'fedora*.repo' -a -type f -a -exec \
            sed -i \
                -e 's,^\(mirrorlist\|metalink\)=,#\1=,' \
                -e "s,$baseurl_p1,$baseurl_p2," \
            {} \+
        fi

        # On old/new Fedora we do

        # ... not support nfs-root
        nfs_root=''

        # ... support only minimal install
        minimal_install=1
    }

    local host subdir url
    local _releasemin=255

    # $releasever
    releasever_orig="$releasever"
    if [ -z "$releasever" ]; then
        # Default Fedora version is latest
        releasever=32
        releasemaj=32
    else
        releasemaj="${releasever%%.*}"

        [ $releasemaj -ge 10 ] ||
            fatal 'no support for Fedora before 10 (Fedora Core?)'
    fi
    releasemin=${_releasemin}

    # $subdir
    subdir='fedora/linux'
    case "$basearch" in
        'i386')
            # Pick Fedora 30, which is last with i386 support,
            # unless default release version is older.
            if [ $releasemaj -gt 30 ]; then
                releasever=30
                releasemaj=30
            fi
            # Starting from Fedora 26 i386 becomes secondary
            [ $releasemaj -le 25 ] || subdir='fedora-secondary'
            ;;
        # Add more secondary architectures here.
        # Note that supported set varies between releases.
    esac

    # $baseurl, $updatesurl
    release_url()
    {
        local subdir="${subdir:+$subdir/}"

        local templ='http://%s.fedoraproject.org/pub/%s%s/%s/%s'
        local base updates

        base="$(
            arch="Everything/$arch/os"

            printf -- "$templ" \
                "$host" "$subdir" 'releases' "$releasever" "$arch"
        )"
        [ -n "$base" ] &&
            curl -L -f -s -o /dev/null "$base" &&
        echo "baseurl='$base'" || return

        updates="$(
            [ $releasever -le 27 ] || arch="Everything/$arch"

            printf -- "$templ" \
                "$host" "$subdir" 'updates'  "$releasever" "$arch"
        )"
        [ "$base" != "$updates" ] &&
            curl -L -f -s -o /dev/null "$updates" &&
        echo "updatesurl='$updates'" ||:
    }
      if url="$(host='dl' release_url)"; then
        # Current
        is_archive=''
    elif url="$(host='archives' subdir="archive/$subdir" release_url)"; then
        # Archive
        is_archive='1'
    else
        fatal "Fedora $releasever isn't available for download"
    fi
    eval "$url"

    # No country/continent mirrors
    cc=''

    # No EPEL repository
    repo_epel=''
    # No external repositories
    distro_disable_extra_repos

    [ $releasemaj -lt 24 ] || has_glibc_langpack=1

    # yum(1) supports --nogpgcheck
    nogpgcheck='--nogpgcheck'

    # Additional packages that are (not) in @core package group
    PKGS="${PKGS:+$PKGS }cronie rsyslog chrony"
    PKGS="${PKGS:+$PKGS }postfix logrotate sudo"
}

distro_${distro}

if [ -n "$has_glibc_langpack" ]; then
    # Language packages
    eval $(
        set -- $(IFS=':' && echo ${install_langs:-en})

        f=''
        while [ $# -gt 0 ]; do
            if [ -n "$1" ]; then
                f="${f:+$f }glibc-langpack-$1"
            fi
            shift
        done

        echo "f='$f'"
    )
    PKGS="${PKGS:+$PKGS }$f" && unset f
fi

# Pick repo names on host to configure and use for initial setup
eval $(
    yum --noplugins -C repolist | \
    sed -n -e '2,$ s,^\W\?\(\w\+\).*$,\1,p' | \
    sed -n -e '1 s,.\+,baserepo=\0,p' \
           -e '2 s,.\+,updatesrepo=\0,p'
)
[ -n "${baserepo-}" ] || baseurl=''
[ -n "${updatesrepo-}" ] || updatesurl=''

# Initial setup
setarch "$basearch" \
yum -y \
    ${releasemaj:+
        --releasever=$releasemaj
     } \
    ${baseurl:+
        --nogpgcheck
        --disablerepo='*'
        --enablerepo="$baserepo"
        --setopt="$baserepo.mirrorlist=file:///dev/null"
        --setopt="$baserepo.baseurl=$baseurl"
        ${updatesurl:+
            --enablerepo="$updatesrepo"
            --setopt="$updatesrepo.mirrorlist=file:///dev/null"
            --setopt="$updatesrepo.baseurl=$updatesurl"
         }
     } \
    ${install_langs:+
        --setopt="override_install_langs=$install_langs"
     } \
    ${nodocs:+
        --setopt='tsflags=nodocs'
     } \
    --installroot="$install_root" \
    \
    --exclude='*firmware*' \
    --exclude='alsa*' \
    --exclude='libertas*' \
    --exclude='microcode_ctl' \
    --exclude='grub2-pc*' --exclude='grub2-efi*' \
    --exclude='NetworkManager*' \
    --exclude='teamd' \
    --exclude='tuned' \
    --exclude='firewalld' \
    --exclude='parted' \
    --exclude='kexec-tools' \
    --exclude='btrfs-progs' \
    --exclude='xfsprogs' \
    --exclude='sg3_utils' \
    --exclude='iprutils' \
    --exclude='sssd-*' \
    \
    install '@core' \
    ${PKGS-} \
    #

if [ -n "${install_root%/}" ]; then
    # Convert rpmdb(1) from host to target format
    {
        t="$install_root/var/lib/rpm"
        find "$t" ! -name 'Packages' -a -type f -a -exec rm -f {} \+

        t="$t/Packages" && f="$t.bak"
        mv -f "$t" "$f"

        /usr/lib/rpm/rpmdb_dump "$f"

        rm -f "$f"
    } | {
        in_chroot_exec "$install_root" '
            cd /var/lib/rpm &&
            /usr/lib/rpm/rpmdb_load Packages &&
            rpm --rebuilddb
        '
    }
fi

# Perform distro specific actions post initial setup
distro_post_core_hook

# $nfs_root

if [ -n "$nfs_root" ]; then
    # Set SELinux to permissive
    [ -z "$readonly_root" ] || selinux='permissive'

    # Need dracut
    pkg_dracut=1
    # Need to include most (all?) of network device drivers
    pkg_dracut_config_generic=1
    # Need network support (including nfs) in dracut
    pkg_dracut_network=1
    # Needed by dracut nfs module
    pkg_nfs_utils=1
    # No bootloader(s)
    pkg_shim=0
    pkg_grub2=0
    # Kernel(s)
    pkg_kernel=1
    # Kernel utils
    pkg_kdump=0
    pkg_dkms=0
    # Mount /tmp as tmpfs
    tmp_mount=${tmp_mount:-1}
    # Set nameserver(s)
    nameservers="${nameservers:-${_nameservers}}"

    # Add "nfs" dracut module (from dracut-network package)
    echo 'add_dracutmodules+=" nfs "' \
        >"$install_root/etc/dracut.conf.d/01-nfs.conf"

    # No minimal install as we need at least dracut modules and nfs-utils
    minimal_install=''
fi

# $selinux

if [ -n "$selinux" ]; then
    sed -i "$install_root/etc/selinux/config" \
        -e "s/^\(SELINUX=\)\w\+\(\s*\)$/\1$selinux\2/"
fi

# $readonly_root

if [ -n "$readonly_root" ]; then
    if centos_version_gt $releasemaj 7; then
        in_chroot "$install_root" 'yum -y install readonly-root'
    fi

    sed -i "$install_root/etc/sysconfig/readonly-root" \
        -e 's/^\(READONLY=\)\w\+\(\s*\)$/\1yes\2/' \
        #
fi

# $passwordless_root

if [ -n "$passwordless_root" ]; then
    in_chroot "$install_root" 'passwd -d root'
fi

# $autopassword_root

if [ -n "$autopassword_root" ]; then
    f="$install_root/usr/libexec"
    install -d "$f"

    f="$f/autopass.sh.$$"
    cat >"$f" <<'_EOF'
#!/bin/sh

# Requires: tr(1), head(1), sed(1), chpasswd(1)

# Usage: pwmake [<length>] [<f_pw_ambiguous>]
pwmake()
{
    # From pwgen/pw_rand.c
    local pw_ambiguous='B8G6I1l0OQDS5Z2'

    eval "
        tr -dc '0-9a-zA-Z' </dev/urandom 2>/dev/null |
        ${2:+tr -d "$pw_ambiguous" 2>/dev/null |}
        head -c '${1:-16}'
    "
    echo
}

# Usage: autopass.sh [<user>] [<passlen>] [<ambiguous>]

user="${1:-root}"
password="$(pwmake ${2:-8} ${3-})"

chpasswd <<EOF
$user:$password
EOF

cat >>'/etc/issue' <<EOF
Login as $user using $password password.

EOF

exit 0
_EOF
    # install(1) sets executable bits
    install -D "$f" "${f%.*}"
    rm -f "$f" ||:

    f="$install_root/etc/sysconfig"
    install -d "$f"

    f="$f/autopass"
    cat >"$f" <<'_EOF'

# Service configures specified $USER account with autogenerated password
# using /dev/urandom data and matched [0-9a-zA-Z]{$PASSLEN} extended
# regular expression pattern, optionally excluding ambiguous characters
# matcheded by [B8G6I1l0OQDS5Z2] regular expression.
#
# Note that excluding ambiguous characters from autogenerated passwords
# reduces their quality. It might be desirable to increase $PASSLEN in
# that case from default 8 to 12 or greather.

# User name
# Default: root
#
USER=root

# Password length
# Default: 8
#
PASSLEN=12

# Exclude ambiguous characters
# Default: 
EXCLUDE_AMBIGUOUS=1
_EOF

    f="$install_root/etc/systemd/system"
    install -d "$f"

    f="$f/autopass.service"
    cat >"$f" <<'_EOF'
[Unit]
Description=Configure user account with autogenerated password
Conflicts=shutdown.target
After=systemd-user-sessions.service plymouth-quit-wait.service
After=rc-local.service rhel-readonly.service readonly-root.service
Before=getty.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/libexec/autopass.sh "$USER" "$PASSLEN" "$EXCLUDE_AMBIGUOUS"
Environment=USER=root
Environment=PASSLEN=8
EnvironmentFile=-/etc/sysconfig/autopass

[Install]
WantedBy=getty.target
_EOF
    in_chroot "$install_root" 'systemctl enable autopass.service'
fi

# $autorelabel

if [ -n "$autorelabel" ]; then
    echo : >"$install_root/.autorelabel"
fi

# $cc

if [ -n "$cc" ]; then
    for f in \
        "$install_root/etc/yum/vars/cc" \
        "$install_root/etc/dnf/vars/cc" \
        #
    do
        if [ -d "${f%/*}" ]; then
            [ -s "$f" ] || echo "$cc" >"$f"
            break
        fi
    done

    for f in "$install_root/etc/yum.repos.d"/*.repo; do
        if [ -f "$f" ]; then
            sed -i "$f" \
                -e '/^mirrorlist=.\+\/\?[^=]\+=[^=]*/!b' \
                -e '/&cc=.\+/b' \
                -e 's/.\+/\0\&cc=$cc/' \
                #
        fi
    done

    unset f

    in_chroot "$install_root" 'yum -y update'
fi

## Minimal install

if [ -n "${minimal_install-}" ]; then
    exit 0
fi

## Release specific tricks

if centos_version_gt $releasemaj 7; then
    # Disable packages that not available in repositories for CentOS/RHEL 8+
    pkg_iucode_tool=

    pkg_lynx=
    pkg_elinks=
    pkg_links=

    pkg_btrfs_progs=
    pkg_whois=
    pkg_ntpdate=

    pkg_cups_x2go=

    pkg_thunar_archive_plugin=
    pkg_thunar_vcs_plugin=

    pkg_orage=
    pkg_xarchiver=

    pkg_mate=

    pkg_guake=
    pkg_gucharmap=

    # LightDM is broken in EPEL for CentOS/RHEL 8: try sddm
    # hxxps://forums.centos.org/viewtopic.php?t=72433
    [ -z "${pkg_lightdm-}" ] || pkg_sddm=1
    pkg_lightdm=

    pkg_libreoffice_nlpsolver=0
    pkg_libreoffice_officebean=0
    pkg_libreoffice_postgresql=0
    pkg_libreoffice_rhino=0

    # No qmmp in EPEL for CentOS/RHEL 8: try rhythmbox
    [ -z "${pkg_qmmp-}" ] || pkg_rhythmbox=1
    pkg_qmmp=

    pkg_putty=
    pkg_remmina=

    pkg_pidgin_otr=
    pkg_filezilla=
    pkg_codeblocks=

    pkg_nm_vpnc=
    pkg_nm_strongswan=

    pkg_vdpau_va_gl=
    pkg_va_utils=
    pkg_va_intel_hybrid_driver=
fi

## List of packages to install

PKGS=''

## Bootloader, kernel and utils

if [ -n "${pkg_dracut-}" ]; then
    PKGS="$PKGS dracut"

    # dracut-caps
    [ -z "${pkg_dracut_caps-}" ] || PKGS="$PKGS dracut-caps"
    # dracut-config-generic
    [ -z "${pkg_dracut_config_generic-}" ] || PKGS="$PKGS dracut-config-generic"
    # dracut-config-rescue
    [ -z "${pkg_dracut_config_rescue-}" ] || PKGS="$PKGS dracut-config-rescue"
    # dracut-fips
    [ -z "${pkg_dracut_fips-}" ] || PKGS="$PKGS dracut-fips"
    # dracut-fips-aesni
    [ -z "${pkg_dracut_fips_aesni-}" ] || PKGS="$PKGS dracut-fips-aesni"
    # dracut-network
    [ -z "${pkg_dracut_network-}" ] || PKGS="$PKGS dracut-network"
    # dracut-tools
    [ -z "${pkg_dracut_tools-}" ] || PKGS="$PKGS dracut-tools"
fi

if [ -n "${pkg_plymouth-}" ]; then
    PKGS="$PKGS plymouth"

    # plymouth-scripts
    [ -z "${pkg_plymouth_scripts-}" ] || PKGS="$PKGS plymouth-scripts"

    # plymouth-plugin-fade-throbber
    [ -z "${pkg_plymouth_plugin_fade_throbber-}" ] ||
        PKGS="$PKGS plymouth-plugin-fade-throbber"
    # plymouth-plugin-label
    [ -z "${pkg_plymouth_plugin_label-}" ] ||
        PKGS="$PKGS plymouth-plugin-label"
    # plymouth-plugin-script
    [ -z "${pkg_plymouth_plugin_script-}" ] ||
        PKGS="$PKGS plymouth-plugin-script"
    # plymouth-plugin-space-flares
    [ -z "${pkg_plymouth_plugin_space_flares-}" ] ||
        PKGS="$PKGS plymouth-plugin-space-flares"
    # plymouth-plugin-throbgress
    [ -z "${pkg_plymouth_plugin_throbgress-}" ] ||
        PKGS="$PKGS plymouth-plugin-throbgress"
    # plymouth-plugin-two-step
    [ -z "${pkg_plymouth_plugin_two_step-}" ] ||
        PKGS="$PKGS plymouth-plugin-two-step"

    # plymouth-system-theme
    [ -z "${pkg_plymouth_system_theme-}" ] ||
        PKGS="$PKGS plymouth-system-theme"
    # plymouth-theme-charge
    [ -z "${pkg_plymouth_theme_charge-}" ] ||
        PKGS="$PKGS plymouth-theme-charge"
    # plymouth-theme-fade-in
    [ -z "${pkg_plymouth_theme_fade_in-}" ] ||
        PKGS="$PKGS plymouth-theme-fade-in"
    # plymouth-theme-script
    [ -z "${pkg_plymouth_theme_script-}" ] ||
        PKGS="$PKGS plymouth-theme-script"
    # plymouth-theme-solar
    [ -z "${pkg_plymouth_theme_solar-}" ] ||
        PKGS="$PKGS plymouth-theme-solar"
    # plymouth-theme-spinfinity
    [ -z "${pkg_plymouth_theme_spinfinity-}" ] ||
        PKGS="$PKGS plymouth-theme-spinfinity"
    # plymouth-theme-spinner
    [ -z "${pkg_plymouth_theme_spinner-}" ] ||
        PKGS="$PKGS plymouth-theme-spinner"
fi

if [ -z "${grp_efi-}" ]; then
    if [ -z "${install_root%/}" ]; then
        # Autodetect EFI if $install_root is '/'
        if [ -d '/sys/firmware/efi' ]; then
            grp_efi=1
        fi
    fi
fi

if [ -n "${grp_efi-}" ]; then
    if [ -n "${grp_efi_ia32-}" ]; then
        grp_efi_ia32=1
        grp_efi_x64=
    else
        grp_efi_ia32=
        grp_efi_x64=1
    fi

    pkg_efibootmgr=1
    [ -z "${grp_efi_secureboot-}" ] || pkg_enable shim
else
    grp_efi=
    grp_efi_ia32=
    grp_efi_x64=
    grp_efi_secureboot=
fi

pkg_switch shim
if [ -n "${pkg_shim-}" ]; then
    if [ -n "$grp_efi_ia32" ]; then
        pkg_enable shim_ia32
        pkg_enable shim_unsigned_ia32
        pkg_switch shim_x64
        pkg_switch shim_unsigned_x64
    else
        pkg_switch shim_ia32
        pkg_switch shim_unsigned_ia32
        pkg_enable shim_x64
        pkg_enable shim_unsigned_x64
    fi

    # shim-ia32
    [ -z "${pkg_shim_ia32-}" ] || PKGS="$PKGS shim-ia32"
    # shim-x64
    [ -z "${pkg_shim_x64-}" ] || PKGS="$PKGS shim-x64"

    if centos_version_eq $releasemaj 7; then
        # shim-unsigned-ia32
        [ -z "${pkg_shim_unsigned_ia32-}" ] || PKGS="$PKGS shim-unsigned-ia32"
        # shim-unsigned-x64
        [ -z "${pkg_shim_unsigned_x64-}" ] || PKGS="$PKGS shim-unsigned-x64"
    fi
fi

pkg_switch grub2
if [ -n "${pkg_grub2-}" ]; then
    if [ -n "$grp_efi" ]; then
        if [ -n "$grp_efi_ia32" ]; then
            pkg_enable grub2_efi_ia32
            pkg_switch grub2_efi_x64
        else
            pkg_switch grub2_efi_ia32
            pkg_enable grub2_efi_x64
        fi
        pkg_switch grub2_pc
    else
        pkg_enable grub2_pc
        pkg_switch grub2_efi_ia32
        pkg_switch grub2_efi_x64
    fi

    # grub2-pc
    [ -z "${pkg_grub2_pc-}" ] || PKGS="$PKGS grub2-pc"
    # grub2-efi-ia32
    [ -z "${pkg_grub2_efi_ia32-}" ] || PKGS="$PKGS grub2-efi-ia32"
    # grub2-efi-x64
    [ -z "${pkg_grub2_efi_x64-}" ] || PKGS="$PKGS grub2-efi-x64"
fi

pkg_switch kernel
if [ -n "${pkg_kernel-}" ]; then
    PKGS="$PKGS kernel microcode_ctl"

    if fedora_version_le 12 || centos_version_lt 7; then
        PKGS="$PKGS kernel-firmware"
    else
        PKGS="$PKGS linux-firmware"
    fi

    ## /usr/lib/kernel/install.d/zz-symlink-to-root.install
    f="$install_root/usr/lib/kernel/install.d"
    install -d "$f"

    f="$f/zz-symlink-to-root.install.$$"
    cat >"$f" <<'_EOF'
#!/bin/sh

prog_name="${0##*/}"

t="${prog_name%.install}"
[ "$t" != "$prog_name" ] || exit 0
t="$t.sh"

COMMAND="$1"
KERNEL_VERSION="$2"
BOOT_DIR_ABS="$3"
KERNEL_IMAGE="$4"

[ -d "$BOOT_DIR_ABS" ] || BOOT_DIR_ABS='/boot'

KERNEL_IMAGE="$BOOT_DIR_ABS/vmlinuz-$KERNEL_VERSION"

case "$1" in
    add)
        t="/etc/kernel/postinst.d/$t"
        ;;
    remove)
        t="/etc/kernel/postrm.d/$t"
        ;;
    *)
        exit 0
        ;;
esac

[ ! -x "$t" ] || exec "$t" "$KERNEL_VERSION" "$KERNEL_IMAGE"
_EOF
    # install(1) sets executable bits
    install -D "$f" "${f%.*}"
    rm -f "$f" ||:

    ## /etc/kernel/postinst.d/zz-symlink-to-root.sh
    f="$install_root/etc/kernel/postinst.d"
    install -d "$f"

    f="$f/zz-symlink-to-root.sh.$$"
    cat >"$f" <<'_EOF'
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
_EOF
    # install(1) sets executable bits
    install -D "$f" "${f%.*}"
    rm -f "$f" ||:

    ## /etc/kernel/prerm.d/zz-symlink-to-root.sh
    f="$install_root/etc/kernel/prerm.d"
    install -d "$f"

    f="$f/zz-symlink-to-root.sh.$$"
    cat >"$f" <<'_EOF'
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
_EOF
    # install(1) sets executable bits
    install -D "$f" "${f%.*}"
    rm -f "$f" ||:

    if [ -n "$nfs_root" ]; then
        ## /usr/lib/kernel/install.d/zz-initrd-chmod-0644.install
        f="$install_root/usr/lib/kernel/install.d"
        install -d "$f"

        f="$f/zz-initrd-chmod-0644.install.$$"
        cat >"$f" <<'_EOF'
#!/bin/sh

prog_name="${0##*/}"

t="${prog_name%.install}"
[ "$t" != "$prog_name" ] || exit 0
t="$t.sh"

COMMAND="$1"
KERNEL_VERSION="$2"
BOOT_DIR_ABS="$3"
KERNEL_IMAGE="$4"

[ -d "$BOOT_DIR_ABS" ] || BOOT_DIR_ABS='/boot'

KERNEL_IMAGE="$BOOT_DIR_ABS/vmlinuz-$KERNEL_VERSION"

case "$1" in
    add)
        t="/etc/kernel/postinst.d/$t"
        ;;
    remove)
        t="/etc/kernel/postrm.d/$t"
        ;;
    *)
        exit 0
        ;;
esac

[ ! -x "$t" ] || exec "$t" "$KERNEL_VERSION" "$KERNEL_IMAGE"
_EOF
        # install(1) sets executable bits
        install -D "$f" "${f%.*}"
        rm -f "$f" ||:

        ## /etc/kernel/postinst.d/zz-initrd-chmod-0644.sh
        f="$install_root/etc/kernel/postinst.d"
        install -d "$f"

        f="$f/zz-initrd-chmod-0644.sh.$$"
        cat >"$f" <<'_EOF'
#!/bin/sh

export LANG=C

KERNEL_VERSION="${1:?missing KERNEL_VERSION}"
KERNEL_IMAGE="${2:?missing KERNEL_IMAGE}"

INITRD_IMAGE="${KERNEL_IMAGE%/*}/initramfs-${KERNEL_VERSION}.img"

chmod 0644 "$INITRD_IMAGE"
_EOF
        # install(1) sets executable bits
        install -D "$f" "${f%.*}"
        rm -f "$f" ||:
    fi # [ -n "$nfs_root" ]

    unset f

    # kexec-tools
    pkg_switch kdump
    [ -z "${pkg_kdump-}" ] || PKGS="$PKGS kexec-tools"
    # dkms
    pkg_switch dkms
    if is_fedora || [ -n "$repo_epel" ]; then
        [ -z "${pkg_dkms-}" ] || PKGS="$PKGS dkms kernel-devel"
    fi
else
    pkg_kdump=
    pkg_dkms=
fi

[ -z "${pkg_iucode_tool-}" ] || PKGS="$PKGS iucode-tool"
[ -z "${pkg_efibootmgr-}" ] || PKGS="$PKGS efibootmgr"

[ -z "${pkg_ipxe_bootimgs-}" ] || PKGS="$PKGS ipxe-bootimgs"
[ -z "${pkg_memtest86-}" ] || PKGS="$PKGS memtest86+"

## Shell helpers and text editors

if [ -n "${pkg_bash-}" ]; then
    PKGS="$PKGS bash"

    # bash-completion
    [ -z "${pkg_bash_completion-}" ] || PKGS="$PKGS bash-completion"
fi

if [ -n "${pkg_zsh-}" ]; then
    PKGS="$PKGS zsh"

    # zsh-syntax-highlighting
    [ -n "${pkg_zsh_syntax_highlighting-}" ] ||
        PKGS="$PKGS zsh-syntax-highlighting"
fi

if is_fedora || [ -n "$repo_epel" ]; then
    [ -z "${pkg_dash-}" ] || PKGS="$PKGS dash"
fi

[ -z "${pkg_mksh-}" ] || PKGS="$PKGS mksh"

[ -z "${pkg_psmisc-}" ] || PKGS="$PKGS psmisc"

[ -z "${pkg_file-}" ] || PKGS="$PKGS file"
[ -z "${pkg_dos2unix-}" ] || PKGS="$PKGS dos2unix"
[ -z "${pkg_bc-}" ] || PKGS="$PKGS bc"

[ -z "${pkg_minicom-}" ] || PKGS="$PKGS minicom"

[ -z "${pkg_lftp-}" ] || PKGS="$PKGS lftp"
[ -z "${pkg_tftp-}" ] || PKGS="$PKGS tftp"

[ -z "${pkg_lynx-}" ] || PKGS="$PKGS lynx"
[ -z "${pkg_mutt-}" ] || PKGS="$PKGS mutt"

if is_fedora || [ -n "$repo_epel" ]; then
    # elinks
    [ -z "${pkg_elinks-}" ] || PKGS="$PKGS elinks"
    # links
    [ -z "${pkg_links-}" ] || PKGS="$PKGS links"

    # pwgen
    [ -z "${pkg_pwgen-}" ] || PKGS="$PKGS pwgen"

    # pbzip2
    [ -z "${pkg_pbzip2-}" ] || PKGS="$PKGS pbzip2"
    # pigz
    [ -z "${pkg_pigz-}" ] || PKGS="$PKGS pigz"

    # p7zip
    [ -z "${pkg_p7zip-}" ] || PKGS="$PKGS p7zip p7zip-plugins"
fi

[ -z "${pkg_zip-}" ] || PKGS="$PKGS zip"

[ -z "${pkg_unzip-}" ] || PKGS="$PKGS unzip"

[ -z "${pkg_mc-}" ] || PKGS="$PKGS mc"

[ -z "${pkg_tmux-}" ] || PKGS="$PKGS tmux"

if is_fedora || [ -n "$repo_epel" ] ||
   centos_version_le $releasemaj 7
then
    # screen
    [ -z "${pkg_screen-}" ] || PKGS="$PKGS screen"
fi

[ -z "${pkg_gpm-}" ] || PKGS="$PKGS gpm"

[ -z "${pkg_nano-}" ] || PKGS="$PKGS nano"
[ -z "${pkg_vim_enhanced-}" ] || PKGS="$PKGS vim-enhanced"

## Hardware/system/network monitoring tools

[ -z "${pkg_sysfsutils-}" ] || PKGS="$PKGS sysfsutils"
[ -z "${pkg_numactl-}" ] || PKGS="$PKGS numactl"
[ -z "${pkg_driverctl-}" ] || PKGS="$PKGS driverctl"

[ -z "${pkg_lshw-}" ] || PKGS="$PKGS lshw"
[ -z "${pkg_pciutils-}" ] || PKGS="$PKGS pciutils"
[ -z "${pkg_usbutils-}" ] || PKGS="$PKGS usbutils"
[ -z "${pkg_dmidecode-}" ] || PKGS="$PKGS dmidecode"

[ -z "${pkg_tuned-}" ] || PKGS="$PKGS tuned"
[ -z "${pkg_irqbalance-}" ] || PKGS="$PKGS irqbalance"
[ -z "${pkg_numad-}" ] || PKGS="$PKGS numad"

[ -z "${pkg_mcelog-}" ] || PKGS="$PKGS mcelog"
[ -z "${pkg_lm_sensors-}" ] || PKGS="$PKGS lm_sensors"

[ -z "${pkg_iotop-}" ] || PKGS="$PKGS iotop"

if is_fedora || [ -n "$repo_epel" ]; then
    # atop
    [ -z "${pkg_atop-}" ]  || PKGS="$PKGS atop"
    # htop
    [ -z "${pkg_htop-}" ]  || PKGS="$PKGS htop"
    # iftop
    [ -z "${pkg_iftop-}" ] || PKGS="$PKGS iftop"
fi

## Debug

[ -z "${pkg_crash-}" ] || PKGS="$PKGS crash"
[ -z "${pkg_gdb-}" ] || PKGS="$PKGS gdb"
[ -z "${pkg_gdbserver-}" ] || PKGS="$PKGS gdb-gdbserver"
[ -z "${pkg_lsof-}" ] || PKGS="$PKGS lsof"
[ -z "${pkg_strace-}" ] || PKGS="$PKGS strace"

## Block utils

if [ -n "${grp_block_utils-}" ]; then
    # sg3_utils
    [ -z "${pkg_sg3_utils-}" ] || PKGS="$PKGS sg3_utils"
    # lsscsi
    [ -z "${pkg_lsscsi-}" ] || PKGS="$PKGS lsscsi"

    # hdparm
    [ -z "${pkg_hdparm-}" ] || PKGS="$PKGS hdparm"
    # sdparm
    [ -z "${pkg_sdparm-}" ] || PKGS="$PKGS sdparm"

    # parted
    [ -z "${pkg_parted-}" ] || PKGS="$PKGS parted"
    # gdisk
    [ -z "${pkg_gdisk-}" ] || PKGS="$PKGS gdisk"

    # iscsi-initiator-utils
    [ -z "${pkg_iscsi_initiator-}" ] || PKGS="$PKGS iscsi-initiator-utils"
    # device-mapper-multipath
    [ -z "${pkg_dm_mpath-}" ] || PKGS="$PKGS device-mapper-multipath"
    # mdadm
    [ -z "${pkg_mdadm-}" ] || PKGS="$PKGS mdadm"
    # lvm2
    [ -z "${pkg_lvm2-}" ] || PKGS="$PKGS lvm2"
    # cryptsetup
    [ -z "${pkg_cryptsetup-}" ] || PKGS="$PKGS cryptsetup"

    # vdo (Virtual Data Optimizer)
    [ -z "${pkg_vdo-}" ] || PKGS="$PKGS kvdo vdo"

    # storaged (udisks2)
    if [ -n "${pkg_storaged-}" ]; then
        PKGS="$PKGS storaged"

        # storaged-iscsi
        [ -z "${pkg_iscsi_initiator-}" -o -z "${pkg_storaged_iscsi-}" ] ||
            PKGS="$PKGS storaged-iscsi"
        # storaged-lvm2
        [ -z "${pkg_lvm2-}" -o -z "${pkg_storaged_lvm2-}" ] ||
            PKGS="$PKGS storaged-lvm2"
    fi

    # blktrace
    [ -z "${pkg_blktrace-}" ] || PKGS="$PKGS blktrace"
fi # [ -n "${grp_block_utils-}" ]

# Filesystem utils

if is_fedora || [ -n "$repo_epel" ]; then
    [ -z "${pkg_ntfs_3g-}" ] || PKGS="$PKGS ntfs-3g"
fi

[ -z "${pkg_ntfsprogs-}" ] || PKGS="$PKGS ntfsprogs"
[ -z "${pkg_xfsprogs-}" ] || PKGS="$PKGS xfsprogs"
[ -z "${pkg_btrfs_progs-}" ] || PKGS="$PKGS btrfs-progs"
[ -z "${pkg_dosfstools-}" ] || PKGS="$PKGS dosfstools"
[ -z "${pkg_nfs_utils-}" ] || PKGS="$PKGS nfs-utils"
[ -z "${pkg_quota-}" ] || PKGS="$PKGS quota"

## Network utils

[ -z "${pkg_net_tools-}" ] || PKGS="$PKGS net-tools"
[ -z "${pkg_ethtool-}" ] || PKGS="$PKGS ethtool"

[ -z "${pkg_tcpdump-}" ] || PKGS="$PKGS tcpdump"

[ -z "${pkg_mtr-}" ] || PKGS="$PKGS mtr"
[ -z "${pkg_traceroute-}" ] || PKGS="$PKGS traceroute"

[ -z "${pkg_telnet-}" ] || PKGS="$PKGS telnet"
[ -z "${pkg_netcat-}" ] || PKGS="$PKGS nmap-ncat"

[ -z "${pkg_nmap-}" ] || PKGS="$PKGS nmap"

[ -z "${pkg_whois-}" ] || PKGS="$PKGS whois"

[ -z "${pkg_curl-}" ] || PKGS="$PKGS curl"
[ -z "${pkg_wget-}" ] || PKGS="$PKGS wget"
[ -z "${pkg_rsync-}" ] || PKGS="$PKGS rsync"

if is_fedora || [ -n "$repo_epel" ]; then
    # hping3
    [ -z "${pkg_hping3-}" ] || PKGS="$PKGS hping3"
    # bind-utils
    [ -z "${pkg_bind_utils-}" ] || PKGS="$PKGS bind-utils"
fi

[ -z "${pkg_ntpdate-}" ] || PKGS="$PKGS ntpdate"

[ -z "${pkg_dpdk-}" ] || PKGS="$PKGS dpdk"

[ -z "${pkg_wpa_supplicant-}" ] || PKGS="$PKGS wpa_supplicant"
[ -z "${pkg_usb_modeswitch-}" ] || PKGS="$PKGS usb_modeswitch"

## Firewall management utilities

[ -z "${pkg_firewalld-}" ] || PKGS="$PKGS firewalld"

[ -z "${pkg_nftables-}" ] || PKGS="$PKGS nftables"

[ -z "${pkg_iptables-}" ] || PKGS="$PKGS iptables-services"
[ -z "${pkg_ipset-}" ] || PKGS="$PKGS ipset-service"

[ -z "${pkg_ebtables-}" ] || PKGS="$PKGS ebtables"
[ -z "${pkg_arptables-}" ] || PKGS="$PKGS arptables"

[ -z "${pkg_conntrack_tools-}" ] || PKGS="$PKGS conntrack-tools"

## Virtualization

if [ -n "${grp_virt_host-}" ]; then
    # libvirt
    [ -z "${pkg_libvirt-}" ] || PKGS="$PKGS libvirt"

    # qemu-kvm
    if [ -n "${pkg_qemu_kvm-}" ]; then
        f=''
        if centos_version_eq $releasemaj 7; then
            [ -z "$repo_openstack" -a \
              -z "$repo_ovirt" -a \
              -z "$repo_advanced_virtualization" \
            ] || f='ev'
        fi

        if [ -n "$f" ]; then
            PKGS="$PKGS qemu-kvm-ev"
        else
            PKGS="$PKGS qemu-kvm"
        fi

        # virtio-win
        [ -z "$repo_virtio_win" -o -z "${pkg_virtio_win-}" ] ||
            PKGS="$PKGS virtio-win"

        # libvirt-daemon-kvm
        [ -z "${pkg_libvirt-}" ] || PKGS="$PKGS libvirt-daemon-kvm"
    else
        pkg_qemu_kvm=
    fi

    # qemu-xen
    if [ -n "${pkg_qemu_xen-}" ]; then
        if centos_version_le $releasemaj 7; then
            PKGS="$PKGS xen"

            # Install before any package from SIG
            in_chroot "$install_root" \
                'yum -y install centos-release-xen centos-release-xen-common' \
                #
            # Update repos data and possibly installed packages
            in_chroot "$install_root" 'yum -y update'

            # libvirt-daemon-xen
            [ -z "${pkg_libvirt-}" ] || PKGS="$PKGS libvirt-daemon-xen"
        else
            # No XEN for CentOS/RHEL 8
            pkg_qemu_xen=
        fi
    else
        pkg_qemu_xen=
    fi

    if [ -n "$repo_openstack" -o -n "$repo_ovirt" ]; then
        if [ -n "${pkg_openvswitch-}" ]; then
            PKGS="$PKGS openvswitch"

            [ -z "${pkg_openvswitch_ipsec-}" ] || PKGS="$PKGS openvswitch-ipsec"
        fi
    fi
fi # [ -n "${grp_virt_host-}" ]

if [ -n "${grp_virt_guest-}" ]; then
    [ -z "${pkg_open_vm_tools-}" ] || PKGS="$PKGS open-vm-tools"
    [ -z "${pkg_qemu_guest_agent-}" ] || PKGS="$PKGS qemu-guest-agent"
    [ -z "${pkg_spice_vdagent-}" ] || PKGS="$PKGS spice-vdagent"
fi # [ -n "${grp_virt_guest-}" ]

# virt-install
[ -z "${pkg_virt_install-}" ] || PKGS="$PKGS virt-install"
# virt-v2v
[ -z "${pkg_virt_v2v-}" ] || PKGS="$PKGS virt-v2v"

# cockpit
if [ -n "${pkg_cockpit-}" ]; then
    if centos_version_ge $releasemaj 7; then
        PKGS="$PKGS cockpit"

        # cockpit-machines
        [ -z "${pkg_cockpit_machines-}" ] ||
            PKGS="$PKGS cockpit-machines"
        # cockpit-machines-ovirt
        [ -z "${pkg_cockpit_machines_ovirt-}" ] ||
            PKGS="$PKGS cockpit-machines-ovirt"
        # cockpit-packagekit
        [ -z "${pkg_cockpit_packagekit-}" ] ||
            PKGS="$PKGS cockpit-packagekit"
        # cockpit-storaged
        if [ -n "${grp_block_utils-}" ]; then
            [ -z "${pkg_storaged-}" -o -z "${pkg_cockpit_storaged-}" ] ||
                PKGS="$PKGS cockpit-storaged"
        fi
        # cockpit-ovirt-dashboard
        if [ -n "$repo_ovirt" ]; then
            PKGS="$PKGS cockpit-ovirt-dashboard"
        fi
    fi
fi

if [ -n "${pkg_libguestfs-}" ]; then
    PKGS="$PKGS libguestfs libguestfs-tools libguestfs-tools-c"

    # libguestfs-bash-completion
    [ -z "${pkg_bash_completion-}" ] ||
    [ -z "${pkg_libguestfs_bash_completion-}" ] ||
         PKGS="$PKGS libguestfs-bash-completion"

    # libguestfs-gfs2
    [ -z "${pkg_libguestfs_gfs2-}" ] || PKGS="$PKGS libguestfs-gfs2"
    # libguestfs-xfs
    [ -z "${pkg_libguestfs_xfs-}" ] || PKGS="$PKGS libguestfs-xfs"

    # libguestfs-rsync
    [ -z "${pkg_libguestfs_rsync-}" ] || PKGS="$PKGS libguestfs-rsync"

    # libguestfs-rescue
    [ -z "${pkg_libguestfs_rescue-}" ] || PKGS="$PKGS libguestfs-rescue"
    # libguestfs-winsupport
    [ -z "${pkg_libguestfs_winsupport-}" ] || PKGS="$PKGS libguestfs-winsupport"
fi

## Xfce

if is_centos && [ -z "$repo_epel" ]; then
    # No Xfce when EPEL disabled
    pkg_xfce=
fi

if [ -n "${pkg_xfce-}" ]; then
    PKGS="$PKGS
        xfce4-panel
        xfce4-session
        xfce4-settings

        xfconf
        xfdashboard
        xfdesktop

        xfce-polkit

        xfwm4

        xfce4-appfinder
        xfce4-power-manager
        xfce4-about
        xfce4-taskmanager
        xfce4-terminal
        xfce4-screensaver
        xfce4-screenshooter
        xfce4-notifyd
    "

    if [ -n "${pkg_thunar-}" ]; then
        PKGS="$PKGS Thunar"

        # thunar-archive-plugin
        [ -z "${pkg_thunar_archive_plugin-}" ] ||
            PKGS="$PKGS thunar-archive-plugin"
        # thunar-vcs-plugin
        [ -z "${pkg_thunar_vcs_plugin-}" ] ||
            PKGS="$PKGS thunar-vcs-plugin"
        # thunar-volman
        [ -z "${pkg_thunar_volman-}" ] || PKGS="$PKGS thunar-volman"
    fi

    # atril/evince
    if [ -n "${pkg_atril-}" ]; then
        if centos_version_le $releasemaj 7; then
            PKGS="$PKGS atril"
        else
            PKGS="$PKGS evince"
        fi
    fi
    # mousepad
    [ -z "${pkg_mousepad-}" ] || PKGS="$PKGS mousepad"
    # orage
    [ -z "${pkg_orage-}" ] || PKGS="$PKGS orage"
    # parole
    [ -z "${pkg_parole-}" ] || PKGS="$PKGS parole"
    # ristretto
    [ -z "${pkg_ristretto-}" ] || PKGS="$PKGS ristretto"
    # xarchiver
    [ -z "${pkg_xarchiver-}" ] || PKGS="$PKGS xarchiver"

    # xfce4-battery-plugin
    [ -z "${pkg_xfce_battery_plugin-}" ] ||
        PKGS="$PKGS xfce4-battery-plugin"
    # xfce4-datetime-plugin
    [ -z "${pkg_xfce_datetime_plugin-}" ] ||
        PKGS="$PKGS xfce4-datetime-plugin"
    # xfce4-diskperf-plugin
    [ -z "${pkg_xfce_diskperf_plugin-}" ] ||
        PKGS="$PKGS xfce4-diskperf-plugin"
    # xfce4-netload-plugin
    [ -z "${pkg_xfce_netload_plugin-}" ] ||
        PKGS="$PKGS xfce4-netload-plugin"
    # xfce4-pulseaudio-plugin
    [ -z "${pkg_xfce_pulseaudio_plugin-}" ] ||
        PKGS="$PKGS xfce4-pulseaudio-plugin"
    # xfce4-screenshooter-plugin
    [ -z "${pkg_xfce_screenshooter_plugin-}" ] ||
        PKGS="$PKGS xfce4-screenshooter-plugin"
    # xfce4-smartbookmark-plugin
    [ -z "${pkg_xfce_smartbookmark_plugin-}" ] ||
        PKGS="$PKGS xfce4-smartbookmark-plugin"
    # xfce4-systemload-plugin
    [ -z "${pkg_xfce_systemload_plugin-}" ] ||
        PKGS="$PKGS xfce4-systemload-plugin"
    # xfce4-time-out-plugin
    [ -z "${pkg_xfce_time_out_plugin-}" ] ||
        PKGS="$PKGS xfce4-time-out-plugin"
    # xfce4-weather-plugin
    [ -z "${pkg_xfce_weather_plugin-}" ] ||
        PKGS="$PKGS xfce4-weather-plugin"
    # xfce4-whiskermenu
    [ -z "${pkg_xfce_whiskermenu-}" ] ||
        PKGS="$PKGS xfce4-whiskermenu-plugin"

    has_de=1
    gtk_based_de=1
fi # [ -n "${pkg_xfce-}" ]

## MATE

if is_centos && [ -z "$repo_epel" ]; then
    # No MATE when EPEL disabled
    pkg_mate=
fi

if [ -n "${pkg_mate-}" ]; then
    PKGS="$PKGS
        mate-desktop
        mate-backgrounds
        mate-icon-theme
        mate-themes
        mate-utils

        mate-applets
        mate-calc
        mate-dictionary
        mate-media
        mate-menus-preferences-category-menu
        mate-power-manager
        mate-screensaver
        mate-screenshot
        mate-search-tool
        mate-settings-daemon
        mate-system-log
        mate-system-monitor
        mate-terminal
    "

    if [ -n "${pkg_caja-}" ]; then
        PKGS="$PKGS caja"

        # caja-image-converter
        [ -z "${pkg_caja_image_converter-}" ] || PKGS="$PKGS caja-image-converter"
        # caja-open-terminal
        [ -z "${pkg_caja_open_terminal-}" ] || PKGS="$PKGS caja-open-terminal"
        # caja-schemas
        [ -z "${pkg_caja_schemas-}" ] || PKGS="$PKGS caja-schemas"
        # caja-sendto
        [ -z "${pkg_caja_sendto-}" ] || PKGS="$PKGS caja-sendto"
    fi
    # atril
    [ -z "${pkg_atril-}" ] || PKGS="$PKGS atril"
    # atril-caja
    [ -z "${pkg_caja-}" -o -z "${pkg_atril-}" ] || PKGS="$PKGS atril-caja"
    # pluma
    [ -z "${pkg_pluma-}" ] || PKGS="$PKGS pluma"
    # eom
    [ -z "${pkg_eom-}" ] || PKGS="$PKGS eom"
    # engrampa
    [ -z "${pkg_engrampa-}" ] || PKGS="$PKGS engrampa"
    # seahorse
    [ -z "${pkg_seahorse-}" ] || PKGS="$PKGS seahorse"

    has_de=1
    gtk_based_de=1
fi # [ -n "${pkg_mate-}" ]

## Desktop Apps

if [ -n "${has_de-}" ]; then
    case "${x11_server-}" in
        'Xspice')
            # Will install xorg-x11-server-Xorg as dependency
            PKGS="$PKGS xorg-x11-server-Xspice"
            ;;
        'x2go')
            # x2goserver
            if is_fedora || [ -n "$repo_epel" ]; then
                PKGS="$PKGS x2goserver"

                # x2goserver-desktopsharing
                [ -z "${pkg_x2goserver_desktopsharing-}" ] ||
                    PKGS="$PKGS x2goserver-desktopsharing"
                # x2goserver-printing
                [ -z "${pkg_x2goserver_printing-}" ] ||
                    PKGS="$PKGS x2goserver-printing"
            else
                # No X11 server
                x11_server=
            fi
            ;;
        '')
            # No X11 server
            x11_server=
            ;;
        *)
            # Xorg
            x11_server='Xorg'
            PKGS="$PKGS xorg-x11-server-Xorg xorg-x11-drivers"
            ;;
    esac
    if [ -n "$x11_server" ]; then
        PKGS="$PKGS xorg-x11-utils"

        # xorg-x11-fonts-100dpi
        [ -z "${pkg_xorg_x11_fonts_100dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-100dpi"
        # xorg-x11-fonts-75dpi
        [ -z "${pkg_xorg_x11_fonts_75dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-75dpi"
        # xorg-x11-fonts-ISO8859-1-100dpi
        [ -z "${pkg_xorg_x11_fonts_ISO8859_1_100dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-ISO8859-1-100dpi"
        # xorg-x11-fonts-ISO8859-1-75dpi
        [ -z "${pkg_xorg_x11_fonts_ISO8859_1_75dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-ISO8859-1-75dpi"
        # xorg-x11-fonts-ISO8859-14-100dpi
        [ -z "${pkg_xorg_x11_fonts_ISO8859_14_100dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-ISO8859-14-100dpi"
        # xorg-x11-fonts-ISO8859-14-75dpi
        [ -z "${pkg_xorg_x11_fonts_ISO8859_14_75dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-ISO8859-14-75dpi"
        # xorg-x11-fonts-ISO8859-15-100dpi
        [ -z "${pkg_xorg_x11_fonts_ISO8859_15_100dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-ISO8859-15-100dpi"
        # xorg-x11-fonts-ISO8859-15-75dpi
        [ -z "${pkg_xorg_x11_fonts_ISO8859_15_75dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-ISO8859-15-75dpi"
        # xorg-x11-fonts-ISO8859-2-100dpi
        [ -z "${pkg_xorg_x11_fonts_ISO8859_2_100dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-ISO8859-2-100dpi"
        # xorg-x11-fonts-ISO8859-2-75dpi
        [ -z "${pkg_xorg_x11_fonts_ISO8859_2_75dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-ISO8859-2-75dpi"
        # xorg-x11-fonts-ISO8859-9-100dpi
        [ -z "${pkg_xorg_x11_fonts_ISO8859_9_100dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-ISO8859-9-100dpi"
        # xorg-x11-fonts-ISO8859-9-75dpi
        [ -z "${pkg_xorg_x11_fonts_ISO8859_9_75dpi-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-ISO8859-9-75dpi"

        # xorg-x11-fonts-Type1
        [ -z "${pkg_xorg_x11_fonts_Type1-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-Type1"

        # bitmap-fixed-fonts
        [ -z "${pkg_bitmap_fixed_fonts-}" ] ||
            PKGS="$PKGS bitmap-fixed-fonts"
        # xorg-x11-fonts-misc
        [ -z "${pkg_xorg_x11_fonts_misc-}" ] ||
            PKGS="$PKGS xorg-x11-fonts-misc"
    fi

    if is_fedora || [ -n "$repo_epel" ]; then
        # guake
        [ -z "${pkg_guake-}" ] || PKGS="$PKGS guake"

        if [ -n "${pkg_lightdm-}" ]; then
            # lightdm
            PKGS="$PKGS lightdm"

            # lightdm-gtk
            [ -z "${gtk_based_de-}" ] ||
                PKGS="$PKGS lightdm-gtk"
            # lightdm-kde
            [ -z "${kde_based_de-}" ] ||
                PKGS="$PKGS lightdm-kde"
            # slick-greeter
            [ -z "${pkg_slick_greeter-}" ] ||
                PKGS="$PKGS lightdm-settings slick-greeter"
            has_dm='lightdm'
        fi

        if [ -n "${pkg_sddm-}" ]; then
            # sddm
            PKGS="$PKGS sddm"
            has_dm='sddm'
        fi

        # chromium
        [ -z "${pkg_chromium-}" ] || PKGS="$PKGS chromium"
    fi
    # evolution
    [ -z "${pkg_evolution-}" ] || PKGS="$PKGS evolution"

    if [ -z "${has_dm-}" ]; then
        # gdm
        PKGS="$PKGS gdm"
        has_dm='gdm'
    fi

    # gucharmap
    [ -z "${pkg_gucharmap-}" ] || PKGS="$PKGS gucharmap"
    # network-manager-applet
    [ -z "${pkg_nm-}" -o -z "${gtk_based_de-}" ] ||
        PKGS="$PKGS network-manager-applet"

    # pinentry
    if [ -n "${gtk_based_de-}" ]; then
        PKGS="$PKGS pinentry-gtk"
    else
        PKGS="$PKGS pinentry-qt"
    fi

    # firefox
    [ -z "${pkg_firefox-}" ] || PKGS="$PKGS firefox"
    # thunderbird
    [ -z "${pkg_thunderbird-}" ] || PKGS="$PKGS thunderbird"

    # icedtea-web
    [ -z "${pkg_icedtea_web-}" ] || PKGS="$PKGS icedtea-web"

    if [ -n "${pkg_pidgin-}" ]; then
        # pidgin
        PKGS="$PKGS pidgin"
        if is_fedora || [ -n "$repo_epel" ]; then
            # pidgin-otr
            [ -z "${pkg_pidgin_otr-}" ] || PKGS="$PKGS pidgin-otr"
            # pidgin-hangouts
            [ -z "${pkg_pidgin_hangouts-}" ] || PKGS="$PKGS pidgin-hangouts"
        fi
    fi

    # libreoffice
    if [ -n "${pkg_libreoffice-}" ]; then
        # libreoffice-writer
        pkg_enable libreoffice_writer
        [ -z "${pkg_libreoffice_writer-}" ] ||
            PKGS="$PKGS libreoffice-writer"
        # libreoffice-calc
        pkg_enable libreoffice_calc
        [ -z "${pkg_libreoffice_calc-}" ] ||
            PKGS="$PKGS libreoffice-calc"
        # libreoffice-math
        pkg_enable libreoffice_math
        [ -z "${pkg_libreoffice_math-}" ] ||
            PKGS="$PKGS libreoffice-math"
        # libreoffice-draw
        pkg_enable libreoffice_draw
        [ -z "${pkg_libreoffice_draw-}" ] ||
            PKGS="$PKGS libreoffice-draw"
        # libreoffice-impress
        pkg_enable libreoffice_impress
        [ -z "${pkg_libreoffice_impress-}" ] ||
            PKGS="$PKGS libreoffice-impress"
        # libreoffice-wiki-publisher
        pkg_enable libreoffice_wiki_publisher
        [ -z "${pkg_libreoffice_wiki_publisher-}" ] ||
            PKGS="$PKGS libreoffice-wiki-publisher"

        if [ -n "${gtk_based_de-}" ]; then
            if centos_version_ge $releasever 7.4 ||
               centos_version_lt $releasever 8.3
            then
                # libreoffice-gtk2
                pkg_enable libreoffice_gtk2
                [ -z "${pkg_libreoffice_gtk2-}" ] ||
                    PKGS="$PKGS libreoffice-gtk2"
            fi
            if centos_version_ge $releasever 7.4; then
                # libreoffice-gtk3
                pkg_enable libreoffice_gtk3
                [ -z "${pkg_libreoffice_gtk3-}" ] ||
                    PKGS="$PKGS libreoffice-gtk3"
            fi
        fi

        # libreoffice-emailmerge
        pkg_enable libreoffice_emailmerge
        [ -z "${pkg_libreoffice_emailmerge-}" ] ||
            PKGS="$PKGS libreoffice-emailmerge"
        # libreoffice-pdfimport
        pkg_enable libreoffice_pdfimport
        [ -z "${pkg_libreoffice_pdfimport-}" ] ||
            PKGS="$PKGS libreoffice-pdfimport"
        # libreoffice-nlpsolver
        pkg_enable libreoffice_nlpsolver
        [ -z "${pkg_libreoffice_nlpsolver-}" ] ||
            PKGS="$PKGS libreoffice-nlpsolver"
        # libreoffice-officebean
        pkg_enable libreoffice_officebean
        [ -z "${pkg_libreoffice_officebean-}" ] ||
            PKGS="$PKGS libreoffice-officebean"
        # libreoffice-ogltrans
        pkg_enable libreoffice_ogltrans
        [ -z "${pkg_libreoffice_ogltrans-}" ] ||
            PKGS="$PKGS libreoffice-ogltrans"
        # libreoffice-postgresql
        pkg_enable libreoffice_postgresql
        [ -z "${pkg_libreoffice_postgresql-}" ] ||
            PKGS="$PKGS libreoffice-postgresql"
        # libreoffice-pyuno
        pkg_enable libreoffice_pyuno
        [ -z "${pkg_libreoffice_pyuno-}" ] ||
            PKGS="$PKGS libreoffice-pyuno"
        # libreoffice-rhino
        pkg_enable libreoffice_rhino
        [ -z "${pkg_libreoffice_rhino-}" ] ||
            PKGS="$PKGS libreoffice-rhino"

        # libreoffice-xsltfilter
        pkg_enable libreoffice_xsltfilter
        [ -z "${pkg_libreoffice_xsltfilter-}" ] ||
            PKGS="$PKGS libreoffice-xsltfilter"
        # libreoffice-filters
        pkg_enable libreoffice_filters
        [ -z "${pkg_libreoffice_filters-}" ] ||
            PKGS="$PKGS libreoffice-filters"
    fi # [ -n "${pkg_libreoffice-}" ]

    # gimp
    [ -z "${pkg_gimp-}" ] || PKGS="$PKGS gimp"

    if is_fedora || [ -n "$repo_epel" ]; then
        # qmmp
        [ -z "${pkg_qmmp-}" ] || PKGS="$PKGS qmmp"
        # rhythmbox
        [ -z "${pkg_rhythmbox-}" ] || PKGS="$PKGS rhythmbox"

        # vlc
        [ -z "$repo_rpm_fusion" -o -z "${pkg_vlc-}" ] ||
            PKGS="$PKGS vlc"

        # dia
        [ -z "${pkg_dia-}" ] || PKGS="$PKGS dia"

        # keepassx2/keepassxc
        if [ -n "${pkg_keepassx2-}" ]; then
            if centos_version_le $releasemaj 7; then
                PKGS="$PKGS keepassx2"
            elif is_centos || fedora_version_ge 26; then
                PKGS="$PKGS keepassxc"
            else
                PKGS="$PKGS keepassx"
            fi
        fi

        # putty
        [ -z "${pkg_putty-}" ] || PKGS="$PKGS putty"

        # x2goclient (qt)
        [ -z "${pkg_x2goclient-}" ] || PKGS="$PKGS x2goclient"
        # tigervnc
        [ -z "${pkg_tigervnc-}" ] || PKGS="$PKGS tigervnc"

        # remmina
        if [ -n "${pkg_remmina-}" ]; then
            PKGS="$PKGS remmina"

            # remmina-plugins-vnc
            [ -z "${pkg_remmina_plugins_vnc-}" ] || PKGS="$PKGS remmina-plugins-vnc"
            # remmina-plugins-rdp
            [ -z "${pkg_remmina_plugins_rdp-}" ] || PKGS="$PKGS remmina-plugins-rdp"
            # remmina-plugins-nx
            [ -z "${pkg_remmina_plugins_nx-}" ] || PKGS="$PKGS remmina-plugins-nx"
            # remmina-plugins-xdmcp
            [ -z "${pkg_remmina_plugins_xdmcp-}" ] || PKGS="$PKGS remmina-plugins-xdmcp"

            if [ -n "${gtk_based_de-}" ]; then
                # remmina-plugins-secret
                PKGS="$PKGS remmina-plugins-secret"
            fi
        fi

        # seamonkey
        [ -z "${pkg_seamonkey-}" ] || PKGS="$PKGS seamonkey"

        # filezilla
        [ -z "${pkg_filezilla-}" ] || PKGS="$PKGS filezilla"

        # transmission
        if [ -n "${pkg_transmission-}" ]; then
            PKGS="$PKGS transmission"

            if [ -n "${gtk_based_de-}" ]; then
                # transmission-gtk
                PKGS="$PKGS transmission-gtk"
            else
                # transmission-qt
                PKGS="$PKGS transmission-qt"
            fi
        fi

        # Development tools
        if [ -n "${grp_devel-}" ]; then
            # codeblocks
            [ -z "${pkg_codeblocks-}" ] || PKGS="$PKGS codeblocks"
            # meld
            [ -z "${pkg_meld-}" ] || PKGS="$PKGS meld"
        fi
    fi # is_fedora || [ -n "$repo_epel" ]

    # virt-manager
    [ -z "${pkg_virt_manager-}" ] || PKGS="$PKGS virt-manager"
    # virt-viewer
    [ -z "${pkg_virt_viewer-}" ] || PKGS="$PKGS virt-viewer"

    # wireshark
    if [ -n "${pkg_wireshark-}" ]; then
       PKGS="$PKGS wireshark"

       if is_fedora || centos_version_le $releasemaj 7; then
           # wireshark-gnome
           [ -z "${gtk_based_de-}" ] ||
               PKGS="$PKGS wireshark-gnome"
       fi
    fi
fi # [ -n "${has_de-}" ]

## ALSA

if [ -n "${pkg_alsa-}" ]; then
    PKGS="$PKGS alsa-utils"

    # alsa-firmware
    [ -z "${pkg_alsa_firmware-}" ] ||
        PKGS="$PKGS alsa-firmware alsa-tools-firmware"
    # alsa-plugins-pulseaudio
    [ -z "${pkg_pulseaudio-}" -o -z "${pkg_alsa_plugins_pulseaudio-}" ] ||
        PKGS="$PKGS alsa-plugins-pulseaudio"
fi

## PulseAudio

if [ -n "${pkg_pulseaudio-}" ]; then
    PKGS="$PKGS pulseaudio"

    # pulseaudio-module-x11
    [ -z "${x11_server-}" ] || PKGS="$PKGS pulseaudio-module-x11"
    # pulseaudio-module-bluetooth
    [ -z "${pkg_bluez-}" ] || PKGS="$PKGS pulseaudio-module-bluetooth"
fi

## CUPS

if [ -n "${pkg_cups-}" ]; then
    PKGS="$PKGS cups"

    # cups-ipptool
    [ -z "${pkg_cups_ipptool-}" ] || PKGS="$PKGS cups-ipptool"
    # cups-lpd
    [ -z "${pkg_cups_lpd-}" ] || PKGS="$PKGS cups-lpd"

    if is_fedora || [ -n "$repo_epel" ]; then
        # cups-pdf
        [ -z "${pkg_cups_pdf-}" ] || PKGS="$PKGS cups-pdf"

        if [ "$x11_server" = 'x2go' ]; then
            # cups-x2go
            [ -z "${pkg_x2goserver_printing-}" -o -z "${pkg_cups_x2go-}" ] ||
                PKGS="$PKGS cups-x2go"
        fi
    fi
fi

## Bluetooth

if [ -n "${pkg_bluez-}" ]; then
    PKGS="$PKGS bluez"

    # bluez-cups
    [ -z "${pkg_cups-}" -o -z "${pkg_bluez_cups-}" ] || PKGS="$PKGS bluez-cups"
    # bluez-hid2hci
    [ -z "${pkg_bluez_hid2hci-}" ] || PKGS="$PKGS bluez-hid2hci"
fi

## NetworkManager

if [ -n "${pkg_nm-}" ]; then
    PKGS="$PKGS NetworkManager"

    [ -z "${pkg_nm_tui-}" ]  || PKGS="$PKGS NetworkManager-tui"

    [ -z "${pkg_nm_team-}" ] || PKGS="$PKGS NetworkManager-team"
    [ -z "${pkg_nm_ovs-}" ] || PKGS="$PKGS NetworkManager-ovs"

    [ -z "${pkg_nm_adsl-}" ]  || PKGS="$PKGS NetworkManager-adsl"

    [ -z "${pkg_nm_wifi-}" ]  || PKGS="$PKGS NetworkManager-wifi"

    [ -z "${pkg_bluez-}" -o -z "${pkg_nm_bluez-}" ] ||
        PKGS="$PKGS NetworkManager-bluetooth"

    [ -z "${pkg_nm_wwan-}" ]  || PKGS="$PKGS NetworkManager-wwan"
    [ -z "${pkg_nm_modem-}" ] || PKGS="$PKGS ModemManager"

    [ -z "${pkg_nm_openvpn-}" ] || PKGS="$PKGS NetworkManager-openvpn"
    [ -z "${pkg_nm_ssh-}" ] || PKGS="$PKGS NetworkManager-ssh"

    [ -z "${pkg_nm_openconnect-}" ] || PKGS="$PKGS NetworkManager-openconnect"
    [ -z "${pkg_nm_vpnc-}" ] || PKGS="$PKGS NetworkManager-vpnc"

    [ -z "${pkg_nm_libreswan-}" ] || PKGS="$PKGS NetworkManager-libreswan"
    [ -z "${pkg_nm_strongswan-}" ] || PKGS="$PKGS NetworkManager-strongswan"

    [ -z "${pkg_nm_l2tp-}" ] || PKGS="$PKGS NetworkManager-l2tp"
    [ -z "${pkg_nm_pptp-}" ] || PKGS="$PKGS NetworkManager-pptp"

    if [ -n "${gtk_based_de-}" ]; then
        [ -z "${pkg_nm_openvpn-}" ] ||
            PKGS="$PKGS NetworkManager-openvpn-gnome"
        [ -z "${pkg_nm_ssh-}" ] ||
            PKGS="$PKGS NetworkManager-ssh-gnome"

        [ -z "${pkg_nm_openconnect-}" ] ||
            PKGS="$PKGS NetworkManager-openconnect-gnome"
        [ -z "${pkg_nm_vpnc-}" ] ||
            PKGS="$PKGS NetworkManager-vpnc-gnome"

        [ -z "${pkg_nm_libreswan-}" ] ||
            PKGS="$PKGS NetworkManager-libreswan-gnome"
        [ -z "${pkg_nm_openswan-}" ] ||
            PKGS="$PKGS NetworkManager-strongswan-gnome"

        [ -z "${pkg_nm_l2tp-}" ] ||
            PKGS="$PKGS NetworkManager-l2tp-gnome"
        [ -z "${pkg_nm_pptp-}" ] ||
            PKGS="$PKGS NetworkManager-pptp-gnome"
    fi # [ -n "${gtk_based_de-}" ]
else
    pkg_nm_adsl=

    pkg_nm_wifi=

    pkg_nm_bluez=

    pkg_nm_wwan=
    pkg_nm_modem=

    pkg_nm_openvpn=
    pkg_nm_ssh=

    pkg_nm_openconnect=
    pkg_nm_vpnc=

    pkg_nm_libreswan=
    pkg_nm_strongswan=

    pkg_nm_l2tp=
    pkg_nm_pptp=
fi # [ -n "${pkg_nm-}" ]

# network-scripts
if [ -n "${pkg_network_scripts-}" ]; then
    if centos_version_gt $releasemaj 7; then
        PKGS="$PKGS network-scripts"
    fi
fi

## Mesa

if [ -n "${pkg_mesa-}" ]; then
    PKGS="$PKGS mesa-dri-drivers"

    # glx-utils
    [ -z "${pkg_glx_utils-}" ] || PKGS="$PKGS glx-utils"
fi

## The GL Vendor-Neutral Dispatch library (GLVND)

if [ -n "${pkg_glvnd-}" ]; then
    PKGS="$PKGS libglvnd"

    # libglvnd-egl
    [ -z "${pkg_glvnd_egl-}" ] || PKGS="$PKGS libglvnd-egl"
    # libglvnd-gles
    [ -z "${pkg_glvnd_gles-}" ] || PKGS="$PKGS libglvnd-gles"
    # libglvnd-glx
    [ -z "${pkg_glvnd_glx-}" ] || PKGS="$PKGS libglvnd-glx"
fi

## Video Decode and Presentation API for UNIX (VDPAU)

if [ -n "${pkg_vdpau-}" ]; then
    PKGS="$PKGS libvdpau"

    # mesa-vdpau-drivers
    [ -z "${pkg_mesa-}" ] || PKGS="$PKGS mesa-vdpau-drivers"

    if [ -n "$repo_epel" ]; then
        # vdpauinfo
        [ -z "${pkg_vdpauinfo-}" ] || PKGS="$PKGS vdpauinfo"

        if [ -n "${pkg_glvnd_glx-}" ]; then
            # libvdpau-va-gl
            [ -z "${pkg_va-}" -o -z "${pkg_vdpau_va_gl-}" ] ||
                PKGS="$PKGS libvdpau-va-gl"
        fi
    fi
fi

## Video Acceleration API (VA)

if [ -n "${pkg_va-}" ]; then
    PKGS="$PKGS libva"

    if [ -n "$repo_epel" ]; then
        # libva-utils
        [ -z "${pkg_va_utils-}" ] || PKGS="$PKGS libva-utils"
        # libva-vdpau-driver
        [ -z "${pkg_vdpau-}" -o -z "${pkg_va_vdpau_driver-}" ] ||
            PKGS="$PKGS libva-vdpau-driver"
    fi

    if [ -n "$repo_epel" ]; then
        # libva-intel-hybrid-driver
        [ -z "${pkg_va_intel_hybrid_driver-}" ] ||
            PKGS="$PKGS libva-intel-hybrid-driver"
    fi
fi

## Install selected packages

for f in $PKGS; do
    echo "$f"
done | setarch $basearch xargs chroot "$install_root" yum -y install

exit 0
