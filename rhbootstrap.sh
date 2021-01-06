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
#           uname(1), mount(8), umount(8), setarch(8), chmod(1), mktemp(1),
#           base64(1)

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

# Usage: has_enable <var>
has_enable()
{
    local rc=$?

    local func="${FUNCNAME:-has_enable}"

    local var="${1:?missing 1st arg to ${func}() <var>}"

    var="has_${var#has_}"
    eval "$var=\$((\${$var-0} + 1)) && [ "\$$var" -gt 0 ] || $var=''"

    return $rc
}

# Usage: has_disable <var>
has_disable()
{
    local rc=$?

    local func="${FUNCNAME:-has_disable}"

    local var="${1:?missing 1st arg to ${func}() <var>}"

    var="has_${var#has_}"
    eval "$var=\$((\${$var-0} - 1)) && [ "\$$var" -gt 0 ] || $var=''"

    return $rc
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

# Usage: host_gpg_import <gpgkey>
host_gpg_import()
{
    local func="${FUNCNAME:-host_gpg_import}"

    local gpgkey="${1:?missing 1st arg to ${func}() <gpgkey>}"
    gpgkey="$rpm_gpg_dir/${gpgkey#$rpm_gpg_dir/}"

    setarch "$basearch" \
        rpm --root="$install_root" \
            --import "$gpgkey" ||
    return
}

# Usage: in_chroot_gpg_import <gpgkey>
in_chroot_gpg_import()
{
    local func="${FUNCNAME:-in_chroot_gpg_import}"

    local gpgkey="${1:?missing 1st arg to ${func}() <gpgkey>}"
    gpgkey="$rpm_gpg_dir/${gpgkey#$rpm_gpg_dir/}"

    in_chroot <"$gpgkey" "$install_root" "rpm --import '/dev/stdin'" || return
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
repo_rpmfusion=''

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
            repo_rpmfusion=''
            ;;
        --repo-rpm-fusion)
            repo_rpmfusion=1
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

        # Usage: make_xdg_dirs <homedir>
        make_xdg_dirs()
        {
            local d="$1"

            if [ -d "$d" ]; then
                install -d \
                    "$d/.local" "$d/.local/share" "$d/.local/bin" \
                    "$d/.cache" "$d/.config" \
                    #
                install -d -m 0700 \
                    "$d/.ssh" \
                    "$d/tmp" \
                    #
                ln -sf '.local/bin' "$d/bin"
            fi
        }

        # /root
        t="$(in_chroot_exec "$install_root" 't=~root; echo "t='\''$t'\''"')"
        eval "$t" && t="$install_root/$t"

        make_xdg_dirs "$t"
        mc_ini "$t"
        screenrc "$t"
        ssh_agent_start4bashrc "$t"

        # /etc/skel
        t="$install_root/etc/skel"

        make_xdg_dirs "$t"
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
                    grub2-mkconfig -o "$(readlink -f /etc/grub2.cfg)"
                 [ ! -L /etc/grub2-efi.cfg ] ||
                    grub2-mkconfig -o "$(readlink -f /etc/grub2-efi.cfg)"
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

    if [ -n "${rpm_gpg_dir-}" ]; then
        rm -rf "$rpm_gpg_dir" ||:
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
# current or archive version
is_archive=''
# has specific feature
has_glibc_langpack=''
has_repo=''
has_epel=''

# Usage: distro_disable_extra_repos
distro_disable_extra_repos()
{
    # Except EPEL
    repo_virtio_win=''
    repo_advanced_virtualization=''
    repo_openstack=''
    repo_ovirt=''
    repo_elrepo=''
    repo_rpmfusion=''
}

# Usage: distro_centos
distro_centos()
{
    # Usage: distro_post_core_hook
    distro_post_core_hook()
    {
        local releasemin
        local yum_update=''

        # Determine actually installed version (e.g. 8 -> 8.3)
        releasever="$(
            sed -n \
                -e '1 s/^CentOS\s\+.\+\s\+\([0-9]\+\.[0-9]\+\).*$/\1/p' \
                '/etc/centos-release' \
                #
        )"
        releasemaj="${releasever%.*}"
        releasemin="${releasever#*.}"

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
                yum_update=1
            fi
        fi

        local EPEL_URL EPEL_RELEASE_RPM EPEL_RELEASE_URL
        local ELREPO_URL ELREPO_RELEASE_RPM ELREPO_RELEASE_URL
        local ADVANCED_VIRTUALIZATION_RELEASE_RPM
        local OPENSTACK_RELEASE_RPM
        local OVIRT_RELEASE_RPM
        local RPMFUSION_URL RPMFUSION_RELEASE_RPM RPMFUSION_RELEASE_URL
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
            RPMFUSION_URL='https://download1.rpmfusion.org/free/el'
            RPMFUSION_RELEASE_RPM='rpmfusion-free-release-8.noarch.rpm'
            RPMFUSION_RELEASE_URL="$RPMFUSION_URL/$RPMFUSION_RELEASE_RPM"
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
            RPMFUSION_URL='https://download1.rpmfusion.org/free/el'
            RPMFUSION_RELEASE_RPM='rpmfusion-free-release-7.noarch.rpm'
            RPMFUSION_RELEASE_URL="$RPMFUSION_URL/$RPMFUSION_RELEASE_RPM"
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

        # $repo_epel, $repo_rpmfusion
        if [ -n "$repo_rpmfusion" ]; then
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

            in_chroot <"$rpm_gpg_dir/epel/RPM-GPG-KEY-EPEL-$releasemaj" \
                "$install_root" \
                "rpm --import '/dev/stdin' && rpm -i '$EPEL_RELEASE_URL'" \
            && has_enable 'repo' || repo_epel=''

            if [ -n "$repo_epel" ]; then
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
                    # Backup /etc/yum.conf since yum(1) from EPEL doesn't have it
                    local t="$install_root/etc/yum.conf"
                    ln -nf "$t" "$t.rpmorig" ||:
                fi

                has_epel=1
            fi
        fi

        # ELRepo
        if [ -n "$repo_elrepo" ]; then
            in_chroot <"$rpm_gpg_dir/elrepo/RPM-GPG-KEY-elrepo.org" \
                "$install_root" \
                "rpm --import '/dev/stdin' && rpm -i '$ELREPO_RELEASE_URL'" \
            && has_enable 'repo' || repo_elrepo=''
        fi

        # VirtIO-Win
        if [ -n "$repo_virtio_win" ]; then
            curl -s -o "$install_root/etc/yum.repos.d/virtio-win.repo" \
                "$VIRTIO_WIN_URL" \
            && has_enable 'repo' || repo_virtio_win=''
        fi

        # Advanced Virtualization
        if [ -n "$repo_advanced_virtualization" ]; then
            in_chroot "$install_root" "
                yum -y install '$ADVANCED_VIRTUALIZATION_RELEASE_RPM'
            " && has_enable 'repo' || repo_advanced_virtualization=''
        fi

        # OpenStack
        if [ -n "$repo_openstack" ]; then
            in_chroot "$install_root" "
                yum -y install '$OPENSTACK_RELEASE_RPM'
            " && has_enable 'repo' || repo_openstack=''
        fi

        # oVirt
        if [ -n "$repo_ovirt" ]; then
            in_chroot "$install_root" "
                yum -y install '$OVIRT_RELEASE_RPM'
            " && has_enable 'repo' || repo_ovirt=''
        fi

        # RPM Fusion
        if [ -n "$repo_rpmfusion" ]; then
            in_chroot <"$rpm_gpg_dir/rpmfusion/RPM-GPG-KEY-rpmfusion-free-el-$releasemaj" \
                "$install_root" \
                "rpm --import '/dev/stdin' && rpm -i '$RPMFUSION_RELEASE_URL'" \
            && has_enable 'repo' || repo_rpmfusion=''
        fi

        # Repositories might provide updated package versions
        [ -z "$has_repo" ] || yum_update=1

        # Perform package update when requested
        if [ -n "$yum_update" ]; then
            in_chroot "$install_root" 'yum -y update'
        fi
    }

    local host subdir url
    local _releasemin=255 releasemin

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

        # ... not support nfs-root for Fedora < 12
        [ $releasemaj -ge 12 ] || nfs_root=''
    }

    local host subdir url

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

    # Has EPEL packages
    has_epel=1

    # No EPEL repository
    repo_epel=''
    # No external repositories
    distro_disable_extra_repos

    [ $releasemaj -lt 24 ] || has_glibc_langpack=1

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

# Extract gpg keys used to sign rpm in repos
rpm_gpg_dir="$(mktemp -d -p '' 'rpm-gpg.XXXXXXXX')" || exit

# md5(bundle.tgz.base64) = e5d23dc94513c09edec650c3c164e39d
base64 -d -i <<'bundle.tgz.base64' | tar -zxf /dev/stdin -C "$rpm_gpg_dir"
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
bundle.tgz.base64

# Prepare rpm database
setarch "$basearch" \
    rpm --root="$install_root" \
        --rebuilddb \
    #

# Import gpg key(s)
case "$distro" in
    'centos')
        host_gpg_import "$distro/RPM-GPG-KEY-CentOS-$releasemaj"
        ;;
    'fedora')
        host_gpg_import "$distro/RPM-GPG-KEY-fedora-$releasemaj-$basearch"
        ;;
esac

# Initial setup
setarch "$basearch" \
yum -y \
    ${releasemaj:+
        --releasever=$releasemaj
     } \
    ${baseurl:+
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

    # Install /etc/dracut.conf.d
    install -d "$install_root/etc/dracut.conf.d"

    # Build generic image regardless of dracut-config-generic
    echo 'hostonly="no"' \
        >"$install_root/etc/dracut.conf.d/00-generic-image.conf"

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
    if centos_version_gt $releasemaj 7 ||
       fedora_version_gt $releasemaj 28
    then
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
    [ -z "$has_epel" -o -z "${pkg_dkms-}" ] ||
        PKGS="$PKGS dkms kernel-devel"
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

[ -z "$has_epel" -o -z "${pkg_dash-}" ] || PKGS="$PKGS dash"
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

if [ -n "$has_epel" ]; then
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

if [ -n "$has_epel" ] || centos_version_le $releasemaj 7; then
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

if [ -n "$has_epel" ]; then
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

[ -z "$has_epel" -o -z "${pkg_ntfs_3g-}" ] || PKGS="$PKGS ntfs-3g"
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

if [ -n "$has_epel" ]; then
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

if [ -z "$has_epel" ]; then
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

if [ -z "$has_epel" ]; then
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
            if [ -n "$has_epel" ]; then
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

    if [ -n "$has_epel" ]; then
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
        if [ -n "$has_epel" ]; then
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
            if centos_version_ge $releasever 7.4 &&
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

    if [ -n "$has_epel" ]; then
        # qmmp
        [ -z "${pkg_qmmp-}" ] || PKGS="$PKGS qmmp"
        # rhythmbox
        [ -z "${pkg_rhythmbox-}" ] || PKGS="$PKGS rhythmbox"

        # vlc
        [ -z "$repo_rpmfusion" -o -z "${pkg_vlc-}" ] ||
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
    fi # [ -n "$has_epel" ]

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

    if [ -n "$has_epel" ]; then
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

    if [ -n "$has_epel" ]; then
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

    if [ -n "$has_epel" ]; then
        # libva-utils
        [ -z "${pkg_va_utils-}" ] || PKGS="$PKGS libva-utils"
        # libva-vdpau-driver
        [ -z "${pkg_vdpau-}" -o -z "${pkg_va_vdpau_driver-}" ] ||
            PKGS="$PKGS libva-vdpau-driver"
    fi

    if [ -n "$has_epel" ]; then
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
