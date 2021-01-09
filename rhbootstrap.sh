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

## Post install configuration snippets

# Usage: config_rpm_gpg
config_rpm_gpg()
{
    local unpack_dir="$rpm_gpg_dir"
# md5(rpm-gpg.tgz.b64) = 49f1053f1580b42a56c4d8fa00149c25
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'rpm-gpg.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
rpm-gpg.tgz.b64
}

# Usage: config_login_banners
config_login_banners()
{
    # Update /etc/issue, /etc/issue.net and /etc/motd banners
    $(
        PRETTY_NAME=''

        # Source in subshell to not pollute environment
        t="$install_root/etc/os-release"
        [ -f "$t" ] && . "$t" >/dev/null 2>&1 || PRETTY_NAME=''

        if [ -z "$PRETTY_NAME" ]; then
            t="$install_root/etc/redhat-release"
            PRETTY_NAME="$(
                sed -n \
                    -e '1 s/^\(.\+\)\s\+release\s\+\(.*\)$/\1 \2/p' \
                    "$t" \
                    #
            )"
            if [ -z "$PRETTY_NAME" ]; then
                PRETTY_NAME="$(uname -s)"
            fi
        fi

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
}

# Usage: config_resolv_conf
config_resolv_conf()
{
    local t="$install_root/etc/resolv.conf"
    if [ -n "${nameservers}${install_root%/}" ]; then
        : >"$t"
    fi
    if [ -n "${nameservers}" ]; then
        local n
        for n in ${nameservers}; do
            echo "nameserver $n" >>"$t"
        done
    fi
}

# Usage: config_xorg
config_xorg()
{
    local unpack_dir="$install_root"
# md5(xorg.tgz.b64) = f8c93da77f041f38ed3a34251c3c96ae
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'xorg.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAOS++F8AA+3STU/bQBAGYF/tXzFyL62qOLPeLztcuEDTQ1SkoKg3hOxNsQh2tBgp5NczdkNa
0lAOpEKo80heW/bqnR2NXVsMvwsxXDX+R1I09Twph8GBIbFa93eye++fhbTWCKmUkAEKidIEoA99
kH3ubttLDxD4pmn/tu+l7++U2zP/HAc3TV21je/fvLpGN2Cj1LPzt8pu5y+7fUIbqQPAA/T3ov98
/lNXtFVTQzz5OfE4Cr+Wrm6reeV8GM8q395dLgYYR1H4AUSa4cqmCMdgMEGE8Ro+fjk//QRXt/d1
MQKlEmvgerw+gmWxuB6BVYnKYDJeR+GkKd2iqh3EjzEXfUgMm119PAgpDQhlUxDGKPpG5Wwq6FK0
zwAMxlOqBZ9nXcknsdKYlTXZr1hMNFIsvafFKloyWrToYk0G1lIsFaJfbxs7mE37WGrWIK5yfL5Z
rZM8/b1ZIfJu3263m5ztsTbb+gK05HS4jDpNqX2ArmCOgi4FuUx3243Cb8tuYGEYn3k3d967sisV
/9F+dFKXm+lG0Vv/ZowxxhhjjDHGGGOMMcYYY4wxxhhj7B95ACMcB9oAKAAA
xorg.tgz.b64
}

# Usage: config_sshd
config_sshd()
{
    local file="$install_root/etc/ssh/sshd_config"
    if [ -f "$file" ]; then
        sed -i "$file" \
            -e '/^#\?LoginGraceTime/iAllowGroups root users' \
            -e 's/^#\?\(PermitRootLogin\s\+\).*$/\1without-password/' \
            -e 's/^#\?\(UseDNS\s\+\).*$/\1no/' \
            -e 's/^#\?\(VersionAddendum\s\+\).*$/\1none/' \
            #
    fi
}

# Usage: config_lvm2
config_lvm2()
{
    # Disable lvmetad to conform to CentOS 8+
    local t="$install_root/etc/lvm/lvm.conf"
    if [ -f "$t" ]; then
        sed -i "$t" \
            -e '/^\s*use_lvmetad\s*=\s*[0-9]\+\s*$/s/[0-9]/0/' \
            #
        in_chroot "$install_root" \
            'systemctl mask lvm2-lvmetad.service lvm2-lvmetad.socket'
        in_chroot "$install_root" \
            'systemctl stop lvm2-lvmetad.service lvm2-lvmetad.socket'
    fi
}

# Usage: config_kvm
config_kvm()
{
    # Enable/disable KVM nested virtualization
    local t="$install_root/etc/modprobe.d/kvm.conf"
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
}

# Usage: config_libvirt_qemu
config_libvirt_qemu()
{
    # Configure libvirt-daemon-driver-qemu
    local t="$install_root/etc/libvirt/qemu.conf"
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
}

# Usage: config_libvirt
config_libvirt()
{
    # Configure libvirt-daemon
    local t="$install_root/etc/libvirt/libvirtd.conf"
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
}

# Usage: config_virt_p2v
config_virt_p2v()
{
    local user='virt-p2v'

    # Add sudoers(5) file
    local t="$install_root/etc/sudoers.d"
    if [ -d "$t" ]; then
        t="$t/$user"
        if [ ! -e "$t" ]; then
            # Remove broken symlink
            rm -f "$t" ||:
            cat >"$t" <<EOF
$user	ALL = (root:root) NOPASSWD: ALL
EOF
            chmod 0600 "$t" ||:
        fi
    fi

    # Add user and group
    in_chroot "$install_root" \
        "useradd -M -d / -s '/bin/sh' '$user'"

    # Add user to libvirt group and change it's ~ if libvirt installed
    if [ -n "${pkg_libvirt-}" ]; then
        in_chroot "$install_root" \
            "usermod -a -G libvirt -d '/var/lib/libvirt' '$user'"
    fi

    # Configure sshd(8)
    local file="$install_root/etc/ssh/sshd_config"
    if [ -f "$file" ]; then
        in_chroot "$install_root" "usermod -a -G users '$user'"

        local keys='/etc/ssh/authorized_keys'
        install -d -m 0751 "$install_root$keys"

        cat >>"$file" <<EOF

Match User $user
	X11Forwarding no
	AllowTcpForwarding yes
	PasswordAuthentication no
	PubkeyAuthentication yes
	AuthorizedKeysFile $keys/%u
EOF
    fi
}

# Usage: config_readonly_root
config_readonly_root()
{
    local t

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
}

# Usage: config_grub_20_ipxe
config_grub_20_ipxe()
{
    local unpack_dir="$install_root"
# md5(20_ipxe.tgz.b64) = f92443bb12554649bd4af298f00933dc
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'20_ipxe.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAIpx+F8AA+3TX2/TMBAA8L7On+LIKtQgZUnbrZnYBmKjg72wCQ2ExB/Lda+r1cSJbGdr1fW7
Y3cDCTYBD0MI6X6qmiZ39d05CTqZXphmtDVOexlX9RxbDy7z8p2d9dH7+djt7+Stbj/PB1lvO897
razby/vdFmQP38pdjXXCALRMVblf5f0u/p/afJSOlE7tlDGLDhJkbAvSxhp/SRhcPxvrr6ScyUpP
1AUv1IixTVBnH4agLFS6WIBt6royDsf+FOa7AyaFRWh3Gi1KhKSMQWm2oZ7vDq59lA+2Y9jbYxtP
YsC5cpCFM7RCMlYbrH1hPvL7zaWQUzyI2p1vV0Mn3FVcSInW8jFeKunrLF+9fXfIXw7fnxwN+eHp
6fkKrsH6bhKEyKZf0k8ujeKIMTWBj5CMIbULm06UKa/CkDhR8HkP3BQ1Azjxgx2koX4a3octH2VY
WLwnVMyMZj4c1nVo3bpeO2RF8MN6Zy/OXx+0O1CKGXJf22HJa+Gm3GAhnLrEMJRylofH7PsSsf83
ymkF0XHV6PHtlpfiAp/Cbcqzxz2f9CdjAUjhYH9/eHrMStQNamcWEL1Bd1WZGYShoBMqxBEkSWPR
WIjCT1kIa0Hf5i1Ze3n3Hq3YhpwKpYtKjNHcNBdmZisW6vkxbjbwbzdRKN3Mu4N7GvB3yX/+9etG
CCGEEEIIIYQQQgghhBBCCCGEEELIg/oKPiVQNwAoAAA=
20_ipxe.tgz.b64
}

# Usage: config_grub_05_serial_terminfo
config_grub_05_serial_terminfo()
{
    local unpack_dir="$install_root"
# md5(05_serial_terminfo.tgz.b64) = 4212ad7a7df69d39a0e12efc6b11d5e9
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'05_serial_terminfo.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAIpx+F8AA+3Ty07CQBQG4K7nKcZiwkVKp0hpjHSBisZEJMG4othAmUoTaE07dSHy7k65GW+w
kMSY/F+aTDNzev5ZnHLh6Y9xOqyMdGa6CY+DwcQVPJ4GoR8p+8EkyzQXq/R5ZVbdVIxjy6qzaq1u
1hRmmIZZVSjbU/5WaSIGMaVKHEViW92u838qd6APg1BPxoQkXFCNZ2s2BHY+KT9cde/P3LtW97p5
45532u3m7YVdKTkFp6BpaRgI23nlfuAUe0w76TtHTrFSKjtG+Sm/bqIeFhI+olooO1P1cLmr0rzO
5dyNuD9IJ2Ixf/miSkjg015W+17YP6VizENCJWFv9sliY5MxW77lVpeaq98fy6vOV58uk15k0kzk
soPS/GNYxhsI2mi0Opdk/UOserryg9VV6LMwGNO8aBLFVEu/VHrR9IfKrG+WwicJ3x25PP51mB8Q
+fz10AEAAAAAAAAAAAAAAAAAAAAAwF68AWpzrokAKAAA
05_serial_terminfo.tgz.b64
}

# Usage: config_kernel_symlink_to_root
config_kernel_symlink_to_root()
{
    local unpack_dir="$install_root"
# md5(symlink-to-root.tgz.b64) = 1e10a85d1fee1a0f0b2d8f351bf832f2
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'symlink-to-root.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
lFNOOeWUU0455ZRTTjnl9H+ivwFblQwIACgAAA==
symlink-to-root.tgz.b64
}

# Usage: config_kernel_initrd_chmod_0644
config_kernel_initrd_chmod_0644()
{
    local unpack_dir="$install_root"
# md5(initrd-chmod-0644.tgz.b64) = b2292dd83646e69324b0c8da74cfd350
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'initrd-chmod-0644.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAIlx+F8AA+2UW2viQBTH85xPMY6WUiFOLmpgiyy2SpFWBVv2pRSJZlaHzUUysYjW774nUWO8
0NI+dFk4v5dJzmVO5sz5Zy4j5okR+8OjgHtMBDJ2PK/isuVSE4GII1cbT/3Q1fR6tVrZupXPoQN2
rZauwPGq27apGJZt1/Wqadbqim4allVTiP7JOl9iDieKCFGiMIzfi/vI/59SLLCRCJicquosCifD
wPF5g5ZWerFYZmuqqnHylrkudiMArmdCSzElhQasWQAlL+TtjfCFiImeJscVOYV9bvvdbrPXAoNB
1fv2oNd+GP5qDx47/R7YTKre9PtPw1ZnMGzePILFyqI63eZdGyxV2OWZaC6Uy8duKx6kX7IRXNel
erxFPoi9+p4I5kutdPg1UGXsSE6SDyUiUAnguO5V+pAAh2I8Hu8kMwtlnDQFNAPtyKKur9PHiPvh
K383OfLPp5b3Wdt25gK4dMZJOwpEW2zuYdt3Pt680uNj7S1pN+jm/s8f5Kz45fSLM/aR/i3TyPRv
VcFu2HX4JaD+v4Gc/vliFkYxeWj27hq36qlGV8aPn76QUgQTcuhcn2h1ZZ7Epq7kj9LpdZ4GrX1o
3n/BymuWjp7j/5Za5twVqgh/kgg0mUqSTCVMdX4/qv7rhiIIgiAIgiAIgiAIgiAIgiAIgiAIgiAI
gnwzfwEZNgftACgAAA==
initrd-chmod-0644.tgz.b64
}

# Usage: config_user_apps
config_user_apps()
{
    # Usage: ssh_agent_start4bashrc() [<user1>|<file1>] [<user2>|<file1>] ...
    ssh_agent_start4bashrc()
    {
        local func="${FUNCNAME:-ssh_agent_start4bashrc}"

        local t f p

        local unpack_dir
        unpack_dir="$(mktemp -d -p '' 'bashrc-ssh-agent.XXXXXXXX')" || return
# md5(bashrc-ssh-agent.tgz.b64) = 3cb908414b7650564bead5b8618d7a3f
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'bashrc-ssh-agent.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAIpx+F8AA+2Wf2/TMBCG93c/xdGOdZ2UtF3LKjFt0jQQm4AxqUMCAarcxF2junZlO+0Kg8/O
OWm6/No6EAgh+dGkNPGd/d75fJ47JGosPUepsUOuKddbf54WctDtRk8k/+y2Op2tdqfXO2i1O919
tGvv99rPtqD1F7QUCJUmEmBLCvFg7JvG/1MqNehjAjSsCwBGQgIX3PnQboOiSgWCQ8gZ/gLXdSvB
CD6B8xWq299enPcv35x8dL5X4csh6DHlFUBwqkE01VG9Hn2owYXQFA2IhkCZv3AGWkCoqDRPylUo
V+M/mi76ow2va1gIyXxYyEBTMmTUzU4/oHx+FNs31/Jd/FiJ7BbjgFF4fgi+iN5jJX3hTaiG4RLi
aDFY9PVN1AsifeqDJzinnsaw3ZTfOQdGtEbBHlEU+v2zwcmrlxdXg8vzFyu1ZE4CdqfTECerb5IV
eby/Ohv0352+zqcsYSgpmay/jIKUgFNGCce84ZRcaJAh5wG/NvqTn8NQ4xCoKMK8Bm40rFNXq+01
9+7REHKFCcrIzYb7WMV9EUqP4u7OAyn41GxOTpREUZntLFdE54TB9m7mm8Etuh83fTpv8pCxSsE8
KdtMMNFOwO3t46wxb5/re/e5RFq9sYAqvZkJqbNpO6pvZ97r1Q0SM8WyUWJi/TsSE99EYvKOEtOO
jfQ+l9VXSWZ3dtJTTALGwGmhbca0CvupjUuMC3VQMw0ICMOS85dJ2WcsUq1nNVxfj1OmaMl0o0Aq
PLt4tKczbbqRivrhCM8y9d2Mwyrf60WK8a3m9ANl+oAPu9S9dmER6DEwDo4awTpMKOtcjfyCT8Ch
xSp3BM5VcnbK1QQa6E2gtALC/Tg8lKZCz8OePgrZ0r0nh9XtXU9Mp8bLmd/dEI1qfp1Vcm42JMcw
nfiBBGeWaUdG/tOoIZV4yCk4o2KwJZbFDhEn4S2ZUIiumLjnY3/TWBoKTCGZjQLB2dLcCeZGKp0k
nBI1gVar18OFs2HiThzn1RXmaOQPY6pSU+28Xsnt3530BT4faKiRyGLnzndmX3AarxEbr2Vkr9UK
mv/rf00sFovFYrFYLBaLxWKxWCwWi8VisVgsFovF8gv8BL+6V0EAKAAA
bashrc-ssh-agent.tgz.b64

        p="$unpack_dir/.bashrc-ssh-agent"
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
            t="$(
                  t='# Start ssh-agent for non-X11 session'
                  sed -n -e "/^$t/{p;q}" "$f"
                )" &&
            [ -z "$t" ] || continue

            # Keep it disabled by default for compatibility
            t="${f%/.bashrc}/.ssh/ssh-agent.env"
            rm -f "$t" ||:
            install -D -m 0644 /dev/null "$t" ||:

            # Patch .bashrc file at known location instead of appending
            sed -i "$f" \
                -e 'N' \
                -e '/^\s\+\. \/etc\/bashrc\s\+fi$/b patch' \
                -e '/^\s\+\. ~\/\.bash_aliases\s\+fi$/b patch' \
                -e 'P;D' \
                -e ":patch r $p" ||
            continue
        done

        rm -rf "$unpack_dir" ||:
    }

    # Usage: mc_ini <unpack_dir>
    mc_ini()
    {
        local func="${FUNCNAME:-mc_ini}"

        local unpack_dir="${1:-missing 1st arg to ${func}() <unpack_dir>}"
# md5(mc.tgz.b64) = adeef3ff407c7c0e25dd5229d0965802
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'mc.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAIpx+F8AA+3SwXKbMBAAUM58hX+gCTgh9OJTr+0XZDI7MiywEyGpkjB2vr4SNsZxp+3Jk+lk
3wXYZaUVy12lVUPtfV/dJ7eSBWVRTNfg+jrd5w9lWZRlmecPSZbnxTpLVsXNOrowOC/sapVYrf3f
3vtX/j91t8yfFN1mjzjgp8fHP80/z9dPV/NfB8kqu007733y+T//oFpR2/kv33TfC1WjfUnF4DU4
sUNw6AezydPBIZDyaJWQsCMcr2NYkw+x6W+yPeB+eoxRbcGLLTgjKlLt5uscHLWtYbTCgCSFIFG1
vtuU6znfkJSx0sFIvpvq0W2yOW1DZ1ZBrdHB1C+F3tXFpo14ReiEbKZFlkJtPGl1PJ7RjuLTUnXK
+oPB0VI43NTiUh0vMJ8yrrGUuoPyYg9d+JoyftF42nNyR462Eo+9/BY9He4cb60eDAyq1mHn9Pm7
OOjBv6Q9OidanMtC7hUPW3FeJyywDy334MlPT9VxpmCs7k38Nj2q4bIgSxuLp/1DutOW3nQ4hgwh
GUaYpTu0nqo44Z+DkO/fmUNeGzBCYaiit7jOR//VjDHGGGOMMcYYY4wxxhhjjDHGGGOfxy/A1eJ+
ACgAAA==
mc.tgz.b64
    }

    # Usage: screenrc <unpack_dir>
    screenrc()
    {
        local func="${FUNCNAME:-screenrc}"

        local unpack_dir="${1:-missing 1st arg to ${func}() <unpack_dir>}"
# md5(screen.tgz.b64) = fcd3ad6952d4d0fecd2a159bc7b28f1f
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'screen.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAIlx+F8AA+2UbWvbMBCA89m/4kgw3dgSmiVNRkqgafo2ysag60rpNpBl2RazpSIpTUOT/76T
nHbZOrYPo4zBPR98PuvepDu5Y7kRQhneeDq2kUG/HyTys+wOh4NGtzcc7gyHw26319judvvdQQO2
n7CmB2bWMQPQMFq739n9af0/pQXH787hLAwBtKFiUgHXKpP5zDAntYJMliJqwaQsQbtCGOjcj0xY
sjCXuGT1zHABrpA2fAanQSo0lw6scE6q3HZ8mJkrtBnBtDDSOskUXKC7xdTcx7Edu7B7OZZRdriu
oqgVMus5JLpMsbJSG2+sBBfWMrOATBtMXgkwglmtohZzzgQ7SKDZedMMMT4IX2O9ywKjYXVY1Tpe
Byb7MIaE8a+50TOVvoTJ0RgDi1qNnDAVZ9dSZRpuvQJbU916tTMYTfbHnw6v+q93d3bjtBqhG6q9
tboVUh8qlvhjmlkBOgNbyMy13+fn18BU+qAeYOWP0izD0y5v7dLc3jhwcm/kxF4d1jAM+L1mbIMr
gM+MEcpBktd7i1qpyBJsTFOr5kY5gMXXFuBT1LnrpG1cqn2xXVPGCwE9f02hlAq3Ec6bG43n6ZNH
GL9WvVZbRlHBTIr3ys0ssHLOFrZk1nl/DPlRYNeU9MPCkkSsm4pywymYbujWGRwg2IrvxnCarmAt
4/Y8vJnVVZAXq1hB7NbfPt9bvZhD3B6j0+kxup6gvFgt8Xm5is/WygHEbyFOIb4MThztpvEkvmuv
fBOBF0zlAiutKt80VA3jeFiQGV0Bd6ZsMz9T4S2BZ6JiPHQch7ViC5gz7Im/G8+jlrDYYwFf9hMf
+USmYmPno/tgWZRIzJSBuGElNDfOQuYKj6uJvmd+kn/he1T7Hj32/bEZzehf/30IgiAIgiAIgiAI
giAIgiAIgiAIgiAIgiCIv+Ubg8+/PgAoAAA=
screen.tgz.b64
    }

    # Usage: xfce4 <unpack_dir>
    xfce4()
    {
        local func="${FUNCNAME:-xfce4}"

        local unpack_dir="${1:-missing 1st arg to ${func}() <unpack_dir>}"
# md5(xfce4.tgz.b64) = 9d75285778652eba7864b6dc6261f7de
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'xfce4.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
xfce4.tgz.b64
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
    xfce4 "$t"
    ssh_agent_start4bashrc "$t"

    # /etc/skel
    t="$install_root/etc/skel"

    make_xdg_dirs "$t"
    mc_ini "$t"
    screenrc "$t"
    xfce4 "$t"
    ssh_agent_start4bashrc "$t"

    unset -f make_xdg_dirs mc_ini screenrc xfce4 ssh_agent_start4bashrc
}

# Usage: config_autopass
config_autopass()
{
    local unpack_dir="$install_root"
# md5(autopass.tgz.b64) = ca5301f405d0c47b768dead76d96076d
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'autopass.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAIlx+F8AA+1XbW/iRhDO5/0VU4JEop4BAyEpiiMlF3KKlF6uoajVRSha7AGvamxudx1CU/57
ZxdDyDW5q3RRrpX2+bLD7Lysx8Mz3lzJWiKGeIdhjec6m3KlqireeknUCft7e3YlfL76tLnlN/f3
2/Vme6+1v1X3W41GcwvqL3qKZ5ArzSXAlswy/SW7r+3/T7H9Q20o0pqKGduGK/yUC4mqA1ru+Ltv
IEYeWUHhcg1j0yAz88M49BUfYwemswn/A+H6MMF0rOOjAYmjm+nshk+GYpxnuToasKXRzi67Z0DY
hjOZTch1jGmNTCVPo2pot5Is5AlsugeVk4N37XM/qV/+ctrb+9ioMGuJt2RYsqKBluBFIVTq3k/c
+/PY+1iBw1qEt7XcRKdsjSP7M82TBP5au5XvG50frS+UyptpS48dFmsPUxfwKFP53u94fntRsVvL
k2AYZ2yxUZ6N/xUVJlcobYWMigpm5c1CMWMRlGxo03WLErNFz2RE2p2i2ObQ3sGC1qa32C0xtno1
cHjYvTxjZROlU155MqNjIddwdFSpoQ5rQqkcK4X1RTYWKXAF1g1yJdIxrJ1hJVTZMg7eCQ119r2b
1+GbYTpBzVWYpSMxXk+Al81hSL7daj3L/37LX/N/u27532/6jv9fA8RSPZS3IkRY9kBO/A9qiqEY
CYyg3O91r4CHYZanGmZCx5bOiLRRco0P1ECBlqzxiHAjrjmQCBOuw5jMr9fcPLgvfzju9S667xeA
dxrTCE0QieM8oTeCd1M6iRJZSim0Rpm+gWyq6TdPkjlth0kemXxr6qThxCUPyVRRnCIhpRzO4fqz
8TF4Ik2VbZPb+0wj6Jh48ssZYGSm19OlUPYxojykSuoYhYRPOU+EnlfhXMNEjGMNQ4QIlZB8mFC+
DEQaSuSKeL0oCmkojD1JaPQ2X4QjnicaDoyL34BMwpjcKImsLgcOkXfKJ0jy6dK2A6Zz6dnMiwys
TJsfVsy+nNib5gdkW5wh8BvGuGsrgc9Veu3Jur+/veifdm+Ofz45f9e/7PcC382I/zYK/tc4iYp1
4xqwJIZvzvEV/q/vt5oP/L9n+L/d9luO/18D1/1U6AE7RRVKYek1eLuaA2C/Bf8N9xuXRIRaBSrO
dZTN0ipVdYyaHY+IJYKiwzwT0FNLvl33F0yT+STLdezR7UN7My70aqtwl6Fn7wRrDxlj4hHxRVma
zB+0hcJ+Na9DnOAokxjQYYiAi1Ox62LoDdiv8ykGWYoqJma8wgkXqU3apU/cYI6Kdelq3CM/HdTy
py/LdGsw5FqitSBOI/6DDEusm94KmaUTTHXwQMeb2hXxHmxqz0SCgVd7+lONnuU8pR5OkgH7jaf0
Wk7mjx/2e7eYg4ODg4ODg4ODg4ODg4ODg4ODg4ODg8Mr42/XudZLACgAAA==
autopass.tgz.b64
}

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
    local t f

    # Do not interrupt exit handler
    set +e

    if [ $rc -eq 0 ]; then
        ## Add helpers
        local systemctl_helper="$install_root/bin/systemctl"

        t='command -v systemctl >/dev/null 2>&1'
        if [ -e "$systemctl_helper" ] || in_chroot "$install_root" "$t"; then
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
        fi
        # Add helper that generates terminfo commands for serial
        config_grub_05_serial_terminfo

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
        fi
        # Add helper that generates boot menu entries for iPXE
        config_grub_20_ipxe

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

        # Configure login banners
        if [ -n "$login_banners" ]; then
            config_login_banners
        fi

        # Configure nameserver(s) in resolv.conf
        config_resolv_conf

        # Configure Xorg server
        if [ "${x11_server-}" = 'Xorg' ]; then
            config_xorg
        fi

        # Configure openssh-server
        config_sshd

        # Configure lvm2
        config_lvm2

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

        if [ -n "${grp_virt_host-}" ]; then
            config_kvm
            config_libvirt_qemu
            config_libvirt
            config_virt_p2v
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

            config_readonly_root

            sed -i "$install_root/etc/sysconfig/readonly-root" \
                -e 's/^\(READONLY=\)\w\+\(\s*\)$/\1yes\2/' \
                #
        fi

        # $autopassword_root
        if [ -n "$autopassword_root" ]; then
            config_autopass

            in_chroot "$install_root" 'systemctl enable autopass.service'
        fi

        # $passwordless_root
        if [ -n "$passwordless_root" ]; then
            in_chroot "$install_root" 'passwd -d root'
        fi

        # $autorelabel
        if [ -n "$autorelabel" ]; then
            echo >"$install_root/.autorelabel"
        fi

        # Provide user configuration for applications
        config_user_apps

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

        # Restore /etc/yum.conf.rhbootstrap after yum(1) from EPEL install
        f="$install_root/etc/yum.conf"
        t="$f.rhbootstrap"
        if [ ! -e "$f" -a -e "$t" ]; then
            mv -f "$t" "$f" ||:
        else
            rm -f "$t" ||:
        fi

        # Remove installed systemctl helper
        if [ -n "$systemctl_helper" ]; then
            rm -f "$systemctl_helper" ||:
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
cd "$install_root"

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
                "$install_root/etc/redhat-release" \
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
                    ln -nf "$t" "$t.rhbootstrap" ||:
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
            arch="Everything/$basearch/os"

            printf -- "$templ" \
                "$host" "$subdir" 'releases' "$releasever" "$arch"
        )"
        [ -n "$base" ] &&
            curl -L -f -s -o /dev/null "$base" &&
        echo "baseurl='$base'" || return

        updates="$(
            [ $releasever -le 27 ] &&
                arch="$basearch" || arch="Everything/$basearch"

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
config_rpm_gpg

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

    # Add helpers that create symlinks to vmlinuz and initrd in root
    config_kernel_symlink_to_root

    if [ -n "$nfs_root" ]; then
        # Add helpers that chmod(1) on initrd to make it world readable
        config_kernel_initrd_chmod_0644
    fi

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
