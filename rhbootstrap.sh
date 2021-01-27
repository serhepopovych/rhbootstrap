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

# Requires: mountpoint(1), chroot(1), find(1), xargs(1), install(1), head(1),
#           sed(1), mv(1), rm(1), ln(1), cat(1), rpm(1), yum(1), curl(1), id(1),
#           uname(1), mount(8), umount(8), setarch(8), chmod(1), mktemp(1),
#           base64(1), tr(1), date(1)

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

# Usage: safe_curl <url> <size> [<curl(1) options>...]
safe_curl()
{
    local func="${FUNCNAME:-safe_curl}"

    local url="${1:?missing 1st arg to ${func}() <url>}" && shift
    local size="${1:?missing 2d arg to ${func}() <size>}" && shift

    [ "$size" -gt 0 ] 2>/dev/null

    exec 4>&1
    eval $(
        exec 3>&1
        {
            curl "$@" -f -s "$url"
            echo >&3 "local rc=$?"
        } | head -c $size >&4
    )
    exec 4>&-

    return $rc
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

    eval "local pkg_val=\"\${$pkg_name-}\""

    if [ "$pkg_val" -eq 0 ] 2>/dev/null; then
        eval "$pkg_name=''"
    else
        local on_off="${2-}"
        case "$on_off" in
           '')  on_off="$pkg_val" ;;
            0)  on_off='' ;;
            *)  on_off=1 ;;
        esac
        eval "$pkg_name='$on_off'"
    fi
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

version_lt() { [ "$(version_cmp "$@")" = '-1' ] || return; }
version_eq() { [ "$(version_cmp "$@")" =  '0' ] || return; }
version_gt() { [ "$(version_cmp "$@")" =  '1' ] || return; }

version_le() { version_eq "$@" || return; }
version_ge() { version_eq "$@" || return; }

version_neq() { ! version_eq "$@" || return; }

is_centos() { [ "${distro-}" = 'centos' ] || return; }
is_fedora() { [ "${distro-}" = 'fedora' ] || return; }

is_centos_stream() { is_centos && [ -z "${releasever%%*-stream}" ] || return; }

centos_stream_compose_id()
{
    is_centos || return

    local r="${releasever%-stream}"
    [ "$r" != "$releasever" ] || return

    if [ -n "${baseurl-}" ]; then
        local url="${baseurl%%/$releasever/*}/$releasever/COMPOSE_ID"

        r="$(
            safe_curl "$url" 1024 | \
            sed -n \
                -e "1 {s/^CentOS-Stream-$r-\(\S\+\)\s*$/\1/p;q}"
        )"
        [ -n "$r" ] && echo "$r" && return 0 ||:
    fi
    # Fake compose_id based on start timestamp
    date --date="@$start_timestamp" '+%Y%m%d'
}

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

# Usage: distro_name [<root>]
distro_name()
{
    local root="${1-}"

    sed -n \
        -e '1 s/^\(Fedora\|CentOS\)\s\+.*$/\1/p' \
        "$root/etc/redhat-release" | \
    tr '[:upper:]' '[:lower:]'
}

# Usage: distro_version [<root>]
distro_version()
{
    local root="${1-}"

    sed -n \
        -e '1 s/^CentOS\s\+Stream\s\+.\+\s\+\([0-9]\+\).*$/\1-stream/p' \
        -e '1 s/^CentOS\s\+.\+\s\+\([0-9.]\+\).*$/\1/p' \
        -e '1 s/^Fedora\s\+.\+\s\+\([0-9]\+\).*$/\1/p' \
        "$root/etc/redhat-release" \
        #
}

## Post install configuration snippets

# Usage: config_rpm_gpg
config_rpm_gpg()
{
    local unpack_dir="$rpm_gpg_dir"
# md5(rpm-gpg.tgz.b64) = 4db8dee3fd3d70aa1c33ed0376b44af3
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

# Usage: config_network
config_network()
{
    nm_devgroup()
    {
        local unpack_dir="$install_root"
# md5(nm-devgroup.tgz.b64) = 76f86334122bf7ef2068cb90f1d35e59
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'nm-devgroup.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIACFPB2AAA+3VW0/bMBQA4D77V5wlkSKqpbkQWmmlvEwa2gMwTeIJTcg4J63V4kS2s8Io/31O
0qFtEgMEYpp2vpc4vh77OC1aER+jXVd6ecQVn6OOC2lqbsUC9aiIa41RU7tCkkYFfp3rqqkHT5Q4
k8mkezq/P7tymidJOs7HWe76Zbv5OB1ANho9Z9nHaYzlGmCgq8r+qd9D7f8ofET+i2qtnnMDnp5/
95JT/l/DQ/l/ifPv8r+3d2/+J1n+a/7TyXjXff/JC+7zXv95/v03EF9IFV9ws2DMh1Pj7sA7CGpd
zc8Vv0TYl8qiLrnAA9jnwspKHbAzCHyI5ggZfIHNBvBKWkgYE9wgeEHmgVQMnLD/Awk34Y9fknAH
ptOubbizHde+uDo0XLQxHPElgmk0whpB8NUKC+AGzPXlSqqlmxnauW6a+m073627pS6e6Jtb9ybx
/WEcZK5qeOv9FFrqQisgbm+7uTaiUqWcx6q/95ERWtbWsBGM7urKRnVbNYy9Pzn+8PFw5gWpxxRi
cd4Pd8v1LR4zVaMFbusZkyW4eFQbz+Hnk9NPURvKFOwC+zM5609odnc4faBd31lYYMmblQ1Z1xev
UICsodu5QQvua4Q2FOi+SVfshnmslIxts/C37xQhhBBCCCGEEEIIIYQQQgghhBBCXtd3AZ7YcgAo
AAA=
nm-devgroup.tgz.b64
    }

    nm_dnsmasq_split_0()
    {
        :
    }
    nm_dnsmasq_split_1()
    {
        {
            echo '[main]'
            echo 'dns=dnsmasq'
        } >>"$install_root/etc/NetworkManager/conf.d/dnsmasq.conf"
    }
    nm_dnsmasq_split_2()
    {
        local unpack_dir="$install_root"
# md5(dnsmasq.tgz.b64) = f9c4e00a9a4e01b6d43f4d026cf08397
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'dnsmasq.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
dnsmasq.tgz.b64
        nameservers="127.0.0.1 ${nameservers:-${_nameservers}}"
        in_chroot "$install_root" 'systemctl enable dnsmasq.service'
    }
    "nm_dnsmasq_split_${nm_dnsmasq_split:-0}"

    # Configure nameserver(s) in resolv.conf
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

    # Support for network device group in NetworkManager ifcfg-rh plugin
    if [ -d "$install_root/etc/sysconfig/network-scripts" ]; then
        if [ -n "${pkg_nm-}" ]; then
            nm_devgroup
        fi
    fi

    # Enable/disable legacy network scripts when no/ NetworkManager available
    if [ -x "$install_root/etc/init.d/network" ]; then
        if [ -z "${pkg_nm-}" ] ||
           centos_version_gt $releasemaj 6 ||
           fedora_version_ge $releasemaj 18
        then
            in_chroot "$install_root" 'systemctl enable network.service'
        else
            in_chroot "$install_root" 'systemctl disable network.service'
        fi
    fi
}

# Usage: config_xorg
config_xorg()
{
    local unpack_dir="$install_root"
# md5(xorg.tgz.b64) = 0e0d9c172eddae3c3834862d4e3690e7
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'xorg.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIACJPB2AAA+3STU/bQBAGYF/tXzFyL62qOLPeLztcuEDTQ1SkoKg3hOxNsQh2tBgp5NczdkNa
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
        ln -snf '../run/lock' "$install_root/var/lock"

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
# md5(20_ipxe.tgz.b64) = 3b7d80ce1ef0d10d274beaffb7335918
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'20_ipxe.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIACFPB2AAA+3TX2/TMBAA8L7Wn+LIKtQiZUmbtZnYBmKjg72wCQ2ExB/Lda+r1cSJbGfrtPW7
Y3cDCTYBD0MI6X6qmiZ39d05CTqZnJlmsjlNBilX9RJbDy718uFwffR+PvazYd7qZ3k+SvOtLM9a
aX+QZ1kL0odv5a7GOmEAWqaq3K/yfhf/T208SiZKJ3bOmEUHMTK2CUljjb8kDK6fjfVXXC5kpWfq
jBdqwtgGqJMPY1AWKl1cgm3qujIOp/4UltsjJoVF6HQbLUqEuOyB0qytnm+Prn2Uj7Z6sLPD2k96
gEvlIA1naIVkrDZY+8J84vebSyHnuBd1ut+uhk64q7iQEq3lUzxX0te5evX23T5/OX5/dDDm+8fH
pyu4Buu7iREim3xJPrkk6kWMqRl8hHgKib20yUyZ8iIMiTMFn3fAzVEzgCM/2F4S6ifhfdj0UYaF
xXtCxcJo5sNhXYfWret1QlYEP6x38uL09V6nC6VYIPe1HZa8Fm7ODRbCqXMMQylneXjMvi/R8/9G
Oa8gOqwaPb3d8lKc4VO4TXn2eOCT/mQsACkc7O6Ojw9ZibpB7cwlRG/QXVRmAWEo6IYKvQjiuLFo
LEThpyyEtaBv865Y5+ruPVqxtpwLpYtKTNHcNBdmZisW6vkxbjbwbzdRKN0s+6N7GvB3yX/+9etG
CCGEEEIIIYQQQgghhBBCCCGEEELIg/oK2ED29AAoAAA=
20_ipxe.tgz.b64
}

# Usage: config_grub_05_serial_terminfo
config_grub_05_serial_terminfo()
{
    local unpack_dir="$install_root"
# md5(05_serial_terminfo.tgz.b64) = d58c2f772b23246e45ac80130284dc6f
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'05_serial_terminfo.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIACFPB2AAA+3TT0/CMBgGcM79FHWYDJCxLjgWIxxQ0ZiIJBhPDJcxOlkCm9k6DyLf3Y4Bxn9w
kMSYPL8s6dK+e58e3nHh6Y9xOqqNdWY6CY8Dd+oIHs+C0I8K+8EkyzSXq/R5ZVbDLBh1y2ow67hu
1QvMMA1ZTtme8rdKE+HGlBbiKBLb6nad/1PFA30UhHoyISThgmo8W7MhaKlJ9eGqf3/m3HX61+0b
57zX7bZvL1q1il2yS5qWhoFo2a/cD+zygGknQ/vILtcqVduoPqnrJsphKeFjqoWyM1UO812FqjqX
czfmvptOxXL+1LJCSODTQVb7Xjg8pWLCQ0Il0drsk+XGJmOevxVXl1oo3x/Lqy5Wn+ZJLzJpLorZ
QWXxMSzjuYI2m53eJVn/EKuejvxgdRX6LAzGNC+aRjHV0i+VXjT7oTLrm6XwacJ3R+bHvw7zAyKf
vx46AAAAAAAAAAAAAAAAAAAAAADYizfmrP/PACgAAA==
05_serial_terminfo.tgz.b64
}

# Usage: config_kernel_symlink_to_root
config_kernel_symlink_to_root()
{
    local unpack_dir="$install_root"
# md5(symlink-to-root.tgz.b64) = d9202321e722694b0e7f8fccd616cca3
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'symlink-to-root.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
oIIKKqigggr6P9HfT07t9AAoAAA=
symlink-to-root.tgz.b64
}

# Usage: config_kernel_initrd_chmod_0644
config_kernel_initrd_chmod_0644()
{
    local unpack_dir="$install_root"
# md5(initrd-chmod-0644.tgz.b64) = bff0c2eeafc5f58e42e8a27deaf12b52
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'initrd-chmod-0644.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIACJPB2AAA+2UW2viQBTH8zyfYoyWskKc3Gxgiyy2SgmtEWzZl7JITGZ12FwkMxbR+t13Em/x
Qkv70GXh/F4mOZc5mTPnnxnPSMRG5A/NEhoRlnDhR1EjJIuFxhImslALJnEaavqVbTc2buVj6BKn
2SxWyfGqO46pGJbjXOmObTmWopuGZZsK1j9Y51PM5IkyjJUsTcVbce/5/1OqFTJiCeEThKZZOh4m
fkxbam2pV6t1slIREvnbznWxHQHpesZqTai40pLrLkDFv/DrK6ZzJrBeJIsGn8h9bvu9XtvrSIOh
ovvuwOs+DH92B49u35M2U0U3/f7TsOMOhu2bR2mxdlFur33XlRZb7vKMtVCWK8duKh6kX5KRvK5L
dLxFOYi8xBFLZgutdvg1skrgc4rzD8UsQVjih+G34iFHHopQEWwlM025yJsiNSPbsYu6vi4eMxqn
L/TN5Cw+n1rfZ23aWQqg3A/ydlSwNl/fw6bvNFi/qsfH2luKbqjr+z9/kLPi55NPzth7+rdM41D/
huPoTdD/V1DSP51P00zgh7Z317pFpxpdGt9/xIxzlozxoXN1otWleRJbuPI/iuu5T4POPrTsvyD1
FSlGz49/c23n3BZqsHicCzSfSpxPpZzq8n4q+tcNBQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+GL+
ApwRMAEAKAAA
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
# md5(bashrc-ssh-agent.tgz.b64) = bdd4ca760879e5a3e7c2961e59c1d659
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'bashrc-ssh-agent.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIACJPB2AAA+2WbWvbMBDH8zqf4pZkTVOwkzalhpUWSjvWsq0rpIONbQTFVhoTRQqSnLRbt8++
kx2nfurDxsYY6EfBsXUn/e90OtUdETWRvqPUxCFXlOvan6eH7O3uxk+k+Nzt9fu17b7n7fW83b7X
r/W2d7wdrwa9v6ClRKQ0kQA1KcSDsT82/p9Sb8IAE6BhXQAwFhK44M6H7W1QVKlQcIg4w1/gum49
HMMncL5Co/Xt5Gxw8eboo/O9AV/2QU8orwOCUw3jqQ7a7fhDE86FpmhANITK/EVz0AIiRaV5Uq4i
uRr/0XXRH214W8NSSBbAUoaakhGjbn76IeWLg8S+u5bv4sd6bLechIzCi30IRPyeKBkIf0o1jG4g
iRaDRd/ARL0kMqAB+IJz6msM2834nXFgRGsU7BNFYTA4HR69enl+Obw4O1mpJQsSsjudhiRZA5Os
2OP95elw8O74dTFlKSNJyXT9ZRxmBBwzSjjmDafkQoOMOA/5ldGf/hxFGodAxREWNXCjYZ26ZnOr
u3WPhogrTFBObj7cpyoeiEj6FHd3EUrBZ2ZzCqIkisptZ7UiuiAMWpu5bwa37H7YDeiiyyPG6iXz
tGxzwcQ7Abe3T7PGvH1ub93nEmv1JwIa9HoupM6n7aDdyr23G49IzBXLoxJT69+RmPqmEtN3lJh1
7GT3uaq+KjK7sZGdYhoyBk4PbXOmDdjJbFxqXKqDpmlAQBiWXHCTln3OItN6VsPt9ThlilZMNw6l
wrOLR3s216YbqbgfjvEs08DNOazyvV6kHN9qziBUpg8EsEndKxeWoZ4A4+CoMazDhKrO1Sku+Awc
Wq5yR+BcFWenWk2ogV6HSisgPEjCQ2kq8n3s6eOI3bj35LDR2vTFbGa8nMXdDdFpFNdZJef6keQY
ZtMglODMc+3IyH8eN6QKDzkDZ1wOtsKy3CGSJLwlUwrxFZP0fOxvGktDgSkks1EgOLsxd4K5kSon
iWZETaHX8zxcOB8m7sRhUV1pjk7xMGYqNdPO2/XC/t1JX+LzgYYaiyx37mJnDgSnyRqJ8VpG/lqt
o/m//tfEYrFYLBaLxWKxWCwWi8VisVgsFovFYrFYLL/AT7V2JDsAKAAA
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
# md5(mc.tgz.b64) = 520261e689f24b8aea4b716e738fb977
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'mc.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIACJPB2AAA+2STXLbMAyFtdYpfIEkkvyjbrzqtjlBJoOhJVjChCJZkrLsnL6kbNmOO21Xnkwn
+DYUAT3wgeBjpdWWmqeuekruRRYol8txDdyu43c+L8tVVi7m5TzJ8nyZl8lseTdHV/TOCzubJVZr
/7f//pX/T3m8zJ8U3eeMOODVYvGn+ed5sbqZf1EUeTLL7mPnI198/i/PVCtqWv/wXXedUDXa11T0
XoMTOwSHvjfrPO0dAimPVgkJO8LhNoY1+RAbX5PtAPfjNka1BS824IyoSDXrb1Nw0LaGwQoDkhSC
RNX4dl0WU35LUkalg4F8O+rRrbMpbYMzq6DW6GD0S8G7ujp0K94QWiG3Y5GLUBtPWh3bM9pR3F1U
p6w/GBwsheZGixd1XGDqMta4SN1BebGHNtymjDcauz0nd+RoI/Ho5bfoqblzvLG6N9CrWoeT05cf
4qB7/5p26JxocJKF3BseNuJcJxTYB8sdePLjrjrOFIzVnYl306HqrwVZurV4Oj+kW23pXYc2ZAjJ
MMIs3aH1VMUJ/+yF/PjPFPLagBEKg4reY53PftUMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzBfh1/Q
IHIsACgAAA==
mc.tgz.b64
    }

    # Usage: screenrc <unpack_dir>
    screenrc()
    {
        local func="${FUNCNAME:-screenrc}"

        local unpack_dir="${1:-missing 1st arg to ${func}() <unpack_dir>}"
# md5(screen.tgz.b64) = a358b5eea617ef59ae3e0c1f884f5c28
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'screen.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIACJPB2AAA+2UbWvbMBCA89m/4kgw3dgSkiVtRkqgafo2ysag60rpNpBl2RazpSIpTUOT/76T
nHbZOrYPo4zBPR98PuvepDu5Y7kRQhneeDq6yM5gECTys+wNhzuNXh+f3eGgP+w3ur3eoLfdgO4T
1vTAzDpmABpGa/c7uz+t/6e04PjdOZyFIYA2VEwq4FplMp8Z5qRWkMlSRC2YlCVoVwgDnfuRCUsW
5hKXrJ4ZLsAV0obP4DRIhebSgRXOSZXbjg8zc4U2I5gWRlonmYILdLeYmvs4tmMXdi/HMsoO11UU
tUJmPYdElylWVmrjjZXgwlpmFpBpg8krAUYwq1XUYs6ZYAcJNDtvmiHGB+FrrHdZYDSsDqtax+vA
ZB/GkDD+NTd6ptKXMDkaY2BRq5ETpuLsWqpMw61XYGuqW6+2d0aT/fGnw6vB693t3TitRuiGan+t
boXUh4ol/phmVoDOwBYyc+33+fk1MJU+qAdY+aM0y/C0y1u7NLc3DpzcGzmxV4c1DAN+rxnb4Arg
M2OEcpDk9d6iViqyBBvT1Kq5UQ5g8bUF+BR17jppG5dqX2zXlPFCQN9fUyilwm2E8+ZG43n65BHG
r1Wv1ZZRVDCT4r1yMwusnLOFLZl13h9DfhTYNSX9sLAkEeumotxwCqYbunUGBwi24rsxnKYrWMu4
PQ9vZnUV5MUqVhC79bfP91Yv5hC3x+h0eoyuJygvVkt8Xq7is7VyAPFbiFOIL4MTR7tpPInv2ivf
ROAFU7nASqvKNw1VwzgeFmRGV8CdKdvMz1R4S+CZqBgPHcdhrdgC5gx74u/G86glLPZYwJf9xEc+
kanY2PnoPlgWJRIzZSBuWAnNjbOQucLjaqLvmZ/kX/ge1b5Hj31/bEYz+td/H4IgCIIgCIIgCIIg
CIIgCIIgCIIgCIIgCOJv+QaJWQ8qACgAAA==
screen.tgz.b64
    }

    # Usage: xfce4 <unpack_dir>
    xfce4()
    {
        local func="${FUNCNAME:-xfce4}"

        local unpack_dir="${1:-missing 1st arg to ${func}() <unpack_dir>}"
# md5(xfce4.tgz.b64) = 8182334f0d8d3b3c75a03add389647c1
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'xfce4.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
W9rSlra05T9W/gWbedbXABgBAA==
xfce4.tgz.b64
    }

    # Usage: rsync_wrapper <unpack_dir>
    rsync_wrapper()
    {
        local func="${FUNCNAME:-rsync_wrapper}"

        local unpack_dir="${1:-missing 1st arg to ${func}() <unpack_dir>}"
# md5(rsync-wrapper.tgz.b64) = 27ba0336474bbc375511fb86a0e5ee50
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'rsync-wrapper.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
rsync-wrapper.tgz.b64
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
            ln -snf '.local/bin' "$d/bin"
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
    rsync_wrapper "$t"

    # /etc/skel
    t="$install_root/etc/skel"

    make_xdg_dirs "$t"
    mc_ini "$t"
    screenrc "$t"
    xfce4 "$t"
    ssh_agent_start4bashrc "$t"
    rsync_wrapper "$t"

    unset -f make_xdg_dirs mc_ini screenrc xfce4 ssh_agent_start4bashrc
}

# Usage: config_autopass
config_autopass()
{
    local unpack_dir="$install_root"
# md5(autopass.tgz.b64) = 9e9ac091b483fac9c63c40950b935faf
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'autopass.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIACFPB2AAA+1XbU8jNxDms3/FNEQKqLdJNkCgEYsERzgh0eNKilodik5md5K1uvHmbC8hpfnv
HTubECjcVTrEtZKfL56M58U7O3lmXWjVyMQ13mLc4IXJx1zruk7XXhJNwu7OjlsJj9eQNtfCrd3d
dnN3e2t3a60ZbrdarTVovugpnkGhDVcAayrPzZfsvrb/P8X6D41rIRs6ZWwdLvBzIRTqDhi1EW6+
gRR54gSN8zVObYNM7A/rcKn5EDswnoz4HwhX+xnKoUkP+iQOPo0nn/joWgyLvNAHfTY32thkdwwI
63Ci8hG5DlE2yFRxmdRjt5XlMc9g1T2qHe29a5+GWfP8l+PezsdWjTlLvCHDihMtjIIgiaHWDH7i
wZ+Hwcca7DcSvGkUNjplax24n7LIMvhr6Va9a3V+dL5Qqa6mrTx0mC09bF0goEzVu7AThO1ZzW3N
T4JxmrPZSnlW/ldUmEKjchWyKiqYk1cLxaxFVHGhbdfNKswVPVcJaTfKYttDB3szWreC2WaFscWr
gf397vkJq9oonerCk1kdi7mBg4NaA03cEFoXWCutz/KhkMA1ODcotJBDWDrDQqizeRy8FQaa7Hs3
r8c3w3aCnuo4lwMxXE6Al81hSb69vf0s/4fb4WP+D7e2PP+/BoileqhuRIww74GC+B/0GGMxEJhA
9bLXvQAex3khDUyESR2dEWmj4gbvqYECzVnjAeEm3HAgEUbcxCmZXy25uX9X/XDY6511388Abw3K
BG0QhcMiozeCt2M6iRa5pBTGoJJvIB8b+s2zbErbcVYkNt+SOmk4ccVjMtUUp0xIKa+ncPVofPSf
SFNn6+T2PjcIJiWe/HIGGNjp9XQptHuMpIipkiZFoeBzwTNhpnU4NTASw9TANUKCWih+nVG+HISM
FXJNvF4WhTQUxp0ktnqXL8EBLzIDe9YlbEGuYEhulETV5wOHyFvyEZJ8PLftgO1cejb7IiMn0+aH
BbPPJ/aq+R7ZlmeIwpY17rpK4HOVXnqy7u9vzy6Pu58Ofz46fXd5ftmLQj8j/tso+d/gKCnXlWvA
nBi+OcdX+N+y/iP+b7fD0PP/a+DqUgrTZ8eoYyUcvUZvF3MA3Lfgv+F+65KJ2OhIp4VJ8omsU1WH
aNjhgFgiKjsssAEDPefbZX/BOJuO8sKkAd0+TDDhwiy2SncVB+5OsPRQKWYBEV+Sy2x6ry0V7qt5
GeIIB7nCiA5DBFyeil2VQ6/Pfp2OMcol6pSY8QJHXEiXtEufuNEUNevS1bhHfiZqFE9flunWYMm1
QmtJnFb8BxlWWFfeCJXLEUoT3dPxqnZBvHur2hORYRQ0nv5Uo2c5ldTDWdZnv3FJr+Vo+vBhv3eL
eXh4eHh4eHh4eHh4eHh4eHh4eHh4eHi8Mv4G9ElytgAoAAA=
autopass.tgz.b64
}

## Parse options

# Distribution to install/setup
distro="$(distro_name)"
# Fedora/CentOS release version
releasever="$(distro_version)"
# System processor (CPU) architecture (default: running system)
arch="$(uname -m)"

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
_nameservers='1.1.1.1 8.8.8.8'
nameservers=''
# DNS split using NetworkManager and dnsmasq
nm_dnsmasq_split=''

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
    --releasever=$releasever
        Supported distribution release version
    --arch=$arch
        System processor (CPU) architecture to install packages for.
        Only AMD64 (x86_64) and i386 (i686) supported at the moment

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
    --nm-dnsmasq-split=${nm_dnsmasq_split:-<none>}, --no-nm-dnsmasq-split
        Configure or do not configure NetworkManager with DNS split. Available
        options are 1 with dnsmasq(8) instance supervised by NetworkManager, 2
        with external dnsmasq(8) instance and NetworkManager dispatcher hooks to
        manage split records in /run/dnsmasq.servers-file.

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

        --nm-dnsmasq-split)
            [ -n "${2-}" ] || exit
            nm_dnsmasq_split="$2"
            arg="--nm-dnsmasq-split '$nm_dnsmasq_split'"
            shift
            ;;
        --nm-dnsmasq-split=*)
            nm_dnsmasq_split="${1##--nm-dnsmasq-split=}"
            [ -n "$nm_dnsmasq_split" ] || exit
            arg="--nm-dnsmasq-split='$nm_dnsmasq_split'"
            ;;
        --no-nm-dnsmasq-split)
            nm_dnsmasq_split=''
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
    'centos') ;;
    'fedora') ;;
    *)      fatal 'Unsupported distribution "%s"\n' "$distro" ;;
esac

# $arch, $basearch
case "$arch" in
    'x86_64') basearch='x86_64' ;;
    i?86)   basearch='i386'   ;;
    *)      fatal 'Unsupported architecture "%s"\n' "$arch" ;;
esac

# $selinux
case "$selinux" in
    'enforcing'|'permissive'|'disabled'|'') ;;
    *) fatal 'Unknown SELinux mode "%s"\n' "$selinux" ;;
esac

# $cc handled after release package(s) installation

# $config
if [ -n "$config" ]; then
    if [ -z "${config##*://*}" ]; then
        url="$config"
        config="$this_dir/${config##*/}"
        safe_curl "$url" $((128*1024)) >"$config" ||
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
        fatal 'fail to resolve install root to absolute path\n'
    install_root="${install_root%/}"

    [ -n "$install_root" ] || build_info=''
else
    install_root='/'
    build_info=''
fi

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

# $nameservers

if [ -n "${nameservers-}" ]; then
    nameservers="$(IFS=',' && echo $nameservers)"
fi

# $nm_dnsmasq_split

case "${nm_dnsmasq_split-}" in
    '1'|'2'|'') ;;
    *) fatal 'nm-dnsmasq-split option should be 1 or 2\n' ;;
esac

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

        # Configure networking
        config_network

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

## Install core components

# start timestamp
start_timestamp="$(date '+%s')"
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
            distro_version "$install_root"
        )"
        if [ -z "${releasever%%*-stream}" ]; then
            releasemaj="${releasever%-stream}"
            releasemin="$(centos_stream_compose_id)"
        else
            releasemaj="${releasever%%.*}"
            releasemin="${releasever#$releasemaj.}"
            releasemin="${releasemin%%.*}"
        fi
        releasemm="$releasemaj.$releasemin"

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

        # common
        EPEL_RELEASE_RPM_NAME='epel-release'
        ELREPO_RELEASE_RPM_NAME='elrepo-release'
        RPMFUSION_RELEASE_RPM_NAME='rpmfusion-free-release'

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
            if [ $releasemaj -eq 8 ] && version_lt $releasemm 8.3; then
                # Enable PowerTools if EPEL is enabled to satisfy dependencies
                in_chroot "$install_root" \
                    'yum config-manager --set-enabled PowerTools' \
                    #
            fi

            in_chroot <"$rpm_gpg_dir/epel/RPM-GPG-KEY-EPEL-$releasemaj" \
                "$install_root" \
                "
                 rpm --import '/dev/stdin' && {
                     rpm -U '$EPEL_RELEASE_URL' || \
                     rpm --quiet -q '$EPEL_RELEASE_RPM_NAME'
                 }
                " \
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

                if [ $releasemaj -eq 4 ] && version_le $releasemm 4.3; then
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
                "
                 rpm --import '/dev/stdin' && {
                     rpm -U '$ELREPO_RELEASE_URL' || \
                     rpm --quiet -q '$ELREPO_RELEASE_RPM_NAME'
                 }
                " \
            && has_enable 'repo' || repo_elrepo=''
        fi

        # VirtIO-Win
        if [ -n "$repo_virtio_win" ]; then
            safe_curl "$VIRTIO_WIN_URL" 1024 \
                >"$install_root/etc/yum.repos.d/virtio-win.repo" \
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
                "
                 rpm --import '/dev/stdin' && {
                     rpm -U '$RPMFUSION_RELEASE_URL' || \
                     rpm --quiet -q '$RPMFUSION_RELEASE_RPM_NAME'
                 }
                " \
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
        if [ -z "${releasever%%*-stream}" ]; then
            releasemaj="${releasever%-stream}"
            releasemin="$(centos_stream_compose_id)"
        else
            # There is some incompatibility with rpmdb(1)
            # format that can't be addressed with rpmdb_dump/load
            # helpers: install last supported and then update.
            [ $releasever != '6.10' ] ||
                releasever='6.9'

            releasemaj="${releasever%%.*}"

            if [ "$releasemaj" != "$releasever" ]; then
                releasemin="${releasever#$releasemaj.}"
                releasemin="${releasemin%%.*}"
            else
                releasemin=${_releasemin}
            fi
        fi

        [ $releasemaj -ge 4 ] ||
            fatal 'no support for CentOS before 4 (no yum?)\n'
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
            safe_curl "$base" $((128*1024)) -L >/dev/null &&
        echo "baseurl='$base'" || return

        updates="$(
            [ $releasemaj -le 7 ] &&
                arch="updates/$basearch" || arch="AppStream/$basearch/os"

            printf -- "$templ" \
                "$host" "$subdir" "$releasever" "$arch"
        )"
        [ "$base" != "$updates" ] &&
            safe_curl "$updates" $((128*1024)) -L >/dev/null &&
        echo "updatesurl='$updates'" ||:
    }
      if url="$(host='mirror' release_url)"; then
        # Current
        is_archive=''
    elif url="$(host='vault' subdir="${subdir#centos}" release_url)"; then
        # Archive
        is_archive='1'
    else
        fatal "CentOS $releasever isn't available for download\n"
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
        releasemm="$releasever"

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
            fatal 'no support for Fedora before 10 (Fedora Core?)\n'
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
        fatal "Fedora $releasever isn't available for download\n"
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

# Always install archivers
PKGS="${PKGS:+$PKGS }tar bzip2 gzip xz"

# Pick repo names on host to configure and use for initial setup
eval $(
    yum --noplugins -C repolist | \
    sed -n -e '2,$ s,^\W\?\([^[:space:]/]\+\).*$,\1,p' | \
    sed -n -e '1 s,.\+,baserepo=\0,p' \
           -e '2 s,.\+,updatesrepo=\0,p'
)
[ -n "${baserepo-}" ] || baseurl=''
[ -n "${updatesrepo-}" ] || updatesurl=''

# Extract gpg keys used to sign rpm in repos
rpm_gpg_dir="$(mktemp -d -p '' 'rpm-gpg.XXXXXXXX')" || exit
config_rpm_gpg

# Prepare filesystem

if [ -n "${install_root%/}" ]; then
    # Bind mount proc, sys and dev filesystems
    for f in '/proc' '/sys' '/dev'; do
        d="$install_root$f"
        install -d "$d" && mount --bind "$f" "$d"
    done

    # Point /etc/mtab to /proc/self/mounts unless it already exist
    f="$install_root/etc/mtab"
    if [ ! -f "$f" ]; then
        install -D -m 0644 /dev/null "$f"
        ln -snf '../proc/self/mounts' "$f"
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
fi
cd "$install_root"

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
        --releasever=$releasever
     } \
    ${baseurl:+
        --disablerepo='*'
        --enablerepo="$baserepo"
        --setopt="$baserepo.baseurl=$baseurl"
        ${updatesurl:+
            --enablerepo="$updatesrepo"
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

# $nm_dnsmasq_split

case "${nm_dnsmasq_split-}" in
    '1') if centos_version_lt $releasemaj 7 ||
            fedora_version_lt $releasemaj 15
         then
             # Too old NetworkManager
             nm_dnsmasq_split=''
         else
             pkg_nm=1
         fi
         ;;
    '2') if centos_version_lt $releasemm 7.4 ||
            fedora_version_lt $releasemaj 21
         then
             # Too old dnsmasq
             nm_dnsmasq_split=''
         else
             pkg_nm=1 && pkg_dnsmasq=1
         fi
         ;;
esac

if [ -n "$nm_dnsmasq_split" ]; then
    # No minimal install as we need at least NetworkManager
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

pkg_remmina_plugins_secret=1
pkg_wireshark_gnome=1

  if is_centos; then
    if centos_version_gt $releasemaj 7; then
        if is_centos_stream; then
            pkg_wireshark_gnome=
        fi

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
        # https://forums.centos.org/viewtopic.php?t=72433
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
elif is_fedora; then
    if fedora_version_le $releasemaj 27; then
        if fedora_version_le $releasemaj 26; then
            if fedora_version_le $releasemaj 25; then
                if fedora_version_le $releasemaj 24; then
                    if fedora_version_le $releasemaj 19; then
                        if fedora_version_le $releasemaj 18; then
                            if fedora_version_le $releasemaj 15; then
                                if fedora_version_le $releasemaj 14; then
                                    if fedora_version_lt $releasemaj 12; then
                                        pkg_vdpau=
                                    fi # < 12
                                    pkg_va=
                                fi # <= 14
                                [ "${x11_server-}" != 'Xspice' ] ||
                                    x11_server='Xorg'
                            fi # <= 15
                            pkg_va_vdpau_driver=
                        fi # <= 18
                        [ "${x11_server-}" != 'x2go' ] || x11_server='Xorg'
                    fi
                    pkg_glvnd=

                    pkg_chromium=
                    pkg_pidgin_hangouts=

                    pkg_nm_openconnect=
                    pkg_nm_l2tp=
                fi # <= 24
                pkg_driverctl=

                pkg_slick_greeter=

                pkg_glvnd_egl=
                pkg_glvnd_gles=
                pkg_glvnd_glx=
            fi # <= 25
            pkg_va_intel_hybrid_driver=
        fi # <= 26
        pkg_iucode_tool=
        pkg_remmina_plugins_secret=
    fi # <= 27
    if fedora_version_ge $releasemaj 24; then
        pkg_wireshark_gnome=
    fi # >= 24
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

    if is_centos || fedora_version_gt $releasemaj 26; then
        # grub2-pc
        [ -z "${pkg_grub2_pc-}" ] || PKGS="$PKGS grub2-pc"
        # grub2-efi-ia32
        [ -z "${pkg_grub2_efi_ia32-}" ] || PKGS="$PKGS grub2-efi-ia32"
        # grub2-efi-x64
        [ -z "${pkg_grub2_efi_x64-}" ] || PKGS="$PKGS grub2-efi-x64"
    else
        # grub2 (pc)
        [ -z "${pkg_grub2_pc-}" ] || PKGS="$PKGS grub2"
        # grub2-efi (x64)
        [ -z "${pkg_grub2_efi_x64-}" ] || PKGS="$PKGS grub2-efi"
    fi
fi

pkg_switch kernel
if [ -n "${pkg_kernel-}" ]; then
    PKGS="$PKGS kernel microcode_ctl"

    if centos_version_lt $releasemaj 7 ||
       fedora_version_le $releasemaj 12
    then
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

[ -z "${pkg_dnsmasq-}" ] || PKGS="$PKGS dnsmasq"

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
            if centos_version_ge $releasemm 7.4 &&
               centos_version_lt $releasemm 8.3
            then
                # libreoffice-gtk2
                pkg_enable libreoffice_gtk2
                [ -z "${pkg_libreoffice_gtk2-}" ] ||
                    PKGS="$PKGS libreoffice-gtk2"
            fi
            if centos_version_ge $releasemm 7.4; then
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
            elif is_centos || fedora_version_ge $releasemaj 26; then
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
                [ -z "${pkg_remmina_plugins_secret-}" ] ||
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

       if [ -n "${gtk_based_de-}" ]; then
           # wireshark-gnome
           [ -z "${pkg_wireshark_gnome-}" ] || PKGS="$PKGS wireshark-gnome"
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
