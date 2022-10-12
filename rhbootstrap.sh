#!/bin/sh

# MIT License
#
# Copyright (c) 2020-2022 Serhey Popovych <serhe.popovych@gmail.com>
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
#           base64(1), tr(1), date(1), timeout(1), tee(1)

# Set option(s)
set -e
set -u

# Enable debug/trace
#exec 2>"/tmp/${0##*/}.debug.$(date '+%s.%N')"
#set >&2
#set -x

readonly _this_prog='rhbootstrap.sh'

if [ ! -e "$0" -o "$0" -ef "/proc/$$/exe" ]; then
    # Executed script is
    #  a) read from stdin through pipe
    #  b) specified via -c option
    #  d) sourced
    this_prog="${_this_prog}"
    this="$this_prog"
    this_dir='./'
else
    # Executed script exists and it's inode differs
    # from process exe symlink (Linux specific)
    this="$0"
    this_dir="${this%/*}/"

    this_prog="${this##*/}"
    [ "$this_prog" != 'sh' ] || this_prog="${_this_prog}"
fi
this_dir="$(cd "$this_dir" && echo "$PWD")"

# Set program name unless already set
[ -n "${prog_name-}" ] &&
[ -n "${prog_name##*[^[:alnum:]_]*}" ] &&
[ -n "${prog_name##[[:digit:]]*}" ] || prog_name="$this_prog"

readonly _prog_name="$prog_name"

prog_name="${prog_name%\.sh}"
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
    msg "$@" || return
}

# Usage: error <fmt> ...
error()
{
    msg "$@" >&2 || return
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

    # Usage: return_rc
    return_rc()
    {
        [ $rc -ne 0 ] && return $rc || return 123
    }

    printf >&2 -- '%s: ' "$prog_name"

    return_rc || error_exit "$@"
}

# Usage: abort <fmt> ...
abort()
{
    local rc=$?
    trap - EXIT
    V=1 error "$@" ||:
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

__cfg_comment__=''

# Usage: cfg_begin <comment>
cfg_begin()
{
    local func="${FUNCNAME:-cfg_begin}"

    if [ -n "${__cfg_comment__}" ]; then
        fatal '%s: config nesting is not supported: end config "%s" first.\n' \
            "${func}" \
            "${__cfg_comment__}" \
            #
    fi

    local comment="${1:?missing 1st arg to ${func}() <comment>}"

    printf -- '## %s-begin-%s\n' \
        "$prog_name" \
        "$comment" \
        #

    __cfg_comment__="$comment"
}

# Usage: cfg_end <comment>
cfg_end()
{
    local func="${FUNCNAME:-cfg_end}"

    if [ -z "${__cfg_comment__}" ]; then
        fatal '%s: no config to end: begin new config first.\n' \
            "${func}" \
            #
    fi

    local comment="${1:?missing 1st arg to ${func}() <comment>}"

    if [ "${comment}" != "${__cfg_comment__}" ]; then
        fatal '%s: config commet mismatch: begin with "%s", end with "%s"\n' \
            "${func}" \
            "${__cfg_comment__}" \
            "${comment}" \
            #
    fi

    printf -- '## %s-end-%s\n' \
        "$prog_name" \
        "$comment" \
        #

    __cfg_comment__=''
}

# Usage: cfg_strip <comment> [<file>]
cfg_strip()
{
    local func="${FUNCNAME:-cfg_strip}"

    local comment="${1:?missing 1st arg to ${func}() <comment>}"
    local file="${2-}"

    local begin_r="^$(
        __cfg_comment__=''           cfg_begin "$comment" | \
        sed -e 's,[]\/$*.^[],\\&,g'
    )$"
    local end_r="^$(
        __cfg_comment__="${comment}" cfg_end   "$comment" | \
        sed -e 's,[]\/$*.^[],\\&,g'
    )$"

    sed ${file:+-i "$file"} \
        -e "/$begin_r/,/$end_r/ d" \
        #
}

# Usage: cfg_replace <comment> <file> [<text>]
cfg_replace()
{
    local func="${FUNCNAME:-cfg_replace}"

    local comment="${1:?missing 1st arg to ${func}() <comment>}"
    local file="${2:?missing 2d arg to ${func}() <file>}"
    local text="${3-}"

    if [ -n "$text" ]; then
        local begin="$(__cfg_comment__=''           cfg_begin "$comment")"
        local   end="$(__cfg_comment__="${comment}" cfg_end   "$comment")"

        local begin_r="^$(
            printf -- '%s\n' "$begin" | \
            sed -e 's,[]\/$*.^[],\\&,g'
        )\$"
        local end_r="^$(
            printf -- '%s\n' "$end" | \
            sed -e 's,[]\/$*.^[],\\&,g'
        )\$"

        local addr="/$begin_r/,/$end_r/"

        if [ -n "$(sed -n -e "$addr p" "$file")" ]; then
            # replace
            text="$(
                printf -- '%s\n%s\n%s\n' \
                    "$begin" "$text" "$end" | \
                sed -e 's,$,\\,'
            )"
            text="${text%\\}"

            sed -i "$file" \
                -e "$addr c$text" \
                #
        else
            # append
            if ! [ -n "${_cfg_replace_append_nohdr-}" ]; then
                text="$begin
$text
$end
"
            fi
            printf -- '%s' "$text" >>"$file"
        fi
    else
        cfg_strip "$comment" "$file"
    fi
}

# Usage: cfg_replace_append_nohdr <comment> <file> [<text>]
cfg_replace_append_nohdr()
{
    local _cfg_replace_append_nohdr='1'
    cfg_replace "$@" || return
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

# Usage: selinuxenabled
selinuxenabled()
{
    in_chroot "$install_root" '
        {
            # libselinux-utils
            command -v selinuxenabled || exit 3
            # SELinux enabled
            selinuxenabled || exit 2
        } >/dev/null 2>&1
    ' || return
}

# Usage: semode_text2rc <mode>
semode_text2rc()
{
    case "${1-}" in
        '0'|'Permissive')
            return 0
            ;;
        '1'|'Enforcing')
            return 1
            ;;
        *)
            local func="${FUNCNAME:-semode_text2rc}"
            echo >&2 "${func}: invalid <mode>, see setenforce(8) for valid modes"
            return 2
            ;;
    esac
}

# Usage: _setenforce <mode>
_setenforce()
{
    in_chroot "$install_root" '
        {
            # libselinux-utils
            command -v setenforce || exit 3
            # Set mode
            setenforce "$1"
        } >/dev/null 2>&1
    ' - "$1" || return
}

# Usage: setenforce <mode>
setenforce()
{
    local mode="${1-2}"

    semode_text2rc "$mode" && mode=0 || mode=$?
    [ $mode -le 2 ] || return 2

    _setenforce $mode
}

# Usage: getenforce
getenforce()
{
    local mode
    mode="$(
        in_chroot "$install_root" '
            {
                # libselinux-utils
                command -v getenforce >&2 || exit 3
                # Get mode
                getenforce
            } 2>/dev/null
        '
    )" && semode_text2rc "$mode" || return
}

# Usage: selinux_enforce()
selinux_enforce()    { setenforce 1 || return; }
# Usage: selinux_permissive()
selinux_permissive() { setenforce 0 || return; }

# Usage: setenforce_save <mode>
setenforce_save()
{
    local mode=${__selinux_saved_mode__-2}
    [ $mode -ge 2 ] || return 123

    semode_text2rc "${1-}" && mode=0 || mode=$?
    [ $mode -lt 2 ] || return 2

    local rc=0
    getenforce || rc=$?

    __selinux_saved_mode__=$rc

    [ $mode -eq $rc ] || _setenforce $mode || return
}

# Usage: setenforce_restore
setenforce_restore()
{
    local mode=${__selinux_saved_mode__-2}
    [ $mode -lt 2 ] || return 123

    unset __selinux_saved_mode__

    _setenforce $mode || return
}

# Usage: systemctl_edit <systemd.unit> [<file|fd>] [-- UNIT...]
systemctl_edit()
{
    local func="${FUNCNAME:-systemctl_edit}"

    local file=''
    while [ $# -gt 0 ]; do
        case "$1" in
            --) # systemctl edit UNIT...
                shift
                break
                ;;
             *) # file name or descriptor
                if [ -n "$file" ]; then
                    echo >&2 "${func}: expected argument delimiter (--)"
                    return 1
                fi
                file="${1:-0}"
                shift
                ;;
        esac
    done
    file="${file:-0}"

    # systemd-run(1) isn't available: cannot run "systemctl edit ..."
    # since it requires stdout and stderr to be valid TTY.
    #
    # See https://github.com/systemd/systemd/issues/21862 for details
    # of systemd.unit override creation from scripts.
    in_chroot "$install_root" \
        'command -v systemd-run >/dev/null 2>&1' ||
    return

    (
        # Note that file given by it's name must exist inside $install_root
        if [ -n "${file##*[^0-9&]*}" -a -n "${file##[0-9&]*&*}" ]; then
            fd="${file#&}" && fd="${fd:-0}"

            file="$(
                mktemp --dry-run --tmpdir="${install_root}tmp" "$func.XXXXXXXX"
            )" && mkfifo -m 0600 "$file" || exit
        else
            fd=''

            file="${file#$install_root}"
            file="${install_root}${file#/}"

            [ -e "$file" ] || exit
        fi

        # No SELinux policy for systemctl(1) supervised by systemd-run(1)
        setenforce_save 'Permissive'

        # This is main reason for putting entire block in subshell:
        # traps are reset in subshell.
        trap '
            if [ -n "$fd" ]; then
                rm -f "$file"
            fi
            setenforce_restore ||:
        ' EXIT INT TERM QUIT

        # Executed asynchronously if $file was originally file descriptor
        in_chroot "$install_root" \
            "exec >/dev/null 2>&1 </dev/null systemd-run \"\$@\" ${fd:+&}" - \
                --quiet \
                -t \
                --collect \
                --service-type='simple' \
                --setenv=SYSTEMD_EDITOR='tee' \
                -- \
            /bin/sh -c "exec <'/${file#$install_root}' systemctl edit \"\$@\"" \
                - \
                "$@" \
                #

        if [ -n "$fd" ]; then
            # Use tee(1) backed by timeout(1) instead of direct
            # append (>>) by a shell interpreter to avoid block on
            # write when $file is named pipe (fifo) and process on
            # other side (e.g. systemd-run(1), tee(1) or systemctl)
            # does not send EOF (e.g. exited due to error).
            #
            # Note that it is up to the caller to provide output on
            # $fd to avoid blocking on read.
            while read -r line; do
                printf -- '%s\n' "$line"
            done <&"$fd" | timeout 5 tee --append "$file" >/dev/null 2>&1
        fi
    ) || return
}

# Usage: _yum ...
_yum()
{
    local cmd="exec ${_xargs_yum:+xargs }yum \"\$@\""

    set -- \
        ${install_langs:+
            ${has_setopt:+"--setopt=override_install_langs=$install_langs"}
         } \
        ${nodocs:+
            ${has_setopt:+'--setopt=tsflags=nodocs'}
         } \
        ${install_weak_deps:+
            ${has_setopt:+"--setopt=install_weak_deps=$install_weak_deps"}
         } \
        "$@" \
        #

    if [ -n "${_install_root}" ]; then
        in_chroot "${_install_root}" "$cmd" - "$@"
    else
        setarch "$basearch" /bin/sh -c "$cmd" - "$@"
    fi || return
}

# Usage: yum ...
yum()
{
    local _install_root=''
    local _xargs_yum=''
    _yum "$@" || return
}

# Usage: in_chroot_yum ...
in_chroot_yum()
{
    local _install_root="${install_root-}"
    local _xargs_yum=''
    _yum "$@" || return
}

# Usage: xargs_yum ...
xargs_yum()
{
    local _install_root=''
    local _xargs_yum='1'
    _yum "$@" || return
}

# Usage: in_chroot_xargs_yum ...
in_chroot_xargs_yum()
{
    local _install_root="${install_root-}"
    local _xargs_yum='1'
    _yum "$@" || return
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

version_le() { [ "$(version_cmp "$@")" -le '0' ] || return; }
version_ge() { [ "$(version_cmp "$@")" -ge '0' ] || return; }

version_neq() { ! version_eq "$@" || return; }

is_rocky()  { [ "${distro-}" = 'rocky' ] || return; }
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

# Usage: rocky_version_cmp <v1> <v2>
rocky_version_cmp()
{
    is_rocky && version_cmp "${1-}" "${2-}" || return
}

rocky_version_lt() { [ "$(rocky_version_cmp "$@")" = '-1' ] || return; }
rocky_version_eq() { [ "$(rocky_version_cmp "$@")" =  '0' ] || return; }
rocky_version_gt() { [ "$(rocky_version_cmp "$@")" =  '1' ] || return; }

rocky_version_le()
{
    rocky_version_lt "$@" || rocky_version_eq "$@" || return
}
rocky_version_ge()
{
    rocky_version_gt "$@" || rocky_version_eq "$@" || return
}

rocky_version_neq() { ! rocky_version_eq "$@" || return; }

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
        -e '1 s/^\(Fedora\|CentOS\|Rocky\)\s\+.*$/\1/p' \
        "$root/etc/redhat-release" | \
    tr '[:upper:]' '[:lower:]'
}

# Usage: distro_version [<root>]
distro_version()
{
    local root="${1-}"

    sed -n \
        -e '1 s/^CentOS\s\+Stream\s\+.\+\s\+\([0-9]\+\).*$/\1-stream/p' \
        -e '1 s/^\(Fedora\|CentOS\|Rocky\)\s\+.\+\s\+\([0-9.]\+\).*$/\2/p' \
        "${root%/}/etc/redhat-release" \
        #
}

## Post install configuration snippets

# Usage: config_rpm_gpg
config_rpm_gpg()
{
    local unpack_dir="$rpm_gpg_dir"
# md5(rpm-gpg.tgz.b64) = bc7854373e8c29969f8be72c1dbad964
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'rpm-gpg.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
/ehHP/rRj370ox/96P8f/W+Rw653AIAHAA==
rpm-gpg.tgz.b64
}

# Usage: config_login_banners
config_login_banners()
{
    if [ -n "$login_banners" ]; then
        # Update /etc/issue, /etc/issue.net and /etc/motd banners
        $(
            PRETTY_NAME=''

            # Source in subshell to not pollute environment
            t="${install_root}etc/os-release"
            [ -f "$t" ] && . "$t" >/dev/null 2>&1 || PRETTY_NAME=''

            if [ -z "$PRETTY_NAME" ]; then
                t="${install_root}etc/redhat-release"
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
            banner="${install_root}etc/issue"
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
            banner="${install_root}etc/issue.net"
            if [ -f "$banner" ]; then
                cat >"$banner" <<'_EOF'
_EOF
            fi

            # /etc/motd
            banner="${install_root}etc/motd"
            if [ -f "$banner" ]; then
                cat >"$banner" <<'_EOF'
_EOF
            fi
        )
    fi
}

# Usage: config_network
config_network()
{
    nm_devgroup()
    {
        local unpack_dir="$install_root"
# md5(nm-devgroup.tgz.b64) = 0ab2661091f59a897181988fffe35fc6
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'nm-devgroup.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAA3WIGAAA+2VXU/bMBSGe51fcZZGy0BL8wFppAG9mTS0C2DaxBVCk3FPWotgR7bDN/99TtpV
LRKDDbQJ7Tw3sR2f9xzntR20PN5He6H06R6TbII6HgtTM8unqAfjuNYYNbVrJGk0xvOJVk3d+00S
R1EU3dNx/9m1080kSYd5kifDXpJtbOZZD7LB4Dlpn0ZjLNMAPa2U/dW8x96/UvAJ/o/VhXzODvgD
/4siJ///Bo/5/xLfv/M/zx/yP82SovU/TdI8G+YbvSQthmnRg+QF1/kg/7n//TcQnwgZnzAz9bw+
HBq3Bz5AUGs1+S7ZGcK2kBZ1yTiOYJtxK5QceUcQ9CGaIGRwDLe3gJfCQuJ5nBkEP8h8ENIDRzj7
gYS34c+bJFyDra3u3fraPK7tuDE0jLc17LFTBNNohAsEzqoKx8AMmKuzSshTpwyt1k1Tv2/17twu
dfVE1y7vTdLvr8dB5obW7/yl0lLPEyUczUrbWVQFx1tgpzgr9ePB/qfPuzt+3J4Jc2W4kqWYxHJ2
OiLDtaitiUXJy0kUpH4X1KlG2gnPwv0VyRY8ZxUE7xb9lj58U43m2K7FNCdmilUFVoFUFmpVVY1F
QHkutJJnKO1KrMs4WEo3it35jGXjBLLR2/Re8kURfKrA3/16cPhlJwxuukZ0F/orE0ux6K55SwNu
gbL9uPMof8VyrAx2s+biYyxZU9nQc8EeXiIHUUPnm0ELrlanlPrQ3Siu2UX53r8+BgRBEARBEARB
EARBEARBEARBEARBEATxqvkBy+LWjAAoAAA=
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
        } >>"${install_root}etc/NetworkManager/conf.d/dnsmasq.conf"
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
    local t="${install_root}etc/resolv.conf"
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
    if [ -d "${install_root}etc/sysconfig/network-scripts" ]; then
        if [ -n "${pkg_nm-}" ]; then
            nm_devgroup
        fi
    fi

    # Enable/disable legacy network scripts when no/ NetworkManager available
    if [ -x "${install_root}etc/init.d/network" ]; then
        if [ -z "${pkg_nm-}" ] ||
           rocky_version_ge $releasemaj 8 ||
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
# md5(xorg.tgz.b64) = 117b2f5acf423eada2f6c44b6997c92b
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'xorg.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAMBoT2AAA+2WUW/bNhDH/Wp9ioP6sHStJFKiRNt92da0dYAEDeAi2FuhSHRCxCYFkoqdfPqe
FDtJ3XTBMGNFUf4AUwZ1+t/9ffTZwlXJ35Qma20u4kqreVwngz1DEJ7n/RXZvfbvKSNpVhSM8nRA
aEaydAD5vgt5ita60gAMjNbun+Keu/+TIp7of04je6PKxsnK9nv/MUfX4IKx7/WfkiLb6X9BGR0A
2YvDZ/jF+x+8gEvnGjtJktVqFddiscCWLxPbNo02Lrk6r3WVCBVVZdL1Ksd2saQxopJWahWtGxu1
561ybXQhlDDlInK6rS6bso6WurUikta2IprLdYC5DqUtzxcC+lhZwWx7zqAW17ISr6G0sBK/GQGt
leoCHwkPj48JJ2xCKJDi7V8TXvz5Dj5tkoQYoQ1YuZQL7OOdyoF9CXPdqhqkAoVVdrbA3lgnljbu
6piW16gOy3bhZIP1bGveCFgwrVJdRHf80YXFp1VdiqVWwUxUDq1DeKSa1r1dlNaGAWw4qoVyci6F
gRDNnc6S9JHJvurTrupt/EnpcMfouq3cv3jiyG4/AAi12rn5cQbhsVTtemf/sPd2WrpLCBM0msjO
QCKuseTfH2I/Nht7F0obEd4leKfqje/gRx9Zzx55av6PCX51lXTa7GP6Pzv/CWd8QDPOC5qxrIuj
eZHlfv7/H9wPs5O7jofB8GGEDcMzaVyLM52EQTB8ATQdkTVPCfwBBYkJgektHHz49P4lXOJ8rCbA
WMwLuJrevoGmWlxNgLOYjeBkehsMTzSOYakEhFuZz71ICJuoXh5olhVAGU+B4v8BvIfpeErxxTCu
AIimOB4reHXWpfxKFv9ArHkxepAlcU5QFvdx4QyXES457WSLEXCOspgIj969bHQ262XRbEHIeky+
bzbP43H62Cyl4y5u1+1G576sTVifAJcxFjdCpynaB+gSjvGnbkwYjLN0124wvBvPw2F4asRcGCPq
LlX4jf3HI9vPbI/H4/F4PB6Px+PxeDwej8fj8Xg8Ho/nV+AL5bEV4gAoAAA=
xorg.tgz.b64
}

# Usage: config_xrdp
config_xrdp()
{
    local dir="${install_root}etc/xrdp"
    if [ -d "$dir" ]; then
        local file

        # Force security layer to tls,
        # uncomment [Xorg] section for xrdp
        # comment [Xvnc] section
        file="$dir/xrdp.ini"
        if [ -f "$file" ]; then
            sed -i "$file" \
                -e 's,^\(security_layer\)=.\+$,\1=tls,g' \
                -e '/^#\[Xorg\]$/,/^\[Xvnc\]$/s,^#,,' \
                -e '/^\[Xvnc\]$/,/^port=-1$/s,^,#,' \
                #
        fi

        # Add Ukrainian keyboard and configure layout change
        # using Left_Ctrl+Left_Win sequence
        file="$dir/xrdp_keyboard.ini"
        if [ -f "$file" ] &&
           ! grep -q '^\[rdp_keyboard_ua\]$' "$file"
        then
            cat >>"$file" <<'_EOF'

[rdp_keyboard_ua]
keyboard_type=4
keyboard_subtype=1
model=pc104
variant=us
options=grp:lctrl_lwin_toggle
rdp_layouts=default_rdp_layouts
layouts_map=layouts_map_ch

[layouts_map_ch]
rdp_layout_us=us,ru,ua
rdp_layout_ru=us,ru,ua
rdp_layout_ua=us,ru,ua
_EOF
        fi

        # Add port 3389 to firewall
        local p1='-A INPUT -p tcp -m state --state NEW -m'
        local p2='--dport'
        local p3='22,\|[0-9]\+,22,[0-9]\+\|,22\|22'
        local p4='-j ACCEPT'

        local regexp="^\($p1\) tcp \($p2\) \($p3\) \($p4\)$"
        local repl='\1 multiport \2s \3,3389 \4'

        for file in \
            'iptables' \
            'ip6tables' \
            #
        do
            file="${install_root}etc/sysconfig/$file"
            if [ -f "$file" -a -s "$file" ]; then
                sed -i "$file" \
                    -e "/[ ,]3389[, ]/ !s/$regexp/$repl/" \
                    #
            fi
        done

        if is_rocky || is_centos || fedora_version_ge $releasemaj 18; then
            # Keep opened sessions when xrdp.service stopped or
            # restarted what is quite common on package upgrade.
            systemctl cat 'xrdp-sesman.service' | \
                sed -e '/^\(BindsTo\|StopWhenUnneeded\)=/d' | \
            systemctl_edit -- --full 'xrdp-sesman.service'

            in_chroot "$install_root" 'systemctl enable xrdp-sesman.service'
        fi

        in_chroot "$install_root" 'systemctl enable xrdp.service'
    fi
}

# Usage: config_sshd
config_sshd()
{
    local file="${install_root}etc/ssh/sshd_config"
    if [ -f "$file" ]; then
        local dir="$file.d"
        if [ -d "$dir" ] &&
           grep -q "^\s*Include\s*/${dir#$install_root}/\*\.conf" "$file"
        then
            file="$dir/99-$prog_name.conf"
            cat >"$file" <<'_EOF'
AllowGroups root users
PermitRootLogin prohibit-password
UseDNS no
VersionAddendum none
_EOF
        else
            sed -i "$file" \
                -e '/^#\?LoginGraceTime/iAllowGroups root users' \
                -e 's/^#\?\(PermitRootLogin\s\+\).*$/\1without-password/' \
                -e 's/^#\?\(UseDNS\s\+\).*$/\1no/' \
                -e 's/^#\?\(VersionAddendum\s\+\).*$/\1none/' \
                #
        fi

        in_chroot "$install_root" 'systemctl enable sshd.service'
    fi
}

# Usage: config_fail2ban
config_fail2ban()
{
    local file="${install_root}etc/fail2ban/jail.conf"
    if [ -f "$file" ]; then
        local dir="${file%/*}"

        local increment=''
        if grep -q '^#\?bantime\.increment\s*=\s*' "$file"; then
            increment='true'
        fi

        local tables='iptables'
        if [ -f "${install_root}etc/sysconfig/nftables.conf" -a \
             -f "$dir/action.d/nftables-allports.conf" ]
        then
            if ! centos_version_le $releasemaj 7 &&
               ! fedora_version_le $releasemaj 33
            then
                tables='nftables'
            fi
        fi

        # filter.d/xrdp.conf
        file="${install_root}etc/fail2ban/filter.d/xrdp.conf"
        if [ ! -f "$file" ]; then
            cat >"$file" <<'_EOF'

[Definition]
failregex = connection received from <HOST> port \d+
ignoreregex =
datepattern = %%Y%%m%%d-%%H:%%M:%%S

# DEV NOTES:
#
# https://stackoverflow.com/questions/65491510/regexp-for-fail2ban-for-xrdp-log
_EOF
        fi

        local _cfg_replace_append_nohdr=''
        if [ -d "$dir/jail.d" ]; then
            dir="$dir/jail.d"
            file="$dir/99-$prog_name.conf"
            : >"$file"
            _cfg_replace_append_nohdr='1'
        else
            file="$dir/jail.local"
        fi

        # default
        cfg_replace 'default' "$file" "
[DEFAULT]
${increment:+
bantime.increment = true
bantime.rndtime = 30m
bantime.maxtime = 20d
bantime.overalljails = true}
bantime  = 3h
findtime  = 30m

banaction = ${tables}
banaction_allports = ${tables}-allports
"
        # openssh-service
        if [ -f "${install_root}etc/ssh/sshd_config" ]; then
            cfg_replace 'sshd' "$file" '
[sshd]
ignoreip = 127.0.0.1
enabled = true
maxretry = 10
'
        fi

        # xrdp
        if [ -f "${install_root}etc/xrdp/xrdp.ini" ]; then
            cfg_replace 'xrdp' "$file" '
[xrdp]
ignoreip = 127.0.0.1
enabled = true
maxretry = 5
port = 3389
logpath = /var/log/xrdp.log
'
        fi

        in_chroot "$install_root" 'systemctl enable fail2ban.service'
    fi
}

# Usage: config_lvm2
config_lvm2()
{
    # Disable lvmetad to conform to CentOS 8+
    local t="${install_root}etc/lvm/lvm.conf"
    if [ -f "$t" ] && grep -q '^\s*use_lvmetad\s*=' "$t"; then
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
    local t="${install_root}etc/modprobe.d/kvm.conf"
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
    local t="${install_root}etc/libvirt/qemu.conf"
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
    local t="${install_root}etc/libvirt/libvirtd.conf"
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
                if v=\"\${$n-}\" && [ -n \"\$v\" ]; then
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

        if grep -q 'SocketMode=' "${install_root}etc/libvirt/libvirtd.conf"; then
            systemctl_edit -- 'libvirtd.socket' <<EOF
[Socket]
${libvirt_unix_group:+SocketGroup=$libvirt_unix_group}
${libvirt_unix_rw_perms:+SocketMode=$libvirt_unix_rw_perms}
EOF

            systemctl_edit -- 'libvirtd-ro.socket' <<EOF
[Socket]
${libvirt_unix_group:+SocketGroup=$libvirt_unix_group}
${libvirt_unix_rw_perms:+SocketMode=$libvirt_unix_ro_perms}
EOF
        fi
    fi
}

# Usage: config_virt_p2v
config_virt_p2v()
{
    local user='virt-p2v'

    # Add sudoers(5) file
    local t="${install_root}etc/sudoers.d"
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
        "useradd -M -r -d / -s '/bin/sh' '$user'"

    # Add user to libvirt group and change it's ~ if libvirt installed
    if [ -n "${pkg_libvirt-}" ]; then
        in_chroot "$install_root" \
            "usermod -a -G libvirt -d '/var/lib/libvirt' '$user'"
    fi

    # Configure sshd(8)
    local file="${install_root}etc/ssh/sshd_config"
    if [ -f "$file" ]; then
        in_chroot "$install_root" "usermod -a -G users '$user'"

        local keys='etc/ssh/authorized_keys'
        install -d -m 0751 "$install_root$keys"
        keys="/$keys"

        local _cfg_replace_append_nohdr=''

        t="$dir/99-$prog_name.conf"
        if [ -f "$t" ]; then
            file="$t"
            _cfg_replace_append_nohdr='1'
        fi

        cfg_replace "$user" "$file" "
Match User $user
	X11Forwarding no
	AllowTcpForwarding yes
	PasswordAuthentication no
	PubkeyAuthentication yes
	AuthorizedKeysFile $keys/%u
"
    fi
}

# Usage: config_readonly_root
config_readonly_root()
{
    if [ -n "$readonly_root" ]; then
        if rocky_version_ge $releasemaj 8 ||
           centos_version_ge $releasemaj 8 ||
           fedora_version_gt $releasemaj 28
        then
           in_chroot_yum -y install 'readonly-root'
        fi

        local t

        # Make postfix readonly root aware
        if pkg_is_installed postfix; then
            t="${install_root}etc/rwtab.d/postfix"
            [ -s "$t" ] || {
                echo 'dirs /var/lib/postfix'
            } >"$t"
        fi

        # Make rsyslog readonly root aware
        if pkg_is_installed rsyslog; then
            t="${install_root}etc/rwtab.d/rsyslog"
            [ -s "$t" ] || {
                echo 'dirs /var/lib/rsyslog'
            } >"$t"
        fi

        # Make gssproxy readonly root aware
        if pkg_is_installed gssproxy; then
            t="${install_root}etc/rwtab.d/gssproxy"
            [ -s "$t" ] || {
                echo 'dirs /var/lib/gssproxy'
            } >"$t"
        fi

        # Make /etc writable to update config files (mainly /etc/passwd)
        t="${install_root}etc/rwtab.d/_etc"
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
            ln -snf '../run/lock' "${install_root}var/lock"

            t="${install_root}usr/lib/tmpfiles.d/legacy.conf"
            if [ -s "$t" ]; then
                sed -e 's,^\(L\s\+/var/lock\),#\1,' "$t" \
                    >"${install_root}etc/tmpfiles.d/${t##*/}"
            fi

            # /usr/lib/tmpfiles.d/rpm.conf: rm -f /var/lib/rpm/__db.*
            rm -f "${install_root}var/lib/rpm"/__db.*

            t="${install_root}usr/lib/tmpfiles.d/rpm.conf"
            if [ -s "$t" ]; then
                sed -e 's,^\(r\s\+/var/lib/rpm/__db\.\*\),#\1,' "$t" \
                    >"${install_root}etc/tmpfiles.d/${t##*/}"
            fi
        fi

        # Enable $readonly_root
        sed -i "${install_root}etc/sysconfig/readonly-root" \
            -e 's/^\(READONLY=\)\w\+\(\s*\)$/\1yes\2/' \
            #
    fi
}

# Usage: config_plymouth
config_plymouth()
{
    if [ -n "$plymouth_theme" ]; then
        eval $(
            in_chroot "$install_root" "
                plymouth='/usr/share/plymouth/themes/'
                # Themes in order of preference
                for theme in \
                    '$plymouth_theme' \
                    'tribar' \
                    'text' \
                    'details' \
                    '' \
                    #
                do
                    if [ -n \"\$theme\" -a \
                         -f \"\${plymouth}\$theme/\$theme.plymouth\" ] &&
                       plymouth-set-default-theme \"\$theme\" >/dev/null 2>&1
                    then
                        break
                    fi
                done
                echo \"plymouth_theme='\$theme'\"
            "
        )

        case "$plymouth_theme" in
            'tribar'|'text'|'details')
                plymouth_type='text'
                ;;
            '')
                plymouth_type=''
                ;;
            *)
                plymouth_type='graphical'
                ;;
        esac
    else
        plymouth_type=''
    fi
}

# Usage: config_grub_ipxe
config_grub_ipxe()
{
    if [ -n "${pkg_ipxe_bootimgs-}" ]; then
        copy_ipxe_file()
        {
            local func="${FUNCNAME:-copy_ipxe_file}"

            local ipxe="${1:?missing 1st argument to ${func}() (boot_ipxe)}"
            local ipxe_name="${2:-$ipxe}"
            local ipxe_iter

            for ipxe_iter in \
                "${install_root}usr/share/ipxe/$ipxe" \
                "${install_root}usr/lib/ipxe/$ipxe" \
                #
            do
                if [ -f "$ipxe_iter" ]; then
                    install -D -m 0644 \
                        "$ipxe_iter" "${install_root}boot/$ipxe_name"
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

        unset -f copy_ipxe_file

        # Add helper that generates boot menu entries for iPXE
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
    fi
}

# Usage: config_grub_serial
config_grub_serial()
{
    # Enable serial line console
    if [ -n "$serial_console" ]; then
        t="${install_root}etc/default/grub"

        local serial
        eval $(
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
                else
                    speed=''
                    parity=''
                    word=''
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
                # Remove "console=..."
                sed -i "$t" \
                    -e '/^GRUB_CMDLINE_LINUX=/!b' \
                    -e "s,\( \)*console=[^\"'[:space:]]\+\( \)*,\1\2,g" \
                    #
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
    fi

    # Add helper that generates terminfo commands for serial
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

# Usage: config_grub
config_grub()
{
    if [ -n "${pkg_grub2-}" ]; then
        # Add default GRUB config
        local t="${install_root}etc/default/grub"

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

        # Disable BLS config type: it is unclear how to update
        # kernel command line options with it:
        # https://bugzilla.redhat.com/show_bug.cgi?id=2032680
        sed -i "$t" \
            -e 's,^\(GRUB_ENABLE_BLSCFG\)=.*$,\1=false,g' \
            #

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

        # Add "rhgb" and "quiet" to kernel command line
        # options list if plymouth enabled
        if [ -n "$plymouth_theme" ]; then
            $(
                # Source in subshell to not pollute environment
                . "$t"

                opts=''

                for o in \
                    'rhgb' \
                    'quiet' \
                    #
                do
                    if v="${GRUB_CMDLINE_LINUX-}" &&
                       [ "${v##*${o}*}" = "$v" ] &&
                       v="${GRUB_CMDLINE_LINUX_DEFAULT-}" &&
                       [ "${v##*${o}*}" = "$v" ]
                    then
                        opts="${opts:+$opts }${o}"
                    fi
                done

                if [ -n "$opts" ]; then
                    cat >>"$t" <<_EOF
GRUB_CMDLINE_LINUX="\${GRUB_CMDLINE_LINUX-} ${opts}"
_EOF
                fi
            )
        fi

        # Enable KMS if X11 server is local or graphical Plymouth theme.
        # Note Display Manager always enabled for local X11 server.
        if [ -n "${has_dm-}" -o "$plymouth_type" = 'graphical' ]; then
            # Remove "nomodeset"
            sed -i "$t" \
                -e '/^GRUB_CMDLINE_LINUX=/!b' \
                -e 's,\( \)*nomodeset\( \)*,\1\2,g' \
                #
        fi

        # Add support for iPXE on BIOS and EFI systems
        config_grub_ipxe

        # Add support for serial console
        config_grub_serial

        # Normalize kernel command line
        $(
            # Source in subshell to not pollute environment
            . "$t"

            # Temporary file name based on interpreter pid
            f="$t.$$"

            GRUB_CMDLINE_LINUX="$(
                echo "${GRUB_CMDLINE_LINUX-}" | \
                sed -e 's,\s\+, ,g' \
                    -e 's,\(^ \| $\),,' \
                    #
            )"

            {
                # <begin>
                # GRUB_CMDLINE_LINUX=...
                sed "$t" \
                    -e '/^GRUB_CMDLINE_LINUX=/q' \
                    #
                # <end>
                sed "$t" \
                    -n \
                    -e '/^GRUB_CMDLINE_LINUX=/,$ {/^GRUB_CMDLINE_LINUX=/d; p}' \
                    #
            } | {
                sed -e '/^GRUB_CMDLINE_LINUX=/!b' \
                    -e "i GRUB_CMDLINE_LINUX=\"${GRUB_CMDLINE_LINUX-}\"" \
                    -e 'd' \
                    #
            } >"$f"

            if [ -s "$f" ]; then
                mv -f "$f" "$t"
            fi
        )
    fi
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

        local unpack_dir="${1:?missing 1st arg to ${func}() <unpack_dir>}"
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

        local unpack_dir="${1:?missing 1st arg to ${func}() <unpack_dir>}"
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

        local unpack_dir="${1:?missing 1st arg to ${func}() <unpack_dir>}"
# md5(xfce4.tgz.b64) = 18e723bc6e5157d1ea68c4a9e692b95c
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'xfce4.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
GAEA
xfce4.tgz.b64
        if [ "${has_dm-}" = 'lightdm' -a -n "${pkg_light_locker-}" ]; then
            local p1='^\(\s*<property name="LockCommand" \)type="empty"/>$'
            local p2='\1type="string" value="light-locker-command --lock"/>'

            local t='.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml'
            sed -i "$unpack_dir/etc/skel/$t" \
                -e "s,$p1,$p2,g" \
                #
        fi
    }

    # Usage: rsync_wrapper <unpack_dir>
    rsync_wrapper()
    {
        local func="${FUNCNAME:-rsync_wrapper}"

        local unpack_dir="${1:?missing 1st arg to ${func}() <unpack_dir>}"
# md5(rsync-wrapper.tgz.b64) = 27ba0336474bbc375511fb86a0e5ee50
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'rsync-wrapper.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
rsync-wrapper.tgz.b64
    }

    # Usage: xsession <unpack_dir>
    xsession()
    {
        local func="${FUNCNAME:-xsession}"

        local unpack_dir="${1:?missing 1st arg to ${func}() <unpack_dir>}"

        if [ -z "${has_dm-}" ]; then
            if [ -n "${has_de-}" ]; then
                local t="$unpack_dir/.xsession"
                echo "${has_de}-session" >"$t" &&
                    chmod a+rx "$t" ||
                return
            fi
        fi
    }

    # Usage: config_skel <dir>
    config_skel()
    {
        local func="${FUNCNAME:-config_skel}"

        local d="${1:?missing 1st arg to ${func}() <dir>}"

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

            mc_ini "$d"
            screenrc "$d"
            xfce4 "$d"
            xsession "$d"
            ssh_agent_start4bashrc "$d"
            rsync_wrapper "$d"
        fi
    }

    local uid gid
    uid="$(id -u 2>/dev/null)"
    gid="$(id -g 2>/dev/null)"

    local t='' u

    # user home directory skeleton
    for u in \
        '/etc/skel' \
        'root' \
        "${SUDO_USER:-setup}" \
        #
    do
        eval $(
            in_chroot_exec "$install_root" "
                if [ -n '${u##*/*}' ]; then
                    # Find user's home directory if user exists
                    t=~$u && [ -z \"\${t##*/*}\" ] || t=''
                else
                    t='$u'
                fi
                # / is not allowed as skel: returns t=''
                echo \"t='\${t#/}'\"
            "
        )
        if [ -n "$t" ]; then
            config_skel "$install_root$t"

            in_chroot "$install_root" "
                if [ -n '${u##*/*}' ] &&
                   u=\"\$(id -u '$u' 2>/dev/null)\" &&
                   g=\"\$(id -g '$u' 2>/dev/null)\" &&
                   [ \$u -ne $uid -o \$g -ne $gid ]
                then
                    # Adjust filesystem entries owner and group
                    exec chown \
                        --from='$uid:$gid' \
                        --recursive \
                        \"\$u:\$g\" \
                        '/$t' \
                        #
                fi
            "
        fi
    done

    unset -f mc_ini screenrc xfce4 rsync_wrapper \
             ssh_agent_start4bashrc config_skel
}

# Usage: config_flatpak
config_flatpak()
{
    if [ -n "${pkg_flatpak-}" ] &&
       in_chroot "$install_root" 'command -v flatpak >/dev/null 2>&1'
    then
        in_chroot "$install_root" \
            'flatpak remote-add --if-not-exists \
                flathub \
                https://flathub.org/repo/flathub.flatpakrepo' \
                #
    fi
}

# Usage: config_autopass
config_autopass()
{
    if [ -n "$autopassword_root" ]; then
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

        in_chroot "$install_root" 'systemctl enable autopass.service'
    fi
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
install_weak_deps='False'
nodocs=''

# yum(8) repo mirrorlist variable cc (country code) variable (default: none)
cc=''
# yum(8) has --setopt=
has_setopt='1'

# Configuration file with packages/groups definitions
config=''
# Exit after installing minimal system
minimal_install=''

# External repositories (e.g. EPEL, ELRepo and RPM Fusion)
repo_epel=1
repo_elrepo=''
repo_rpmfusion=''
repo_virtio_win=''
repo_advanced_virtualization=''
repo_openstack=''
repo_ovirt=''
repo_nfv_openvswitch=''

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
# Plymouth
_plymouth_theme='tribar'
plymouth_theme=''
_plymouth_type='text'
plymouth_type=''
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
        Only rocky, centos and fedora supported at the moment.
    --releasever=$releasever
        Supported distribution release version
    --arch=$arch
        System processor (CPU) architecture to install packages for.
        Only AMD64 (x86_64) and i386 (i686) supported at the moment

    --install-langs=${install_langs:-<all>}
        (rpm) install localization files for given languages (e.g. 'en:uk')
    --install-weak-deps, --no-install-weak-deps
        (rpm) avoid installing packages weak dependencies. Weak deps are
        such deps that provide extended functionality to installed package
        and not mandatory for package functionality
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
    --repo-elrepo, --no-repo-elrepo
        Enable/disable ELRepo and selected packages from it
    --repo-rpmfusion, --no-repo-rpmfusion
        Enable/disable RPM Fusion and selected packages from it
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
    --repo-nfv-openvswitch, --no-repo-nfv-openvswitch
        Enable/disable NFV-OpenvSwitch repository and selected packages
        from it, ignored if OpenStack or oVirt repositories enabled

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
    --plymouth-theme=${plymouth_theme:-${_plymouth_theme}}
        Select plymouth theme when plymouth enabled
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
        --no-install-weak-deps)
            install_weak_deps='False'
            ;;
        --install-weak-deps)
            install_weak_deps='True'
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
        # ELRepo
        --no-repo-elrepo)
            repo_elrepo=''
            ;;
        --repo-elrepo)
            repo_elrepo=1
            ;;
        # RPM Fusion
        --no-repo-rpmfusion)
            repo_rpmfusion=''
            ;;
        --repo-rpmfusion)
            repo_rpmfusion=1
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
        # OpenvSwitch
        --no-repo-nfv-openvswitch)
            repo_nfv_openvswitch=''
            ;;
        --repo-nfv-openvswitch)
            repo_nfv_openvswitch=1
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
        --plymouth-theme)
            [ -n "${2-}" ] || exit
            plymouth_theme="$2"
            arg="--plymouth-theme '$plymouth_theme'"
            shift
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
    'fedora') ;;
    'centos') ;;
    'rocky') ;;
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
unset has_de has_dm gtk_based_de

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
    install_root="${install_root%/}/"

    [ -n "${install_root%/}" ] || build_info=''
else
    install_root='/'
    build_info=''
fi

# Install build information
if [ -n "$build_info" ]; then
    d="${install_root}.${prog_name}"

    # $this
    if [ -e "$this" ]; then
        install -D "$this" "$d/${_prog_name}"
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

    "\$this_dir/${_prog_name}" $argv \\
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

# Usage: exit_installed
exit_installed()
{
    local t f

    if :; then
        ## Add helpers
        local systemctl_helper="${install_root}bin/systemctl"

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

rc=''
while shift && [ $# -gt 0 ]; do
    if name="${1%.*}" && [ -n "$name" ]; then
        chkconfig "$name" "$cmd" && ret=0 || ret=$?
        [ -e "/etc/init.d/$name" ] || ret=0
        : $((rc += ret))
    fi
done

exit ${rc:-123}
_EOF
            chmod a+rx "$systemctl_helper" ||:
        fi

        ## Finish installation

        # Pick default theme for plymouth
        config_plymouth

        # Configure GRUB2
        config_grub

        # Configure login banners
        config_login_banners


        # Configure X11 server
        case "${x11_server-}" in
            'Xorg')
                config_xorg
                ;;
            'Xrdp')
                config_xrdp
                ;;
        esac

        # Configure openssh-server
        config_sshd

        # Configure fail2ban-server
        config_fail2ban

        # Configure lvm2
        config_lvm2

        # Enable tmp.mount with up to $tmp_mount percents of system RAM
        if [ -n "$tmp_mount" ]; then
            t="${install_root}usr/lib/systemd/system/tmp.mount"
            if [ -s "$t" ]; then
                [ "$tmp_mount" -ge ${_tmp_mount_min} -a \
                  "$tmp_mount" -le ${_tmp_mount_max} ] 2>/dev/null ||
                    tmp_mount=${_tmp_mount}
                sed -e "s/^\(Options=.\+\)$/\1,size=$tmp_mount%/" "$t" \
                    >"${install_root}etc/systemd/system/${t##*/}"
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

        # Disable mcelog as it might fail to run in virtualized environment
        if [ -n "${pkg_mcelog-}" ]; then
            in_chroot "$install_root" 'systemctl disable mcelog.service'
        fi

        # Enable display-manager.service and set-default to graphical.target
        if [ -n "${has_dm-}" ]; then
            in_chroot "$install_root" "systemctl enable '$has_dm.service'"
            in_chroot "$install_root" 'systemctl set-default graphical.target'
        fi

        # Enable postfix as it might be disabled (e.g. on CentOS/RHEL 8)
        in_chroot "$install_root" 'systemctl enable postfix.service'

        # $selinux
        if [ -n "$selinux" ]; then
            sed -i "${install_root}etc/selinux/config" \
                -e "s/^\(SELINUX=\)\w\+\(\s*\)$/\1$selinux\2/"
        fi

        # $readonly_root
        config_readonly_root

        # $autopassword_root
        config_autopass

        # $passwordless_root
        if [ -n "$passwordless_root" ]; then
            in_chroot "$install_root" 'passwd -d root'
        fi

        # $autorelabel
        if [ -n "$autorelabel" ]; then
            echo >"${install_root}.autorelabel"
        fi

        # Provide user configuration for applications
        config_user_apps

        # Configure flatpak repositories
        config_flatpak

        # Configure networking
        config_network

        # Termiate bash after given seconds of inactivity (auto-logout)
        if [ -x '/bin/bash' ]; then
            t="${install_root}etc/profile.d/shell-timeout.sh"
            cat >"$t" <<'_EOF'
# Set non-X11 login shell session auto-logout after timeout
[ -n "$DISPLAY" ] || export TMOUT=$((20 * 60))
_EOF
        fi

        # Make sure /var/log/lastlog is here
        t="${install_root}var/log/lastlog" && [ -f "$t" ] || : >"$t"
        # Make sure /etc/sysconfig/network is here
        t="${install_root}etc/sysconfig/network" && [ -f "$t" ] || : >"$t"
        # Make sure /var/lib/systemd/random-seed is here and empty
        t="${install_root}var/lib/systemd" && [ ! -d "$t" ] || : >"$t/random-seed"
        # Make sure /etc/machine-id is here and empty
        t="${install_root}etc/machine-id" && : >"$t"

        # Update initramfs file
        if [ -n "${pkg_dracut-}" ]; then
            in_chroot "$install_root" '
                if dracut --help 2>&1 | grep -q -- "--regenerate-all"; then
                    exec dracut --force --quiet --regenerate-all
                else
                    for kmod in /lib/modules/*; do
                        if [ -d "$kmod" ] &&
                           kver="${kmod##*/}" &&
                           [ -n "$kver" -a -f "/boot/vmlinuz-$kver" ]
                        then
                            dracut --force --quiet "/boot/initramfs-$kver.img" "$kver"
                        fi
                    done
                fi
            '
        fi

        # Update GRUB2 configuration file
        if [ -n "${pkg_grub2-}" ]; then
            in_chroot "$install_root" '
                 [ ! -L /etc/grub2.cfg ] ||
                    grub2-mkconfig -o "$(readlink -f /etc/grub2.cfg)"
                 [ ! -L /etc/grub2-efi.cfg ] ||
                    grub2-mkconfig -o "$(readlink -f /etc/grub2-efi.cfg)"
            '
        fi

        # Restore /etc/yum.conf.rhbootstrap after yum(1) from EPEL install
        f="${install_root}etc/yum.conf"
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
            find "${install_root}usr/share/doc" -type d -a -empty -a -delete
        fi

        # Clean yum(1) packages and cached data
        in_chroot_yum -y clean all

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
        clean_dir "${install_root}var/log"
    fi

    exit 0
}

exit_handler()
{
    local rc=$?
    local t

    # Do not interrupt exit handler
    set +e

    if [ -n "${install_root%/}" ]; then
        # Unmount bind-mounted filesystems
        for t in 'proc/1' 'proc' 'sys' 'dev'; do
            t="$install_root$t"
            ! mountpoint -q "$t" || umount "$t"
        done

        t="${install_root}.tmp"
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
    repo_elrepo=''
    repo_rpmfusion=''
    repo_virtio_win=''
    repo_advanced_virtualization=''
    repo_openstack=''
    repo_ovirt=''
    repo_nfv_openvswitch=''
}

# Usage: distro_rhel
distro_rhel()
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

        if is_centos && [ -n "$is_archive" ]; then
            # Releases available at $baseurl
            local url="${baseurl%/$releasever/*}"

            local baseurl_p1='^#\?\(baseurl\)=.\+/\$releasever/\(.\+\)$'
            local baseurl_p2="\1=$url/$releasever/\2"

            find "${install_root}etc/yum.repos.d" \
                -name 'CentOS-*.repo' -a -type f -a -exec \
            sed -i \
                -e 's,^\(mirrorlist\|metalink\)=,#\1=,' \
                -e "s,$baseurl_p1,$baseurl_p2," \
            {} \+
        fi

        if centos_version_lt $releasemaj 6; then
            # Add gpgkey= to local file://
            local t="$install_root"
            local url
            url="${t}etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-$releasemaj"
            if [ ! -f "$url" ]; then
                url="${t}usr/share/doc/centos-release-$releasemaj/RPM-GPG-KEY"
                if [ ! -f "$url" ]; then
                    url=''
                fi
            fi
            if [ -n "$url" ]; then
                find "${install_root}etc/yum.repos.d" \
                    -name 'CentOS-*.repo' -a -type f -a -exec \
                sed -i \
                    -e '/^gpgkey=/d' \
                    -e "/^gpgcheck=1/a gpgkey=file:///${url#$t}" \
                {} \+
            fi
        fi

        if is_centos && [ -n "${releasever_orig-}" ]; then
            # Update to target version
            if [ $releasever_orig = '6.10' ]; then
                find "${install_root}etc/yum.repos.d" \
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
        local NFV_OPENVSWITCH_RELEASE_RPM
        local RPMFUSION_URL RPMFUSION_RELEASE_RPM RPMFUSION_RELEASE_URL
        local VIRTIO_WIN_URL

        # VirtIO-Win
        VIRTIO_WIN_URL='https://fedorapeople.org/groups/virt/virtio-win/virtio-win.repo'

        # common
        EPEL_RELEASE_RPM_NAME='epel-release'
        ELREPO_RELEASE_RPM_NAME='elrepo-release'
        RPMFUSION_RELEASE_RPM_NAME='rpmfusion-free-release'

          if [ $releasemaj -ge 8 ]; then
            # EPEL
            EPEL_URL='http://dl.fedoraproject.org/pub/epel'
            EPEL_RELEASE_RPM="epel-release-latest-$releasemaj.noarch.rpm"
            EPEL_RELEASE_URL="$EPEL_URL/$EPEL_RELEASE_RPM"

            # ELRepo
            ELREPO_URL='https://www.elrepo.org'
            ELREPO_RELEASE_RPM="elrepo-release-$releasemaj.el$releasemaj.elrepo.noarch.rpm"
            ELREPO_RELEASE_URL="$ELREPO_URL/$ELREPO_RELEASE_RPM"

            # RPM Fusion
            RPMFUSION_URL='https://download1.rpmfusion.org/free/el'
            RPMFUSION_RELEASE_RPM="rpmfusion-free-release-$releasemaj.noarch.rpm"
            RPMFUSION_RELEASE_URL="$RPMFUSION_URL/$RPMFUSION_RELEASE_RPM"

            # Advanced Virtualization
            ADVANCED_VIRTUALIZATION_RELEASE_RPM='centos-release-advanced-virtualization'

            # OpenStack
            OPENSTACK_RELEASE_RPM='centos-release-openstack-ussuri'

            # oVirt
            OVIRT_RELEASE_RPM='centos-release-ovirt44'

            # OpenvSwitch
            NFV_OPENVSWITCH_RELEASE_RPM='centos-release-nfv-openvswitch'
        elif [ $releasemaj -eq 7 ]; then
            # EPEL
            EPEL_URL='http://dl.fedoraproject.org/pub/epel'
            EPEL_RELEASE_RPM='epel-release-latest-7.noarch.rpm'
            EPEL_RELEASE_URL="$EPEL_URL/$EPEL_RELEASE_RPM"

            # ELRepo
            ELREPO_URL='https://www.elrepo.org'
            ELREPO_RELEASE_RPM='elrepo-release-7.el7.elrepo.noarch.rpm'
            ELREPO_RELEASE_URL="$ELREPO_URL/$ELREPO_RELEASE_RPM"

            # RPM Fusion
            RPMFUSION_URL='https://download1.rpmfusion.org/free/el'
            RPMFUSION_RELEASE_RPM='rpmfusion-free-release-7.noarch.rpm'
            RPMFUSION_RELEASE_URL="$RPMFUSION_URL/$RPMFUSION_RELEASE_RPM"

            # Advanced Virtualization
            ADVANCED_VIRTUALIZATION_RELEASE_RPM='centos-release-qemu-ev'

            # OpenStack
            OPENSTACK_RELEASE_RPM='centos-release-openstack-train'

            # oVirt
            OVIRT_RELEASE_RPM='centos-release-ovirt43'

            # OpenvSwitch
            NFV_OPENVSWITCH_RELEASE_RPM='<no_nfv_openvswitch_release_rpm>'
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
            repo_nfv_openvswitch=''
        fi

        # $repo_openstack
        if [ -n "$repo_openstack" ]; then
            repo_ovirt=''
            repo_virtio_win=''
            repo_advanced_virtualization=''
            repo_nfv_openvswitch=''
        fi

        # $repo_epel, $repo_rpmfusion
        if [ -n "$repo_rpmfusion" ]; then
            repo_epel=1
        fi

        # EPEL
        if [ -n "$repo_epel" ]; then
            if is_centos &&
               [ $releasemaj -eq 8 ] && version_lt $releasemm 8.3
            then
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
                if is_centos && [ -n "$is_archive" ]; then
                    # Unsupported releases available at $url
                    local url="http://archives.fedoraproject.org/pub/archive/epel"
                    local t="\$releasever\|$releasemaj"

                    local baseurl_p1="^#\?\(baseurl\)=.\+/\($t\)/\(.\+\)$"
                    local baseurl_p2="\1=$url/\$releasever/\3"

                    find "${install_root}etc/yum.repos.d" \
                        -name 'epel*.repo' -a -type f -a -exec \
                    sed -i \
                        -e 's,^\(mirrorlist\|metalink\)=,#\1=,' \
                        -e "s,$baseurl_p1,$baseurl_p2," \
                    {} \+
                fi

                if is_centos &&
                   [ $releasemaj -eq 4 ] && version_le $releasemm 4.3
                then
                    # Backup /etc/yum.conf since yum(1) from EPEL doesn't have it
                    local t="${install_root}etc/yum.conf"
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

        # VirtIO-Win
        if [ -n "$repo_virtio_win" ]; then
            safe_curl "$VIRTIO_WIN_URL" 1024 \
                >"${install_root}etc/yum.repos.d/virtio-win.repo" \
            && has_enable 'repo' || repo_virtio_win=''
        fi

        # Advanced Virtualization
        if [ -n "$repo_advanced_virtualization" ]; then
            in_chroot_yum -y install "$ADVANCED_VIRTUALIZATION_RELEASE_RPM" &&
                has_enable 'repo' || repo_advanced_virtualization=''
        fi

        # OpenStack
        if [ -n "$repo_openstack" ]; then
            in_chroot_yum -y install "$OPENSTACK_RELEASE_RPM" &&
                has_enable 'repo' || repo_openstack=''
        fi

        # oVirt
        if [ -n "$repo_ovirt" ]; then
            in_chroot_yum -y install "$OVIRT_RELEASE_RPM" &&
                has_enable 'repo' || repo_ovirt=''
        fi

        # OpenvSwitch
        if [ -n "$repo_nfv_openvswitch" ]; then
            in_chroot_yum -y install "$NFV_OPENVSWITCH_RELEASE_RPM" &&
                has_enable 'repo' || repo_nfv_openvswitch=''
        fi

        # Repositories might provide updated package versions
        [ -z "$has_repo" ] || yum_update=1

        # Perform package update when requested
        if [ -n "$yum_update" ]; then
            in_chroot_yum -y update
        fi
    }

    local host subdir url
    local _releasemin=255 releasemin

    # $releasever
    releasever_orig="$releasever"
    if [ -z "$releasever" ]; then
        if is_centos; then
            # Default CentOS version is 8-stream
            releasever='8-stream'
        else
            # Default Rocky/other version is 8
            releasever='8'
        fi
    fi

    if [ -z "${releasever%%*-stream}" ]; then
         releasemaj="${releasever%-stream}"
         releasemin="$(centos_stream_compose_id)"
    else
        # There is some incompatibility with rpmdb(1) on CentOS 6.x
        # format that can't be addressed with rpmdb_dump/load
        # helpers: install last supported and then update.
        if centos_version_eq $releasever '6.10'; then
            releasever='6.9'
        fi

        releasemaj="${releasever%%.*}"

        if [ "$releasemaj" != "$releasever" ]; then
            releasemin="${releasever#$releasemaj.}"
            releasemin="${releasemin%%.*}"
        else
            releasemin=${_releasemin}
        fi
    fi

    if is_centos; then
        if version_le $releasever 6.0; then
            if [ $releasemaj -lt 4 ]; then
                fatal 'no support for CentOS before 4 (no yum?)\n'
            fi
            has_setopt=''
        fi
    fi

    if version_ge $releasever 8.6; then
        # Since RHEL 8.6 advanced-virtualization merged to @appstream
        # https://forums.rockylinux.org/t/will-virt-stream-advanced-virtualization-come-to-rocky-linux/3348/11
        repo_advanced_virtualization=''
    fi

    # $baseurl, $updatesurl
    release_url()
    {
        local subdir="${subdir:+$subdir/}"

        local templ='http://%s/%s%s/%s/'
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
      if is_rocky; then
        host='download.rockylinux.org'

        if [ $releasemaj -ge 9 ]; then
            # These not ready/tested for Rocky/others 9
            repo_openstack=''
            repo_ovirt=''
        fi

          if url="$(subdir='pub/rocky' release_url)"; then
            # Current
            is_archive=''
        elif url="$(subdir='vault/rocky' release_url)"; then
            # Archive
            is_archive='1'
        else
            unset is_archive
        fi
    elif is_centos; then
        host='centos.org'

        if [ $releasemaj -le 7 ]; then
            # These is not available on CentOS/others <= 7
            repo_nfv_openvswitch=''
        fi

        # $subdir
        subdir='centos'
        case "$basearch" in
            'i386')
                # Pick CentOS 7 AltArch, which is last with i386 support,
                # unless default release version is older.
                if centos_version_ge $releasemaj 7; then
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
            # Add more alternative architectures here.
            # Note that supported set varies between releases.
        esac

          if url="$(host="mirror.$host" release_url)"; then
            # Current
            is_archive=''
        elif url="$(host="vault.$host" subdir="${subdir#centos}" release_url)"; then
            # Archive
            is_archive='1'
        else
            unset is_archive
        fi
    else
        # Never reached
        unset is_archive
    fi
    if ! [ -n "${is_archive+x}" ]; then
        fatal "$distro $releasever isn't available for download\n"
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

# Usage: distro_rocky
distro_rocky()  { distro_rhel "$@"; }
# Usage: distro_centos
distro_centos() { distro_rhel "$@"; }

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

            find "${install_root}etc/yum.repos.d" \
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

        if [ $releasemaj -lt 12 ]; then
            if [ $releasemaj -lt 10 ]; then
                fatal 'no support for Fedora before 10 (Fedora Core?)\n'
            fi
            has_setopt=''
        fi
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
        fatal "$distro $releasever isn't available for download\n"
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

    if [ $releasemaj -ge 24 ]; then
        has_glibc_langpack=1
        # Explicitly add systemd-udev package
        PKGS="${PKGS:+$PKGS }systemd-udev"
    fi

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
PKGS="${PKGS:+$PKGS }tar bzip2 gzip"

# Pick repo names on host to configure and use for initial setup
eval $(
    command yum --noplugins -C repolist | \
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
    for f in 'proc' 'sys' 'dev'; do
        d="$install_root$f"
        install -d "$d" && mount --bind "/$f" "$d"
    done

    # Point /etc/mtab to /proc/self/mounts unless it already exist
    f="${install_root}etc/mtab"
    if [ ! -f "$f" ]; then
        install -D -m 0644 /dev/null "$f"
        ln -snf '../proc/self/mounts' "$f"
    fi

    # Hide /proc/1 from target (e.g. for rpm pre/post scripts)
    f="${install_root}proc/1"
    d="${install_root}.tmp/1"

    [ -d "$f" ] && install -d "$d" && mount --bind "$d" "$f" ||:

    if [ -n "${install_root%/}" ]; then
        # Need access to resolvers: prefer system, fall back to public
        f='etc/resolv.conf'
        d="$install_root$f"
        f="/$f"

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
    'fedora')
        host_gpg_import "$distro/RPM-GPG-KEY-fedora-$releasemaj-$basearch"
        ;;
    'centos')
        host_gpg_import "$distro/RPM-GPG-KEY-CentOS-$releasemaj"
        ;;
    'rocky')
        host_gpg_import "$distro/RPM-GPG-KEY-Rocky-$releasemaj"
        ;;
esac

# Initial setup
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

f="${install_root}etc/fstab"
if [ ! -e "$f" ]; then
    # Remove broken symlink
    rm -f "$f" ||:
    : >"$f"
fi

if [ -n "${install_root%/}" ]; then
    # Convert rpmdb(1) from host to target format
    {
        t="${install_root}var/lib/rpm"
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
    install -d "${install_root}etc/dracut.conf.d"

    # Build generic image regardless of dracut-config-generic
    echo 'hostonly="no"' \
        >"${install_root}etc/dracut.conf.d/00-generic-image.conf"

    # Add "nfs" dracut module (from dracut-network package)
    echo 'add_dracutmodules+=" nfs "' \
        >"${install_root}etc/dracut.conf.d/01-nfs.conf"

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
    cc="$(echo "$cc" | tr '[:upper:]' '[:lower:]')"
    if is_rocky; then
        cc_var='country'
    else
        cc_var='cc'
    fi

    for f in \
        "${install_root}etc/yum/vars/$cc_var" \
        "${install_root}etc/dnf/vars/$cc_var" \
        #
    do
        if [ -d "${f%/*}" ]; then
            [ -s "$f" ] || echo "$cc" >"$f"
            break
        fi
    done

    for f in "${install_root}etc/yum.repos.d"/*.repo; do
        if [ -f "$f" ]; then
            sed -i "$f" \
                -e '/^mirrorlist=.\+\/\?[^=]\+=[^=]*/!b' \
                -e "/&$cc_var=.\+/b" \
                -e "s/.\+/\0\&$cc_var=$cc/" \
                #
        fi
    done

    unset f cc_var

    in_chroot_yum -y update
fi

## Minimal install

if [ -n "${minimal_install-}" ]; then
    exit_installed
fi

## Release specific tricks

pkg_remmina_plugins_secret=1
pkg_wireshark_gnome=1

  if is_rocky || is_centos; then
    if [ $releasemaj -ge 8 ]; then
        if [ $releasemaj -eq 8 ]; then
            # appstream
            pkg_lynx=
            # epel
            pkg_links=

            # No qmmp in EPEL for CentOS/RHEL 8: try rhythmbox
            [ -z "${pkg_qmmp-}" ] || pkg_rhythmbox=1

            pkg_va_intel_hybrid_driver=
            pkg_vdpau_va_gl=
        else
            # appstream
            pkg_pidgin=
            pkg_rhythmbox=
            # epel
            pkg_putty=
            pkg_seamonkey=
            pkg_transmission=
            pkg_icedtea_web=
            pkg_bitmap_fixed_fonts=

            pkg_caja_image_converter=
            pkg_caja_open_terminal=
            pkg_caja_sendto=

            pkg_xfce_battery_plugin=

            pkg_alsa_plugins_pulseaudio=

            pkg_storaged=
            pkg_libguestfs_gfs2=
            pkg_hping3=
            pkg_dash=
            pkg_zsh_syntax_highlighting=

            pkg_network_scripts=

            pkg_bluez_hid2hci=
            pkg_vdpau=
        fi

        # Disable groups that not available for RHEL 8+
        grp_efi_ia32=

        # Disable packages that not available in repositories for RHEL 8+
        pkg_iucode_tool=
        pkg_btrfs_progs=
        pkg_ntpdate=

        pkg_dracut_fips=
        pkg_dracut_fips_aesni=

        pkg_elinks=
        pkg_pidgin_otr=
        pkg_qmmp=
        pkg_wireshark_gnome=

        pkg_cups_x2go=
        pkg_cups_pdf=
        pkg_thunar_vcs_plugin=

        pkg_orage=
        pkg_xarchiver=
        pkg_light_locker=
        pkg_guake=

        pkg_libreoffice_nlpsolver=0
        pkg_libreoffice_officebean=0
        pkg_libreoffice_postgresql=0
        pkg_libreoffice_rhino=0

        pkg_codeblocks=

        pkg_remmina_plugins_nx=
        pkg_remmina_plugins_xdmcp=

        pkg_nm_vpnc=
        pkg_nm_strongswan=
    else
        if [ $releasemaj -eq 7 ]; then
            :
        else
            pkg_cockpit=
            pkg_ipxe_bootimgs=
        fi
    fi
elif is_fedora; then
    if [ $releasemaj -le 27 ]; then
        if [ $releasemaj -le 26 ]; then
            if [ $releasemaj -le 25 ]; then
                if [ $releasemaj -le 24 ]; then
                    if [ $releasemaj -le 19 ]; then
                        if [ $releasemaj -le 18 ]; then
                            if [ $releasemaj -le 17 ]; then
                                if [ $releasemaj -le 16 ]; then
                                    if [ $releasemaj -le 15 ]; then
                                        if [ $releasemaj -le 14 ]; then
                                            if [ $releasemaj -le 12 ]; then
                                                if [ $releasemaj -le 11 ]; then
                                                    pkg_dracut=
                                                    [ "${x11_server-}" != 'Xrdp' ] ||
                                                        x11_server='Xorg'
                                                fi # <= 11
                                                pkg_vdpau=
                                            fi # <= 12
                                            pkg_va=
                                        fi # <= 14
                                        [ "${x11_server-}" != 'Xspice' ] ||
                                            x11_server='Xorg'
                                    fi # <= 15
                                    pkg_ipxe_bootimgs=
                                fi # <= 16
                                pkg_shim=
                            fi # <= 17
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
    if [ $releasemaj -ge 24 ]; then
        pkg_wireshark_gnome=
    fi # >= 24
fi

## List of packages to install

# Always install openssh
PKGS='openssh-server openssh-clients'

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

if [ -n "${plymouth_theme-}" ]; then
    PKGS="$PKGS plymouth plymouth-scripts plymouth-system-theme"

    # Try to enable selected theme
    eval "pkg_plymouth_theme_$plymouth_theme=1"

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

    if is_rocky || is_centos || fedora_version_gt $releasemaj 26; then
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

if [ -n "${pkg_fail2ban-}" ]; then
    PKGS="$PKGS fail2ban-server"

      if is_rocky || is_centos; then
        if [ $releasemaj -ge 7 ]; then
            PKGS="$PKGS fail2ban-systemd"

            if [ $releasemaj -ge 8 ]; then
                PKGS="$PKGS fail2ban-selinux"
            fi
        fi
    elif is_fedora; then
        if [ $releasemaj -ge 21 ]; then
            PKGS="$PKGS fail2ban-systemd"

            if [ $releasemaj -ge 32 ]; then
                PKGS="$PKGS fail2ban-selinux"
            fi
        fi
    fi
fi

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
            in_chroot_yum -y install \
                'centos-release-xen' \
                'centos-release-xen-common' \
                #
            # Update repos data and possibly installed packages
            in_chroot_yum -y update

            # libvirt-daemon-xen
            [ -z "${pkg_libvirt-}" ] || PKGS="$PKGS libvirt-daemon-xen"
        else
            # No XEN for CentOS/RHEL 8
            pkg_qemu_xen=
        fi
    else
        pkg_qemu_xen=
    fi

    # openvswitch
    if [ -n "${pkg_openvswitch-}" ]; then
          if [ -n "$repo_openstack" -o -n "$repo_ovirt" ]; then
            PKGS="$PKGS openvswitch"

            [ -z "${pkg_openvswitch_ipsec-}" ] ||
                PKGS="$PKGS openvswitch-ipsec"
        elif [ -n "$repo_nfv_openvswitch" ]; then
            PKGS="$PKGS openvswitch${pkg_openvswitch}"

            [ -z "${pkg_openvswitch_ipsec-}" ] ||
                PKGS="$PKGS openvswitch${pkg_openvswitch_ipsec}-ipsec"
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
        xfconf
        xfdesktop
        xfwm4

        xfce4-panel
        xfce4-session
        xfce4-settings

        xfce-polkit

        xfce4-appfinder
        xfce4-power-manager
        xfce4-about
        xfce4-taskmanager
        xfce4-terminal
        xfce4-screensaver
        xfce4-screenshooter

        gnome-themes-standard
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
    [ -z "${pkg_xfce_whiskermenu_plugin-}" ] ||
        PKGS="$PKGS xfce4-whiskermenu-plugin"
    # xfce4-xkb-plugin
    [ -z "${pkg_xfce_xkb_plugin-}" ] ||
        PKGS="$PKGS xfce4-xkb-plugin"

    has_de='xfce4'
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
        mate-session-manager
        marco
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
    # seahorse-caja
    [ -z "${pkg_caja-}" -o -z "${pkg_seahorse-}" ] || PKGS="$PKGS seahorse-caja"

    has_de='mate'
    gtk_based_de=1
fi # [ -n "${pkg_mate-}" ]

## Desktop Apps

if [ -n "${has_de-}" ]; then
    case "${x11_server-}" in
        'Xspice')
            # Will install xorg-x11-server-Xorg as dependency
            PKGS="$PKGS xorg-x11-server-Xspice"
            ;;
        'Xrdp')
            # Will install xorg-x11-server-Xorg as dependency
            PKGS="$PKGS xrdp xrdp-selinux xorgxrdp"
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
            has_dm=''
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
            # lightdm-qt5
            [ -z "${kde_based_de-}" ] ||
                PKGS="$PKGS lightdm-qt5"
            # slick-greeter
            [ -z "${pkg_slick_greeter-}" ] ||
                PKGS="$PKGS lightdm-settings slick-greeter"
            # light-locker
            [ -z "${pkg_light_locker-}" ] ||
                PKGS="$PKGS light-locker"
            [ -n "${has_dm-x}" ] || has_dm='lightdm'
        fi

        if [ -n "${pkg_sddm-}" ]; then
            # sddm
            PKGS="$PKGS sddm"
            [ -n "${has_dm-x}" ] || has_dm='sddm'
        fi

        # chromium
        [ -z "${pkg_chromium-}" ] || PKGS="$PKGS chromium"
    fi
    # evolution
    [ -z "${pkg_evolution-}" ] || PKGS="$PKGS evolution"

    if [ -z "${has_dm-x}" ]; then
        # gdm
        PKGS="$PKGS gdm"
        has_dm='gdm'
    fi

    # gucharmap
    [ -z "${pkg_gucharmap-}" ] || PKGS="$PKGS gucharmap"
    # network-manager-applet
    [ -z "${pkg_nm-}" -o -z "${gtk_based_de-}" ] ||
        PKGS="$PKGS network-manager-applet"

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
            if rocky_version_ge $releasemaj 8 ||
               centos_version_ge $releasemm 7.4
            then
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

    # tigervnc
    [ -z "${pkg_tigervnc-}" ] || PKGS="$PKGS tigervnc"

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
            elif is_rocky || is_centos || fedora_version_ge $releasemaj 26; then
                PKGS="$PKGS keepassxc"
            else
                PKGS="$PKGS keepassx"
            fi
        fi

        # putty
        [ -z "${pkg_putty-}" ] || PKGS="$PKGS putty"

        # x2goclient (qt)
        [ -z "${pkg_x2goclient-}" ] || PKGS="$PKGS x2goclient"

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

    # flatpak
    [ -z "${pkg_flatpak-}" ] || PKGS="$PKGS flatpak"
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
    PKGS="$PKGS network-scripts"
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
    printf -- '%s\n' "$f"
done | in_chroot_xargs_yum -y install

exit_installed
