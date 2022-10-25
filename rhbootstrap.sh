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

readonly this this_dir this_prog

# Set program name unless already set
[ -n "${prog_name-}" ] &&
[ -n "${prog_name##*[^[:alnum:]_]*}" ] &&
[ -n "${prog_name##[[:digit:]]*}" ] || prog_name="$this_prog"

readonly _prog_name="$prog_name"

readonly prog_name="${prog_name%\.sh}"
readonly prog_version='1.0'

# Verbosity: report errors by default
[ -n "${V-}" ] && [ "$V" -le 0 -o "$V" -ge 0 ] 2>/dev/null || V=1

# Normalize umask(1)
umask 0022

## Global helpers and steps

true()  {   :; }
false() { ! :; }

# Usage: shell_type_builtin <name>
shell_type_builtin()
{
    local func="${func:-${FUNCNAME:-shell_type_builtin}}"
    local name="${1:?missing 1st arg to ${func}() <name>}"

    local line
    line="$(
        {
            type "$name" | {
                read -r line
                printf -- '%s\n' "$line"
            }
        } 2>/dev/null
    )" || return 123

    # bash(1) type is 'alias', 'keyword', 'function', 'builtin', or 'file'
    case "$line" in
        *\ */*)
            # file
            return 5
            ;;
        *\ alias\ *|*\ aliased\ *)
            # alias
            return 1
            ;;
        *\ keyword|*\ reserved\ word)
            # keyword
            return 2
            ;;
        *\ function)
            # function
            return 3
            ;;
        *\ builtin)
            # builtin
            return 4
            ;;
        *)
            # unknown
            return 0
            ;;
    esac
}

# Usage: shell_type_t_builtin <name>
shell_type_t_builtin()
{
    local func="${FUNCNAME:-shell_type_t_builtin}"

    local rc=0
    shell_type_builtin "$@" || rc=$?

    local t_0='unknown'
    local t_1='alias'
    local t_2='keyword'
    local t_3='function'
    local t_4='builtin'
    local t_5='file'

    eval "local t=\"\${t_${rc}-}\""
    [ -n "$t" ] || return

    printf -- '%s\n' "$t"
}

# Usage: shell_type_is_alias <name>
shell_type_is_alias()
{
    local func="${FUNCNAME:-shell_type_is_alias}"

    local rc=0
    shell_type_builtin "$@" || rc=$?

    [ $rc -eq 1 ] || return
}

# Usage: shell_type_is_keyword <name>
shell_type_is_keyword()
{
    local func="${FUNCNAME:-shell_type_is_keyword}"

    local rc=0
    shell_type_builtin "$@" || rc=$?

    [ $rc -eq 2 ] || return
}

# Usage: shell_type_is_function <name>
shell_type_is_function()
{
    local func="${FUNCNAME:-shell_type_is_function}"

    local rc=0
    shell_type_builtin "$@" || rc=$?

    [ $rc -eq 3 ] || return
}

# Usage: shell_type_is_builtin <name>
shell_type_is_builtin()
{
    local func="${FUNCNAME:-shell_type_is_builtin}"

    local rc=0
    shell_type_builtin "$@" || rc=$?

    [ $rc -eq 4 ] || return
}

# Usage: shell_type_is_file <name>
shell_type_is_file()
{
    local func="${FUNCNAME:-shell_type_is_file}"

    local rc=0
    shell_type_builtin "$@" || rc=$?

    [ $rc -eq 5 ] || return
}

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

   in_chroot "$install_root" "rpm --query '$pkg_name' >/dev/null 2>&1" || return
}

# Usage: _env [NAME=VALUE]... [COMMAND [ARG]...]
_env()
{
    local _env_exec="${_env_exec-}"
    [ -z "${_env_exec}" ] || _env_exec='exec'

    local H="${helpers_dir-}"
    local P='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

    ${_env_exec} env -i \
        TERM="${TERM:-vt220}" \
        PATH="${H:+$H:}$P" \
        USER="${USER:-root}" \
        HOME='/' \
        LANG='C' \
        "$@"
        #
}

# Usage: in_env ...
in_env()
{
    local _env_exec=''
    _env "$@" || return
}

# Usage: in_env_exec ...
in_env_exec()
{
    local _env_exec='1'
    _env "$@" || return
}

# Usage: _in_chroot [NAME=VALUE]... [--] <dir> <cmd> [-|command name] [<arg> ...]
_in_chroot()
{
    local func="${func:-${FUNCNAME:-_in_chroot}}"

    local env_vars=''
    while [ $# -gt 0 ]; do
        case "$1" in
            [[:alpha:]_]*=*)
                env_vars="${env_vars:+$env_vars }'$1'"
                ;;
            --)
                shift
                break
                ;;
            # errors
            --*)
                printf >&2 -- '%s: unknown option: %s\n' "$func" "$1"
                return 1
                ;;
            *)
                break
                ;;
        esac
        shift
    done

    local dir="${1:?missing 1st arg to ${func}() <dir>}"
    local cmd="${2:?missing 2d arg to ${func}() <cmd>}"
    shift 2

    local helpers_dir="/${helpers_dir#$install_root}"
    local _env_exec="${_in_chroot_exec-}"

    eval "
        _env $env_vars \
        setarch '$basearch' \
            chroot '$dir' /bin/sh -c \"\$cmd\" \"\$@\" ||
        return
    "
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
        '2'|'Disabled')
            return 2
            ;;
        *)
            local func="${FUNCNAME:-semode_text2rc}"
            echo >&2 "${func}: invalid <mode>, see setenforce(8) for valid modes"
            return 3
            ;;
    esac
}

# Usage: _setenforce <mode>
_setenforce()
{
    in_chroot "$install_root" '
        {
            # libselinux-utils
            command -v setenforce || exit
            # Set mode
            setenforce "$1"
        } >/dev/null 2>&1
    ' - "$1" || return 3
}

# Usage: setenforce <mode>
setenforce()
{
    local mode="${1-2}"

    semode_text2rc "$mode" && mode=0 || mode=$?
    [ $mode -lt 2 ] || return 3

    _setenforce $mode || return
}

# Usage: getenforce
getenforce()
{
    local mode

    mode="$(
        in_chroot "$install_root" '
            {
                # libselinux-utils
                command -v getenforce >&2 || exit
                # Get mode
                getenforce
            } 2>/dev/null
        '
    )" || return 3

    semode_text2rc "$mode" || return
}

# Usage: selinux_enforce()
selinux_enforce()    { setenforce 1 || return; }
# Usage: selinux_permissive()
selinux_permissive() { setenforce 0 || return; }

# Usage: setenforce_save <mode>
setenforce_save()
{
    local mode=${__selinux_saved_mode__-3}
    [ $mode -gt 2 ] || return 123

    semode_text2rc "${1-}" && mode=0 || mode=$?
    [ $mode -lt 2 ] || return 3

    local rc=0

    getenforce || rc=$?
    case $rc in
        0|1) ;;            # Permissive,Enforced
          2) mode=$rc ;;   # Disabled
          *) return $rc ;; # error
    esac

    __selinux_saved_mode__=$rc

    [ $mode -eq $rc ] || _setenforce $mode || return
}

# Usage: setenforce_restore
setenforce_restore()
{
    local mode=${__selinux_saved_mode__-3}
    [ $mode -le 2 ] || return 123

    unset __selinux_saved_mode__

    [ $mode -eq 2 ] || _setenforce $mode || return
}

# Usage: _yum [NAME=VALUE]... [--] ...
_yum()
{
    local func="${func:-${FUNCNAME:-_yum}}"

    local env_vars=''
    while [ $# -gt 0 ]; do
        case "$1" in
            [[:alpha:]_]*=*)
                env_vars="${env_vars:+$env_vars }'$1'"
                ;;
            --)
                shift
                break
                ;;
            *)
                break
                ;;
        esac
        shift
    done

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
        ${has_setopt:+"--setopt=strict=True"} \
        "$@" \
        #

    eval "
        if [ -n '${_install_root-}' ]; then
            in_chroot $env_vars '${_install_root}' '$cmd' - \"\$@\"
        else
            in_env $env_vars setarch '$basearch' /bin/sh -c '$cmd' - \"\$@\"
        fi || return
    "
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

## Pre install configuration snippets

# Usage: config_helpers
config_helpers()
{
    local unpack_dir="$helpers_dir"
# md5(helpers.tgz.b64) = 14269ed8eaa28421a842785f195280b9
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'helpers.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
pm3apm3apm3a92r/Bhr2GB0AeAAA
helpers.tgz.b64
}

# Usage: config_rpm_gpg
config_rpm_gpg()
{
    local unpack_dir="$rpm_gpg_dir"
# md5(rpm-gpg.tgz.b64) = aa512da69f9ff6d81b961a58089d3447
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'rpm-gpg.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
QZwTBzIaPIroo25i/yFP1uQQn+dbNWhOpyV81GnR3tSj0EMvVCkyhTCLlcirNDn/4A+WfoOFIPlT
C0HyDqeX7N5FbLEvub9zxdyyN7emv7/wv1WSbJMflSR5lmcltrsI4LuIftR1kX/fp4TnuIDnWfM/
qRTJG8IBrWHUUMtgOAKEz8jF0kAP+V+6iSFr/gkipUETPzT8EkJaP9Xnd++lRtfUGGc+A9/N0Q8b
BkIJ++/CfS7vpJdLIK4ZIrdfk+S+yCsSkk/4xECY1HlWrHd+Vueh6NqUmXMmXFnc+MQP2+EL+Ic3
9cuCqx1ggqf5fNv+MFZEvn+ff/5d35cgcv75bpfCoV4gQdbRd0bctCB0SOmj29jQBXjbCOlWT8C6
qvZxBMIxaZ4exEpyTtVV0zy8P6Q+WwINclMX7lChcoI1t25nmujLom5JvYgc7SbAyzWULRjndj5X
m5y7NbEQTtc0TWHBaU0cmZ/4MOrSq+ChJIxB7LuQ4JwNsd5l9YCSgMCy30VDHM3TQs1jgEfRbPwy
5c+lbmtaS6vo3acEBBHqmN1+XBmf8lKCM0JHm+uIbAEwvOHonZf9XYEyRXJqplNsjQNXzXvvoJVU
Uzy63UGkSrcuiBGStK23ByyxkI8rZQ8D7LqTSfpd5wUClqymMY2nD4lrcVHMydy9wu75wsY8fz2Q
wZfsnlPuyzmMMHAhk3RQF6DQSyYLkFqNShMa370IFN0aVI4qlo7SEdaIWIpfrQkxTWjtn3LVC3jz
/WCGWYzpSQ+A9Ryiztf4nnQtWwaTPt/YO/AD+Pp4ao+FWcc5ylZ2cR0/mNhGMJBunFGrree9la1u
AK/c/+B2ilmPOv7eQFXmdZDx7Q3GyKJgfTGGp/T8JbVsc7f1pyXgHy2/Ev9j1G8Y4zf4/zAY+avx
/9+WAvQ/HP/9Kv/vb0zI+y36p/5K/y/x0//7N8mv0j/228b4Tfr/8/af/3hLP/X/N8mvtf/8li3g
N9l//nz+55/c0k/7z2+XX7X+kd82xm9Z/+Rfuf8jP9f/3yS/dv3/linwW9Y/8tev/79tCvzU/6/C
//8w/f/V9n/sp/7/Bvk1+/9v9bj+hv0fh/+6+g/Iz/jPv01+7f7/W/D2DwX/1/Uf/sj/g6Iw8bP+
/z9E/rb8P082V/VHRQieiW66XQacOYJ+SAyzeI4CSg7wm+WoySv8K9EVzK9I0z14A0EuQKr5cFk7
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
jx9/AW4L9yYA0AcA
rpm-gpg.tgz.b64
}

## Post install configuration snippets

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

# Usage: config_iptables
config_iptables()
{
    local unpack_dir="$install_root"

    # Enable iptables
    if [ -f "${install_root}etc/sysconfig/iptables-config" ]; then
        if [ ! -s "${install_root}etc/sysconfig/iptables" ]; then
# md5(iptables.tgz.b64) = 06c9f9bb2da96da0cbedbbdabb07d325
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'iptables.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAAAAAAAAA+3SUWvbMBAH8Dz7Uxz0bUxEcdIO8uYlHstom5K69GHsQbXlRZltGem8km8/2Wlh
W7KNQWEM/j8wMjqd7hCnOR/7vc9tU5rPY9Oyeqi0H70oGVxIOazyeJ3I2cVoMpvG0/M3Mp5ORnIy
k+fxiOTLtnFa51k5opGzln937k/x/9QZeVW3labDBHROsbENldbR8zCQ1+6ryXV0RnvbUa4a0oVh
4q3xVKumU1W1p5DQeU1hlljX4nCbKI3TjyEcUkMNFeKFpcYyKf8lHCe2pIqi/0xfVlXUWsd+/FRx
ODCUKXSpuop/7DJ6VZqKtYvmq+ubu4ySxSK9yeijnMtP0fzdenOfbJY/7a7vsqOjIqHDBaKmMA2s
SYjDukkvkyxdvk5vs+Tt5er2fboksXvK/i6vJZPX7cmQocr+Iofz9rjkdXrfbw4xUfTPQXF88oJd
aO9Dugh/wumdzlk8Gt4OnYit9SxaZ7fmwbAu+qzn9/irvMX66mqVRf96SgEAAAAAAAAAAAAAAAAA
AAAA4JRv3P93qAAoAAA=
iptables.tgz.b64
        fi

        in_chroot "$install_root" 'systemctl enable iptables.service'
    fi

    # Enable ip6tables
    if [ -f "${install_root}etc/sysconfig/ip6tables-config" ]; then
        if [ ! -s "${install_root}etc/sysconfig/ip6tables" ]; then
# md5(ip6tables.tgz.b64) = 7dab0acaf7c557443e9b86db7bc54fe2
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'ip6tables.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAAAAAAAAA+3SUWvbMBAAYD/7Vxz0bUxETlJ3+M1LPJbRNiV16cPYg2rJizLbMtK5Jf9+spOO
bUk2BoVRuM8YGZ/uzhansBi5rStMU+qvI93GKB4q5YKXxL2Y82Hlh2sUXUyCaDoZT84v+HgSBTya
+isA/qJfcULnUFiAwBqDf9r3t/grdQZO1G2lYDcBnRWoTQOlsfBjGMAp+6gLFZ7B1nRQiAaU1Ai4
1g5q0XSiqrbgMzqnwA8TqprtyrFSW/Xkwz7VNxE+Lg00BkG4b347oAEhZX/rvq+ooDUW3Wjfcdgw
tJGqFF2Fv35m+KbUFSobJovrm7sc0tksu8nhM0/4lzD5sFzdp6v5b2+Xd/nBVpbCrgCrwY8DKmBs
t66yyzTP5m+z2zx9f7m4/ZjNgW322T/ltf60HmOmi7o9GtdQmROJWLSHfa+z+/7lEGOyPxMYj48W
kFCqdzxJRvG0r9bJodqw7BPPp/GJBkfKbfwvf8pm/olZtVEFsieNa+h/LGZC1qy1Zq0fNCrZZz2f
8T/lzZZXV4s8/N+jTwghhBBCCCGEEEIIIYQQQgghhBBCyKv3HSd9ETwAKAAA
ip6tables.tgz.b64
        fi

        in_chroot "$install_root" 'systemctl enable ip6tables.service'
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

    local t network_manager

    if [ -f "${install_root}etc/NetworkManager/NetworkManager.conf" ]; then
        network_manager=1
    else
        network_manager=''
    fi

    # Configure nameserver(s) in resolv.conf
    t="${install_root}etc/resolv.conf"
    if [ -n "${nameservers}${install_root%/}" ]; then
        : >"$t"
    fi
    if [ -n "${nameservers}" ]; then
        local n
        for n in ${nameservers}; do
            echo "nameserver $n" >>"$t"
        done
    fi

    # Make sure /etc/sysconfig/network is here
    t="${install_root}etc/sysconfig/network"
    if ! [ -e "$t" ]; then
        # Remove broken symlink
        rm -f "$t" ||:
        : >"$t"
    fi

    # Support for network device group in NetworkManager ifcfg-rh plugin
    if [ -d "$t-scripts" ]; then
        if [ -n "$network_manager" ]; then
            nm_devgroup
        fi
    fi

    # Enable/disable legacy network scripts when no/ NetworkManager available
    if [ -x "${install_root}etc/init.d/network" ]; then
        if [ -z "$network_manager" ] ||
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
            in_chroot "$install_root" '
                # Keep opened sessions when xrdp.service stopped or
                # restarted what is quite common on package upgrade.
                systemctl cat xrdp-sesman.service | \
                    sed -e "/^# \(\/[^/]\+\)\+/d" \
                        -e "/^\(BindsTo\|StopWhenUnneeded\)=/d" | \
                systemctl edit --full xrdp-sesman.service

                systemctl enable xrdp-sesman.service
            '
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
            _config_sshd_file="$file"
        else
            sed -i "$file" \
                -e '/^#\?LoginGraceTime/iAllowGroups root users' \
                -e 's/^#\?\(PermitRootLogin\s\+\).*$/\1without-password/' \
                -e 's/^#\?\(UseDNS\s\+\).*$/\1no/' \
                -e 's/^#\?\(VersionAddendum\s\+\).*$/\1none/' \
                #
            _config_sshd_file=''
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

        local _cfg_replace_append_nohdr
        if [ -d "$dir/jail.d" ]; then
            dir="$dir/jail.d"
            file="$dir/99-$prog_name.conf"
            : >"$file"
            _cfg_replace_append_nohdr='1'
        else
            file="$dir/jail.local"
            _cfg_replace_append_nohdr=''
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

        if grep -q 'is not required or honoured if using systemd socket$' \
            "${install_root}etc/libvirt/libvirtd.conf"
        then
            in_chroot "$install_root" 'systemctl edit libvirtd.socket' <<EOF
[Socket]
${libvirt_unix_group:+SocketGroup=$libvirt_unix_group}
${libvirt_unix_rw_perms:+SocketMode=$libvirt_unix_rw_perms}
EOF

            in_chroot "$install_root" 'systemctl edit libvirtd-ro.socket' <<EOF
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

    local file
    local _cfg_replace_append_nohdr

    # Configure sudo(8)
    file="${install_root}etc/sudoers"
    if [ -f "$file" ]; then
        local dir="$file.d"
        if [ -d "$dir" ] &&
           grep -q "^\s*[#@]includedir\s*/${dir#$install_root}/\?\s*$" "$file"
        then
            file="$dir/99-$prog_name"
            : >"$file"
            _cfg_replace_append_nohdr='1'
        else
            _cfg_replace_append_nohdr=''
        fi

        cfg_replace "$user" "$file" "
$user	ALL = (root:root) NOPASSWD: ALL
"
    fi

    # Create user and group, add supplementary group libvirt and
    # set home directory if libvirt installed
    in_chroot "$install_root" "
        dir='/var/lib/libvirt'
        [ -d \"\$dir\" ] || dir=''

        group='libvirt'
        id -g \"\$group\" >/dev/null 2>&1 || group=''

        if [ ~$user != '~$user' ]; then
            usermod -a -s '/bin/sh' \
                \${group:+-G \"\$group\" }\${dir:+-d \"\$dir\" }'$user'
        else
            useradd -r -s '/bin/sh' \
                \${group:+-G \"\$group\" }-d \${dir:-/} -M '$user'
        fi
    "

    # Configure sshd(8)
    file="${install_root}etc/ssh/sshd_config"
    if [ -f "$file" ]; then
        in_chroot "$install_root" "usermod -a -G users '$user'"

        local keys='etc/ssh/authorized_keys'
        install -d -m 0751 "$install_root$keys"
        keys="/$keys"

        if [ -n "${_config_sshd_file-}" ]; then
            file="${_config_sshd_file}"
            _cfg_replace_append_nohdr='1'
        else
            _cfg_replace_append_nohdr=''
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
        if pkg_is_installed 'postfix'; then
            t="${install_root}etc/rwtab.d/postfix"
            [ -s "$t" ] || {
                echo 'dirs /var/lib/postfix'
            } >"$t"
        fi

        # Make rsyslog readonly root aware
        if pkg_is_installed 'rsyslog'; then
            t="${install_root}etc/rwtab.d/rsyslog"
            [ -s "$t" ] || {
                echo 'dirs /var/lib/rsyslog'
            } >"$t"
        fi

        # Make gssproxy readonly root aware
        if pkg_is_installed 'gssproxy'; then
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
        t="${install_root}etc/sysconfig/readonly-root"
        if [ -f "$t" ]; then
            sed -i "$t" \
                -e 's/^\(READONLY=\)\w\+\(\s*\)$/\1yes\2/' \
                #
        fi
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

# Usage: config_dracut
config_dracut()
{
    local file="${install_root}etc/dracut.conf"

    if [ -f "$file" ]; then
        if [ -n "$nfs_root" ]; then
            local dir="$file.d"
            if [ -d "$dir" ]; then
                file="$dir/99-$prog_name.conf"
                : >"$file"
                _cfg_replace_append_nohdr='1'
            else
                _cfg_replace_append_nohdr=''
            fi

            cfg_replace 'nfs_root' "$file" '
# Build generic image regardless (like dracut-config-generic package)
hostonly="no"
# Add "nfs" dracut module (from dracut-network package)
add_dracutmodules+=" nfs "
'
        fi

        # Update initramfs file
        in_chroot "$install_root" '
            if dracut --help 2>&1 | grep -q -- "--regenerate-all"; then
                exec dracut --force --regenerate-all
            else
                for kmod in /lib/modules/*; do
                    if [ -d "$kmod" ] &&
                       kver="${kmod##*/}" &&
                       [ -n "$kver" -a -f "/boot/vmlinuz-$kver" ]
                    then
                        dracut --force "/boot/initramfs-$kver.img" "$kver"
                    fi
                done
            fi
        '
    fi
}

# Usage: config_grub_ipxe
config_grub_ipxe()
{
    # Usage: copy_ipxe_file <boot_ipxe>
    copy_ipxe_file()
    {
        local func="${FUNCNAME:-copy_ipxe_file}"

        local ipxe="${1:?missing 1st argument to ${func}() <ipxe>}"
        local ipxe_name="${2:-$ipxe}"
        local ipxe_iter

        for ipxe_iter in \
            "${install_root}usr/share/ipxe/$ipxe" \
            "${install_root}usr/lib/ipxe/$ipxe" \
            #
        do
            if [ -f "$ipxe_iter" ]; then
                install -D -m 0644 \
                    "$ipxe_iter" "${install_root}boot/$ipxe_name" ||
                return
            fi
        done

        return 1
    }

    local rc=0
    if ! copy_ipxe_file 'ipxe.efi'; then
        if [ -n "${grp_efi_ia32-}" ]; then
            copy_ipxe_file 'ipxe-i386.efi' 'ipxe.efi' || rc=1
        else
            copy_ipxe_file 'ipxe-x86_64.efi' 'ipxe.efi' || rc=1
        fi
    fi
    copy_ipxe_file 'ipxe.lkrn' || rc=2

    unset -f copy_ipxe_file

    if [ $rc -lt 2 ]; then
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
    local t="${install_root}etc/grub.d/00_header"
    if [ -f "$t" ]; then
        # Add default GRUB config
        t="${install_root}etc/default/grub"

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

        # Update GRUB2 configuration file
        if [ -z "${install_root%/}" ]; then
            in_chroot "$install_root" '
                  if command -v grub2-mkconfig >/dev/null 2>&1; then
                    grub2_mkconfig() { exec grub2-mkconfig "$@"; }
                elif command -v update-grub2   >/dev/null 2>&1; then
                    grub2_mkconfig() { exec update-grub2; }
                else
                    grub2_mkconfig() {
                        echo >&2 "No GRUB2 config management tool found."
                        exit 1
                    }
                fi
                [ ! -L /etc/grub2.cfg ] ||
                    grub2_mkconfig -o "$(readlink -f /etc/grub2.cfg)"
                [ ! -L /etc/grub2-efi.cfg ] ||
                    grub2_mkconfig -o "$(readlink -f /etc/grub2-efi.cfg)"
            '
        fi
    fi
}

# Usage: config_kernel_symlink_to_root
config_kernel_symlink_to_root()
{
    local unpack_dir="$install_root"
# md5(symlink-to-root.tgz.b64) = b02e2fcd4b5385f931e6e2cbe3069bb0
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'symlink-to-root.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
/yP9AaumBSsAKAAA
symlink-to-root.tgz.b64
}

# Usage: config_kernel_initrd_chmod_0644
config_kernel_initrd_chmod_0644()
{
    local unpack_dir="$install_root"
# md5(initrd-chmod-0644.tgz.b64) = 4e0d5b397d569d08953f2ef3a5fdeff3
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'initrd-chmod-0644.tgz.b64' | tar -zxf - -C "$unpack_dir"
H4sIAAAAAAAAA+2UXWviQBSGvZ5fMUaLVIiTD5vAiiy2SpGtCrb0prtINKMONYkksYjW/75noqbx
g5b2YpfCeW4mc8575vvNIgrZTAzZMw99PmPCj2JnNqu4bLVShS/i0FVHUy9wVc2qViu7dO5zaIBt
XyUtcNxCzsjpVVO3bLtqaFZOM3TTvMpR7ZPzfIkF7CikNBcGQfye7qP8N6WQZ0Phs2hKyDwMJgPf
8XhdKa61QqHMNgohseylqYv9E4DUE1WKsULzdWhTgUL/0NdXypciplpSHFeiKYxz0+t0Gt0mBHSF
/Gr1u627wWOrf9/udSFmKOS613sYNNv9QeP6HiJmqmp3GrctiFRhlCequjBdVrub8aC8xIZwXSVy
PERWxF68mfAXK7V4uBqYZeREnMqFUuETCjiue5l8SGBTjMejvWXmQRTLQwHPwHGkqlot+Qy5F7zw
d4tD73xp+a1qd5wZAY+ckTyOPFWX23vYnTsfbbvK8bbeIslpKNv7P7+Rs+aPpl98Yx/539I16X9D
t0zbMCGu25atof//BRn/8+U8CGN61+je1m/IqUfX+o+fnogi4U/oYXJz4tW1caJNUvKPku1LM0p5
NnbBylI2DkLa7rYf+s1tGLxIfycWKCVv0/HGUekg4u67BeIGyUe2/ngaOfWGFddZzUZNNfutVYQ3
2VpTjCn8fsbgo2wJGK9G4yn3U3cmlqHSMsfSVDIMufOc9MYC1upz8r/fAYIgCIIgCIIgCIIgCIIg
CIIgCIIgCIIg35e/bUTfmQAoAAA=
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
        if [ "${has_dm-}" = 'lightdm' ] && pkg_is_installed 'light-locker'; then
            local p1='^\(\s*<property name="LockCommand" \)type="empty"/>$'
            local p2='\1type="string" value="light-locker-command --lock"/>'

            local t='.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml'
            sed -i "$unpack_dir/$t" \
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
                [ -d \"\$t\" ] || t=''
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
    if in_chroot "$install_root" \
        'command -v flatpak >/dev/null 2>&1'
    then
        local unpack_dir="$install_root"
# md5(flatpak.tgz.b64) = 089c3a1de1c053c23df637c08d048b6f
[ -d "$unpack_dir" ] || install -d "$unpack_dir"
base64 -d -i <<'flatpak.tgz.b64' | tar -zxf - -C "$unpack_dir"
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
flatpak.tgz.b64
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
readonly _tmp_mount_min=10
readonly _tmp_mount=25
readonly _tmp_mount_max=50
tmp_mount=${_tmp_mount}
# Plymouth
readonly _plymouth_theme='tribar'
plymouth_theme=''
readonly _plymouth_type='text'
plymouth_type=''
# Serial line console
readonly _serial_console='console=ttyS0,115200n8'
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
readonly _nameservers='1.1.1.1 8.8.8.8'
nameservers=''
# DNS split using NetworkManager and dnsmasq
nm_dnsmasq_split=''

# KVM nesting
kvm_nested=''
# libvirt qemu user to run as
readonly _libvirt_qemu_user='qemu'
libvirt_qemu_user=''
# libvirt UNIX socket group ownership
readonly _libvirt_unix_group='libvirt'
libvirt_unix_group=''
# libvirt UNIX R/O socket permissions
readonly _libvirt_unix_ro_perms='0777'
libvirt_unix_ro_perms=''
# libvirt UNIX R/W socket permissions
readonly _libvirt_unix_rw_perms='0770'
libvirt_unix_rw_perms=''
# libvirt UNIX R/O authentication
readonly _libvirt_unix_auth_ro='none'
libvirt_unix_auth_ro=''
# libvirt UNIX R/W authentication
readonly _libvirt_unix_auth_rw='none'
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
        vars="$(
            # Usage: env [<filter>] [<with_val>]
            env()
            {
                export -p | while read -r var; do
                    var="${var#export }"
                    t="${var%%=*}"
                    case "$t" in
                        'PATH'|'TERM'|'HOME'|'PWD')
                            # No shell specific variables
                            [ -z "${1-}" ] || continue
                            ;;
                        _*|has_*|is_*|this_*|prog_*|V)
                            # No internal variables
                            [ -z "${1-}" ] || continue
                            ;;
                        pkg_*|grp_*)
                            # No packages and groups for minimal install
                            [ -z "${1-}" -o -z "$minimal_install" ] || continue
                            ;;
                        '')
                            # No empty variable names (never happens)
                            continue
                            ;;
                    esac
                    [ -n "${2-}" ] || var="$t"
                    echo "$var"
                done
            }

            for var in $(env); do
                unset "$var"
            done

            set -a
            . "$config" >/dev/null || exit

            env 'filter' 'with_val'
        )" || fatal 'unable to include "%s" config\n' "$config"
        eval "$vars"
        unset vars
    else
        fatal 'cannot find "%s" config\n' "$config"
    fi
else
    minimal_install=1
fi

# $install_root and $build_info_dir
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
build_info_dir="${install_root}.${prog_name}"

# Install build information
if [ -n "$build_info" ]; then
    # $this
    if [ -e "$this" ]; then
        install -D "$this" "$build_info_dir/${_prog_name}"
    fi

    # $config
    if [ -n "$config" ]; then
        f="${config##*/}" &&
            install -D -m 0644 "$config" "$build_info_dir/$f" &&
        f="${f:+--config=\"\$this_dir/$f\"}"
    else
        f=''
    fi

    # run.sh
    d="$build_info_dir/run.sh.$$"
    cat >"$d" <<EOF
#!/bin/sh

# Set option(s)
set -e
set -u
#set -x

build_info_dir='$build_info_dir'
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
    install -D -m 0755 "$d" "${d%.*}"
    rm -f "$d" ||:

    unset f d
fi

# $cc handled after release package(s) installation

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
    'enforcing'|'permissive'|'disabled'|'')
        [ -z "$readonly_root" ] || selinux='permissive'
        ;;
    *)
        fatal 'Unknown SELinux mode "%s"\n' "$selinux"
        ;;
esac

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

## Final installation steps

# Usage: exit_installed
exit_installed()
{
    local t f

    if :; then
        # Configure iptables
        config_iptables

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

        # Disable lm_sensors as they require explicit configuration
        if [ -f "${install_root}etc/sysconfig/lm_sensors" ]; then
            in_chroot "$install_root" 'systemctl disable lm_sensors.service'
        fi

        # Disable mcelog as it might fail to run in virtualized environment
        if [ -f "${install_root}etc/mcelog/mcelog.conf" ]; then
            in_chroot "$install_root" 'systemctl disable mcelog.service'
        fi

        # Enable display-manager.service and set-default to graphical.target
        if [ -n "${has_dm-}" ]; then
            in_chroot "$install_root" "systemctl enable '$has_dm.service'"
            in_chroot "$install_root" 'systemctl set-default graphical.target'
        fi

        # Enable postfix as it might be disabled (e.g. on CentOS/RHEL 8)
        if [ -f "${install_root}etc/postfix/main.cf" ]; then
            in_chroot "$install_root" 'systemctl enable postfix.service'
        fi

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
        # Make sure /var/lib/systemd/random-seed is here and empty
        t="${install_root}var/lib/systemd" && [ ! -d "$t" ] || : >"$t/random-seed"
        # Make sure /etc/machine-id is here and empty
        t="${install_root}etc/machine-id" && : >"$t"

        # Configure plymouth
        config_plymouth

        # Configure dracut
        config_dracut

        # Configure grub2
        config_grub

        # Restore /etc/yum.conf.rhbootstrap after yum(1) from EPEL install
        f="${install_root}etc/yum.conf"
        t="$f.rhbootstrap"
        if [ ! -e "$f" -a -e "$t" ]; then
            mv -f "$t" "$f" ||:
        else
            rm -f "$t" ||:
        fi

        if [ -n "$nodocs" ]; then
            # Directories not excluded from install. They are empty.
            find "${install_root}usr/share/doc" -type d -a -empty -a -delete
        fi

        # Remove artifacts
        in_chroot "$install_root" 'rm -f /null ||:'

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

## Initial installation setups

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

    if [ -n "${helpers_dir-}" ]; then
        rm -rf "$helpers_dir" ||:
    fi
    if [ -n "${rpm_gpg_dir-}" ]; then
        rm -rf "$rpm_gpg_dir" ||:
    fi

    return $rc
}
trap 'exit_handler' EXIT

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
has_setopt='1'
# reset variables
unset has_de has_dm gtk_based_de

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
    if [ -z "$releasever" ]; then
        if is_centos; then
            # Default CentOS version is 8-stream
            releasever='8-stream'
        else
            # Default Rocky/other version is 8
            releasever='9'
        fi
    fi

    if [ -z "${releasever%%*-stream}" ]; then
         releasemaj="${releasever%-stream}"
         releasemin="$(centos_stream_compose_id)"
    else
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

    # Usage: _fedora_releasever_latest
    _fedora_releasever_latest()
    {
        local func="${FUNCNAME:-_fedora_releasever_latest}"

        local url='https://dl.fedoraproject.org/pub/fedora/linux/releases/'
        local min=${fedora_releasever_min:-10} max=${fedora_release_max:-99}
        local releasever
        local r

        [ $max -ge $min ] ||
            abort '%s: min greather than max\n' "$func"

        t="$(
            safe_curl "$url" $((128*1024)) -L |\
            sed -n -e 's,^.*<a href=.\+>\([[:digit:]]\+\)/\?</a>.*$,\1,p'
        )" ||:

        # Pick highest parsed version or hint if none
        releasever=$min
        for r in ${t:-$releasever}; do
            if [ $r -gt $releasever ]; then
                releasever=$r
            fi
        done
        [ $releasever -gt $min ] || releasever=$max

        r=$releasever
        while ! safe_curl "$url$r/Everything/" $((128*1024)) -L >/dev/null; do
            if [ $r -le $min ]; then
                releasever=''
                break
            else
                : $((r -= 1))
            fi
        done

        [ -n "$releasever" ] && printf -- '%s\n' "$releasever" || return
    }
    readonly fedora_releasever_min=10
    readonly fedora_releasever_max=99

    readonly fedora_releasever_latest="$(_fedora_releasever_latest)" ||
        fatal 'unable to determine latest Fedora release version\n'

    unset -f _fedora_releasever_latest

    # $releasever
    [ -n "$releasever" ] || releasever="$fedora_releasever_latest"

    releasemaj="${releasever%%.*}"

    if [ $releasemaj -lt 12 ]; then
        if [ $releasemaj -lt $fedora_releasever_min ]; then
            fatal 'no support for Fedora before %u (Fedora Core?)\n' \
                $fedora_releasever_min \
                #
        fi
        has_setopt=''
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

## Install core components

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

    # Provide empty /etc/fstab and /etc/mtab unless they already exists
    for f in 'fstab' 'mtab'; do
        f="${install_root}etc/$f"
        if [ ! -f "$f" ]; then
            # Remove broken symlink
            rm -f "$f" ||:
            install -D -m 0644 /dev/null "$f"
        fi
    done
    # f="${install_root}etc/mtab"
    ln -snf '../proc/self/mounts' "$f" ||:

    # Hide /proc/1 from target (e.g. for rpm pre/post scripts)
    f="${install_root}proc/1"
    d="${install_root}.tmp/1"

    [ -d "$f" ] && install -d "$d" && mount --bind "$d" "$f" ||:

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

    unset f d
fi
cd "$install_root"

# Prepare helpers
helpers_dir="$build_info_dir/bin"
config_helpers

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

if [ -n "${install_root%/}" ]; then
    # Convert rpmdb(1) from host to target format
    if rocky_version_ge $releasemaj 9 ||
       centos_version_ge $releasemaj 9 ||
       fedora_version_ge $releasemaj 33
    then
        in_chroot "$install_root" 'rpm --rebuilddb'
    else
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
fi

# Perform distro specific actions post initial setup
distro_post_core_hook

if [ -n "$minimal_install" ]; then
    nfs_root=''
    nm_dnsmasq_split=''
fi

# $nfs_root

if [ -n "$nfs_root" ]; then
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

if [ -n "$minimal_install" ]; then
    exit_installed
fi

## Release specific tricks

pkg_xfce_screensaver=1
pkg_remmina_plugins_secret=1
pkg_wireshark_gnome=1
pkg_xorg_x11_utils=1

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
    ## <= $releasemaj

    fedora_le_11() {
        pkg_dracut=
        [ "${x11_server-}" != 'Xrdp' ] || x11_server='Xorg'
    }
    fedora_le_12() {
        pkg_vdpau=
    }
    fedora_le_14() {
        pkg_va=
    }
    fedora_le_15() {
        [ "${x11_server-}" != 'Xspice' ] || x11_server='Xorg'
    }
    fedora_le_16() {
        pkg_ipxe_bootimgs=
    }
    fedora_le_17() {
        pkg_shim=
        pkg_mate=
    }
    fedora_le_18() {
        pkg_va_vdpau_driver=
    }
    fedora_le_19() {
        [ "${x11_server-}" != 'x2go' ] || x11_server='Xorg'
    }
    fedora_le_23() {
        pkg_flatpak=
    }
    fedora_le_24() {
        pkg_glvnd=
        pkg_chromium=
        pkg_pidgin_hangouts=
        pkg_nm_openconnect=
        pkg_nm_l2tp=
    }
    fedora_le_25() {
        pkg_driverctl=
        pkg_slick_greeter=
        pkg_glvnd_egl=
        pkg_glvnd_gles=
        pkg_glvnd_glx=
    }
    fedora_le_26() {
        pkg_va_intel_hybrid_driver=
    }
    fedora_le_27() {
        pkg_iucode_tool=
        pkg_remmina_plugins_secret=
    }
    fedora_le_28() {
        pkg_network_scripts=
    }
    fedora_le_29() {
        pkg_xfce_screensaver=
    }

    r=$releasemaj
    while :; do
        f="fedora_le_${r}"
        if shell_type_is_function "$f"; then
            "$f"
        fi
        [ $((r += 1)) -le $fedora_releasever_latest ] || break
    done

    ## >= $releasemaj

    fedora_ge_24() {
        pkg_wireshark_gnome=
    }
    fedora_ge_34() {
        pkg_orage=
        pkg_ntpdate=
    }
    fedora_ge_35() {
        pkg_xorg_x11_utils=
        pkg_icedtea_web=
        pkg_libreoffice_rhino=0
        pkg_remmina_plugins_nx=
        pkg_remmina_plugins_xdmcp=
    }

    r=$releasemaj
    while :; do
        f="fedora_ge_${r}"
        if shell_type_is_function "$f"; then
            "$f"
        fi
        [ $((r -= 1)) -ge $fedora_releasever_min ] || break
    done

    ## common
    pkg_libguestfs_winsupport=

    unset f r
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
          if [ -n "$repo_openstack" -o -n "$repo_ovirt" ] ||
             fedora_version_ge $releasemaj 17; then
            PKGS="$PKGS openvswitch"

            if ! is_fedora || version_ge $releasemaj 31; then
                [ -z "${pkg_openvswitch_ipsec-}" ] ||
                    PKGS="$PKGS openvswitch-ipsec"
            fi
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
        xfce4-screenshooter

        gnome-themes-standard
    "

    # xfce4-screensaver
    [ -z "${pkg_xfce_screensaver-}" ] || PKGS="$PKGS xfce4-screensaver"

    if [ -n "${pkg_thunar-}" ]; then
        PKGS="$PKGS Thunar"

        # thunar-archive-plugin
        [ -z "${pkg_thunar_archive_plugin-}" ] ||
            PKGS="$PKGS thunar-archive-plugin"
        # thunar-vcs-plugin
        [ -z "${pkg_thunar_vcs_plugin-}" ] ||
            PKGS="$PKGS thunar-vcs-plugin"
        # thunar-volman
        [ -z "${pkg_thunar_volman-}" ] ||
            PKGS="$PKGS thunar-volman"
    fi

    # evince
    [ -z "${pkg_evince-}" ] || PKGS="$PKGS evince"
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
        if is_rocky ||
           centos_version_ge $releasemaj 7 ||
           fedora_version_ge $releasemaj 21
        then
            PKGS="$PKGS caja"

            # caja-schemas
            [ -z "${pkg_caja_schemas-}" ] ||
                PKGS="$PKGS caja-schemas"

            if is_fedora || [ $releasemaj -le 8 ]; then
                # caja-image-converter
                [ -z "${pkg_caja_image_converter-}" ] ||
                    PKGS="$PKGS caja-image-converter"
                # caja-open-terminal
                [ -z "${pkg_caja_open_terminal-}" ] ||
                    PKGS="$PKGS caja-open-terminal"
                # caja-sendto
                [ -z "${pkg_caja_sendto-}" ] ||
                    PKGS="$PKGS caja-sendto"
            fi

            # atril-caja
            if [ -n "${pkg_evince-}" ]; then
                PKGS="$PKGS atril-caja"
            fi

            # seahorse-caja
            if [ -n "${pkg_seahorse-}" ]; then
                if is_rocky ||
                   centos_version_ge $releasemaj 8 ||
                   fedora_version_ge $releasemaj 28
                then
                    PKGS="$PKGS seahorse-caja"
                fi
            fi
        else
            PKGS="$PKGS nautilus"

            if is_fedora || centos_version_ge $releasemaj 6; then
                # nautilus-image-converter
                [ -z "${pkg_caja_image_converter-}" ] ||
                    PKGS="$PKGS nautilus-image-converter"
            fi
            # nautilus-open-terminal
            [ -z "${pkg_caja_open_terminal-}" ] ||
                PKGS="$PKGS nautilus-open-terminal"
            # nautilus-sendto
            [ -z "${pkg_caja_sendto-}" ] ||
                PKGS="$PKGS nautilus-sendto"

            # evince-nautilus
            if [ -n "${pkg_evince-}" ]; then
                if fedora_version_ge $releasemaj 13; then
                    PKGS="$PKGS evince-nautilus"
                fi
            fi

            # seahorse-nautilus
            if [ -n "${pkg_seahorse-}" ]; then
                if fedora_version_ge $releasemaj 17; then
                    PKGS="$PKGS seahorse-nautilus"
                fi
            fi
        fi
    fi

    # pluma
    [ -z "${pkg_pluma-}" ] || PKGS="$PKGS pluma"
    # eom
    [ -z "${pkg_eom-}" ] || PKGS="$PKGS eom"
    # engrampa
    [ -z "${pkg_engrampa-}" ] || PKGS="$PKGS engrampa"
    # seahorse
    [ -z "${pkg_seahorse-}" ] || PKGS="$PKGS seahorse"

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
        # xorg-x11-utils
        [ -z "${pkg_xorg_x11_utils-}" ] ||
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
