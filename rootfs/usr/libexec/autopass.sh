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
