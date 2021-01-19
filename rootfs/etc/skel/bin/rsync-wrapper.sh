#!/bin/sh -e

# Requires: rsync(1), mv(1), mkdir(1), id(1), mktemp(1), cat(1), pwd(1)

# This wrapper intended to start rsync(1) daemon on remote machine using
# ssh(1) as remote-shell transport with per user rsyncd.conf(5).
#
# It can be started either directly from rsync(1) client on local machine
# or via forced command given in authorized_keys(8) on remote machine.
#
# To start directly you need to tell rsync(1) to use remote-shell program
# for transfers and supply --rsync-path pointing to absolute path to
# wrapper on remote machine:
#
#   $ rsync -av -e ssh --rsync-path='$HOME/bin/rsync-wrapper.sh' ...
#
# To start with forced command you need to have either "ForcedCommand"
# in sshd_config(8) or per ssh key "command"
# (e.g. command="$HOME/bin/rsync-wrapper.sh") option given in user/system
# authorized_keys(8) file and run following command on local machine:
#
#   $ rsync -av -e ssh ...
#
# See rsync(8), rsyncd.conf(5), sshd(8), sshd_config(5) for more
# information.

### See how we where called ###

if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
	set -- $SSH_ORIGINAL_COMMAND

	# Ignore anything except rsync(8)
	rsync="$1"
	[ "${rsync##/*/}" = 'rsync' ]
	# Skip to the rsync arguments
	shift
else
	rsync='rsync'
fi

### Make default configuration file in case of none exists ###

# Retermine home directory. If no HOME variable is set assume current
# working directory as home since we expected to be called from sshd(8).
rsync_home="${HOME:-$(pwd)}"

# Determine config directory and file.
if [ -d "$rsync_home/.config" ]; then
	rsync_config_dir="$rsync_home/.config/rsync/"
else
	rsync_config_dir="$rsync_home/."
fi
rsync_conf="${rsync_config_dir}rsyncd.conf"

# Avoid overwriting existing config file.
if [ ! -f "$rsync_conf" -o ! -s "$rsync_conf" ]; then
	# Prepare temporary file name for configuration output.
	rsync_conf_tmp="$(mktemp -u "$rsync_conf.XXXXXXXX")"
	[ -n "$rsync_conf_tmp" ]

	# Establish info needed for configuration file template.
	rsync_uid="${USER:-$(id -un)}"
	rsync_gid="${GROUP:-$(id -gn)}"

	rsync_tmp_dir="$rsync_home/tmp/"
	[ -d "$rsync_tmp_dir" ] || rsync_tmp_dir="$rsync_home/."
	rsync_log_file="${rsync_tmp_dir}rsync.log"
	rsync_lock_file="${rsync_tmp_dir}rsync.lock"

	# Ensure configuration directory exists and create if it does
	# not. This action should be last to reduce number of changes
	# this routine left in case of error.
	if [ ! -d "$rsync_config_dir" ]; then
		mkdir "$rsync_config_dir"
	fi

	# Output configuration to temporary file.
	cat >"$rsync_conf_tmp" <<EOF
#
# GLOBAL OPTIONS
#

#uid		= $rsync_uid
#gid		= $rsync_gid
use chroot	= no
read only	= yes
list		= no
timeout		= 300
numeric ids	= yes
motd file	= /etc/issue.net
transfer logging \\
		= yes
log file	= $rsync_log_file
lock file	= $rsync_lock_file
ignore nonreadable \\
		= yes
exclude		= aquota.*
dont compress	= *.zip *.rar *.7z *.rpm *.deb *.cab *.wim *.iso *.bz2 *.bzip2 \\
		  *.tbz *.tbz2 *.gz *.gzip *.tgz *.taz *.z *.xz *.tpz *.tzx \\
		  *.lzma *.lzh *.lzo *.lzop *.arj *.arc *.lha *.vhd *.squashfs \\
		  *.bin *.img *.ima

#[root]
#	comment		= "Read access via rsync protocol to rootfs"
#	path		= /
#	list		= yes

[home]
	comment		= "Read/write access via rsync to home directory"
	path		= $rsync_home
	list		= yes
	read only	= yes
EOF

	# Install new configuration file atomically.
	mv "$rsync_conf_tmp" "$rsync_conf"
fi

### Execute rsync(8) if executable ###
exec "$rsync" --config "$rsync_conf" "$@"

### Never reached ###
exit 1
