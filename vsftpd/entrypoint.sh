#!/bin/bash
set -e

FTP_USER="${FTP_USER:=skw}"
FTP_PASS="${FTP_PASS:=foobar}"

echo "[+] Using FTP_USER=${FTP_USER}"
echo "[+] Using FTP_PASS=${FTP_PASS}"

# Create user
adduser -D -h /home/ftpuser "$FTP_USER"
echo "$FTP_USER:$FTP_PASS" | chpasswd

# Set permissions
chown -R "$FTP_USER":"$FTP_USER" /home/ftpuser

# Configure vsftpd
cat <<EOF > /etc/vsftpd/vsftpd.conf
listen=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES

# Logging (FULL VERBOSE)
xferlog_enable=YES
xferlog_std_format=NO
log_ftp_protocol=YES
dual_log_enable=YES
vsftpd_log_file=/var/log/vsftpd.log

# Connection logging
connect_from_port_20=YES

# Passive mode
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30009

# Security
chroot_local_user=YES
allow_writeable_chroot=YES
seccomp_sandbox=NO
EOF

# Create log file
touch /var/log/vsftpd.log
chmod 666 /var/log/vsftpd.log

# Run vsftpd
exec vsftpd /etc/vsftpd/vsftpd.conf &
tail -f /var/log/vsftpd.log
