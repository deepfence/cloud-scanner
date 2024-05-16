#!/bin/bash
set -e

sudo su root -c "service cron start && (echo \"*/5 * * * * /usr/sbin/logrotate /etc/logrotate.d/logrotate.conf\") | crontab -" 2>&1

if [[ "${1#-}" != "$1" ]];
then
    set -- /usr/local/bin/cloud_scanner "$@" 
fi

exec "$@"
