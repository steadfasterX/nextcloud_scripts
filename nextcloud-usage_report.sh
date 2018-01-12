#!/bin/bash

# By Georgiy Sitnikov.
# This script works with https://apps.nextcloud.com/apps/user_usage_report
# Will generate report and output it in cacti format
# Supports Argument as "user" if you need to check statistic for one user only
# run ./nextcloud-usage_report.sh user to get specific user information
# AS-IS without any worrenty

COMMAND=/var/www/nextcloud/occ
OPTIONS="usage-report:generate"
LOCKFILE=/tmp/nextcloud_usagereport
TMPFILE=/tmp/nextcloud_usagereport_tmp

[ -f "$LOCKFILE" ] && exit
touch $LOCKFILE

#get usage imnformation
php $COMMAND $OPTIONS $1 > $LOCKFILE

#generate log in Cacti format
awk -F, '{print $1"storage_all:"$3" " $1"storage_used:"$4" " $1"files_all:"$5" " $1"shares_new:"$6" " $1"files_new:"$7" " $1"files_read:"$8" "}' $LOCKFILE | sed 's/"//g' | sed ':a;N;$!ba;s/\n/ /g' >> $TMPFILE

cat $TMPFILE

rm $TMPFILE
rm $LOCKFILE
exit 0