#!/bin/bash
##############################################################################################
# LICENSE: GPL v3
# AS-IS without any warranty
#
# Copyright 2020-2021 Georgiy Sitnikov
# Copyright 2024 steadfasterX <steadfasterX | AT | gmail #DOT# com>
#
# source:
# https://github.com/steadfasterX/nextcloud_scripts/blob/main/nextcloud-duplicates-tagger.sh
#
##############################################################################################
# Searches for duplicate files in the specified user account and tags them
##############################################################################################

# the tag name for duplicates
# at least 1 file must be tagged in the user account (which is defined as user=xxx here)
tagName=duplicate

# nextcloud login
#NextcloudURL="https://yourFQDN/nextcloud"
#user="nextcloud-user"
#password="xxxxx-xxxxx-xxxxxx"	# recommended: create a web app password
# OPTIONAL: limit the search to a specific folder in nextcloud
# e.g. "https://yourFQDN/nextcloud/apps/files/xxxxx?dir=/Smartphone/camerapics" becomes:
# SUBPATH="Smartphone/camerapics"
# leave outcommented if you want to scan all files
#SUBPATH="nextcloud-URI-path"

# Log Level: none|Info|Debug
LogLvL=Info

# Path to nextcloud
NextCloudPath=/var/www/nextcloud

#####################
### End of Config ###
#####################

F_HELP(){
    cat <<_EOH

    # LICENSE: GPL v3
    # AS-IS without any warranty
    #
    # Copyright 2020-2021 Georgiy Sitnikov
    # Copyright 2024 steadfasterX <steadfasterX | AT | gmail #DOT# com>
    # https://github.com/steadfasterX/nextcloud_scripts/blob/main/nextcloud-duplicates-tagger.sh
    #
    # Searches for duplicate files in the specified user account and tags them

    Usage
    ---------------------

    when you set >user, password, NextcloudURL, NextCloudPath< in $0:
        $> $0

    or when you want to run this for multiple users and/or servers instead:
        $> $0 -u "username" -p "password" -s "nextcloud-url" [--path,--tag,--limit,...]

    Optional parameters
    ---------------------

    -u | --user <username>      the username where you want to search for duplicates
    -p | --password <password>  the corresponding (app) password
    -s | --server <nc-url>      the nextcloud base URI (e.g. https://yourFQDN/nextcloud)
         --path <nc-path>       local path to your nextcloud installation
    -t | --tag <tag name>       the tag name to be used (at least 1 file must have that tag manually set)
    -l | --limit <nc dir>       limit the search to a specific sub dir (e.g. "Smartphone/camerapics")
    -d | --debug                enables debug mode
    -q | --quiet                disables any output (errors will be still shown though)
    -r | --rescan               forces a full re-scan
    -h | -help | --help | help  this screen ;)

    For convenience you can set any of the above directly within $0
    e.g. you could specify global settings like "--path" in $0
    and user + password and any of the other as parameters on the CLI.

    Note: CLI parameters overwrite any defaults set in $0
    
_EOH
}

ReScan=no

# arg parser
while [ ! -z "$1" ];do
    case $1 in
        help|--help|-help|-h) F_HELP; exit;;
        -u|--user) user="$2"; shift 2;;
        -p|--password) password="$2"; shift 2;;
        -s|--server) NextcloudURL="$2"; shift 2;;
        -d|--debug) LogLvL=Debug; shift;;
        -q|--quiet) LogLvL=None; shift;;
        -r|--rescan) ReScan=yes; shift;;
        --path) NextCloudPath="$2"; shift 2;;
        -l|--limit) SUBPATH="$2"; shift 2;;
        -t|--tag) tagName="$2"; shift 2;;
        *) echo "wrong parameter >$1< !"; F_HELP; exit;;
    esac
done

if [ $LogLvL != "None" ];then
    if [ -z "$SUBPATH" ];then limitdir="-no limit-"; else limitdir="$SUBPATH";fi
    echo -e "\nStarting duplicate search!\n\nuser: $user\nNextcloudURL: $NextcloudURL\nNextCloudPath: $NextCloudPath\ntagName: $tagName\nSearch limited to: $limitdir\nLogLvL: $LogLvL\nReScan: $ReScan\n"
fi

LOCKFILE=/tmp/nextcloud-duplicates-tagger_${user}.tmp
[ "$ReScan" == "yes" ] && rm $LOCKFILE

# Check if config.php exist
[[ -r "$NextCloudPath"/config/config.php ]] || { echo >&2 "[ERROR] config.php could not be read under "$NextCloudPath"/config/config.php. Please check the path and permissions"; exit 1; }

# Fetch data directory place from the config file
DataDirectory=$(grep datadirectory "$NextCloudPath"/config/config.php | cut -d "'" -f4)

# Check if user Directory exist
[[ -d "$DataDirectory/$user" ]] || { echo >&2 "[ERROR] User "$user" could not be found. Please check if case is correct"; exit 1; }

getFileID () {

	fileid="$(curl -s -m 10 -u $user:$password ''$NextcloudURL'/remote.php/dav/files/'${user}'/'${SUBPATH}/${fileToTag}'' \
-X PROPFIND --data '<?xml version="1.0" encoding="UTF-8"?>
 <d:propfind xmlns:d="DAV:">
   <d:prop xmlns:oc="http://owncloud.org/ns">
     <oc:fileid/>
   </d:prop>
 </d:propfind>' | xml_pp | grep "fileid" | sed -n 's/^.*<\(oc:fileid\)>\([^<]*\)<\/.*$/\2/p')"

	[[ "$LogLvL" == "Debug" ]] && { echo "[DEBUG] Searching Nextcloud Internal FileID for $fileToTag"; }

	if [[ -z "$fileid" ]]; then

		[ $LogLvL != "None" ] && echo "[WARNING] File ID could not be found for >$fileToTag< will skip it."
		return 1

	else

		[[ "$LogLvL" == "Debug" ]] && { echo "[DEBUG] FileID is $fileid."; }
		return

	fi

}

getTag () {

	getAllTags="$(curl -s -m 10 -u $user:$password ''$NextcloudURL'/remote.php/dav/systemtags/' \
-X PROPFIND --data '<?xml version="1.0" ?>
<d:propfind  xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
  <d:prop>
    <oc:id />
    <oc:display-name />
    <oc:user-visible />
    <oc:user-assignable />
    <oc:can-assign />
  </d:prop>
</d:propfind>' | xml_pp | grep -B 1 -w "$tagName" | head -n 1)"

	if [[ ! -z "$getAllTags" ]]; then

		tagID="$(echo $getAllTags | sed -n 's/^.*<\(oc:id\)>\([^<]*\)<\/.*$/\2/p')"
		[[ "$LogLvL" != "None" ]] && { echo "[INFO] Internal TagID for tag $tagName is $tagID."; }

	else

		echo "[ERROR] Could to find tagID for a tag $tagName. Please check spelling and if tag exist"
		exit 1

	fi

}

SetTag () {

	[ $LogLvL != "None" ] && echo "[PROGRESS] Setting tag $tagName for $fileToTag."
	curl -s -m 10 -u $user:$password "$NextcloudURL/remote.php/dav/systemtags-relations/files/$fileid/$tagID" \
	 -X 'PUT' \
	 -H 'content-type: application/json' \
	 -H "origin: '$NextcloudURL'" \
	 --data-raw '{"id":'$tag',"userVisible":true,"userAssignable":true,"canAssign":true,"name":"'$tagName'"}'

}

checkIfTagIsSet () {

	if [[ ! -z "$fileid" ]]; then

		getAllTags="$(curl -s -m 10 -u $user:$password ''$NextcloudURL'/remote.php/dav/systemtags-relations/files/'$fileid'' \
-X PROPFIND --data '<?xml version="1.0" ?>
<d:propfind  xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
  <d:prop>
    <oc:id />
    <oc:display-name />
    <oc:user-visible />
    <oc:user-assignable />
    <oc:can-assign />
  </d:prop>
</d:propfind>' | xml_pp | grep -w "$tagName")"

		if [[ ! -z "$getAllTags" ]]; then

			[[ "$LogLvL" == "Debug" ]] && echo "[DEBUG] Tag $tagName is already set for $fileToTag, skipping."
   			return

		else

			[[ "$LogLvL" == "Debug" ]] && echo "[DEBUG] Tag $tagName is not set"
			SetTag && [[ "$LogLvL" != "None" ]] && echo "[INFO] Tag $tagName has been set successfully"

		fi

	fi

}

findDuplicates () {

	[ $LogLvL != "None" ] && echo "[PROGRESS] Searching for duplicates, this can take a long time..."
	cd $DataDirectory/$user/files/$SUBPATH

	find . ! -empty -type f -exec md5sum {} + | sort | uniq -w32 -dD >> $LOCKFILE
	[[ "$LogLvL" != "None" ]] && { echo "[INFO] Finally finished it is $(wc -l $LOCKFILE | awk '{print $1}') duplicates found"; }

}

checkLockFile () {

	if [ -f "$LOCKFILE" ] && [ $LogLvL != "None" ]; then

		# Remove lock file if script fails last time and did not run more than 10 days due to lock file.
		echo "[WARNING] - An older Duplicates report found in a $LOCKFILE,
            will use it to tag files, it contains $(wc -l $LOCKFILE | awk '{print $1}') duplicates.
            If you want to perform new search, please delete this file under: $LOCKFILE
            e.g. execute: rm $LOCKFILE

            File will be automatically deleted if older than 10 days.
"
		find "$LOCKFILE" -mtime +10 -type f -delete
		#exit 1

	fi

	touch $LOCKFILE

}

# From https://gist.github.com/cdown/1163649
urlencode() {

	local LANG=C i c e=''

	for ((i=0;i<${#1};i++)); do

		c=${1:$i:1}
		[[ "$c" =~ [a-zA-Z0-9\.\~\_\-] ]] || printf -v c '%%%02X' "'$c"
		e+="$c"

	done

	# sed here will return slashes back to the path
	echo "$e" | sed 's/%2F/\//g'

}

# From https://gist.github.com/cdown/1163649
urldecode() {

	# urldecode <string>

	local url_encoded="${1//+/ }"
	printf '%b' "${url_encoded//%/\\x}"

}

fileToTagPath() {

	urlencode "$(echo $line | cut -c 36-)"

}

checkLockFile

getTag

# Will use existing Tag report
[[ -s "$LOCKFILE" ]] || { findDuplicates; }

while read line; do

	# reading each line

	fileToTag=$(fileToTagPath)

	getFileID && checkIfTagIsSet

done < $LOCKFILE

[ $LogLvL != "None" ] && echo "Script ended with $?"
