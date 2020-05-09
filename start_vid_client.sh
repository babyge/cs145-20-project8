#! /bin/bash

if [ ! -z $1 ] || [ ! -z $2 ]; then
	~/mininet/util/m $1 /opt/google/chrome/google-chrome --enable-logging --v=1 --user-data-dir=~/project/project1/chromedata/${1}-datadir http://$2/streaming.html --no-sandbox
else
	echo "start_vid_client [host name] [server ip address]"
fi
