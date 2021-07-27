#!/bin/bash

# check for root permission
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root"
	exit 1
fi

function cleanup() {
	echo "Remove syndrv kernel module"
	rmmod syndrv
	echo
}

function inttrap(){
	exit
}

trap cleanup EXIT
trap inttrap SIGINT

echo "Instal syndrv kernel module"
insmod kernel/syndrv.ko
echo "Start processing NFQUEUE"
user/filter
