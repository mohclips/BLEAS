#!/bin/bash

RESET=$1
shift

clear

DATE=$(date)
echo "+ Running startup script at $DATE"


#cd /home/nick/workspaces/ble_scanner/

SUDOPASS=$(cat .sudopass)

if [[ ! -z $RESET ]] ; then
    echo "+ reset usb port"
    echo $SUDOPASS | sudo -S python3 reset_usb.py search "Bluetooth"

    echo "+ restart bluetooth service"
    echo $SUDOPASS | sudo -S service bluetooth restart

    echo "+ dmesg logs"
    echo $SUDOPASS | sudo -S dmesg -T | tail -50 | egrep -i "usb|blue"
fi

echo "+ running..."
python3 -u ./main.py 2>&1 | tee ./run-$(date +'%s').log
