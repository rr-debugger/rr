#!/bin/bash
echo "Disabling address space randomization...(sudo sysctl -w kernel.randomize_va_space=0)"
sudo sysctl -w kernel.randomize_va_space=0
echo "Adding permission to write to process memory...(sudo sysctl -w kernel.yama.ptrace_scope=0)"
sudo sysctl -w kernel.yama.ptrace_scope=0
#echo "Disabling shared memory extension for X window system..."
#if [[ -e "/etc/X11/xorg.conf" && 
#	  $(cat /etc/X11/xorg.conf | grep 'Option "MIT-SHM" "disable"') != "" &&
#	  $(cat /etc/X11/xorg.conf | grep 'Disable "dri"') != ""
#	  ]]; then
#	echo "Already disabled! Good."
#else
#	echo "Disabled. You will need to log out and back in to your system."
#	echo Section "Extensions" 		 > xorg.conf
#	echo Option "MIT-SHM" "disable" >> xorg.conf
#	echo EndSection				 	>> xorg.conf
#	echo Section "Module"			>> xorg.conf
#  echo Disable "dri"				>> xorg.conf
#	echo EndSection					>> xorg.conf
#	sudo mv xorg.conf /etc/X11/
#fi
