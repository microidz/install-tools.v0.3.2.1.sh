#!/bin/bash

#This script installs tools needed for the Threat Hunting classes on a
#deb package or rpm package -based system.  It also patches all
#installed packages.
#The general aim is that this will work on multiple Linux distributions
#that use either .deb or .rpm packages, though more testing is needed.
#Please contact bill@activecountermeasures.com if you have any updates
#on errors or compatibility issues found.  Many thanks to Chris B for
#the original idea and multiple improvements.


#Tested on:
#Ubuntu 18.04
#Centos 7
#Brief check on older Fedora Linux; note that rita is not set up to install on Fedora.  Otherwise good.

install_tools_version="0.3.2"

#Uncomment one of the following lines to set the default data set to download and install
data_needed="thunt"
#data_needed="packet-decode"


fail() {
	#Something failed, exit.

	echo "$@, exiting." >&2
	exit 1
}


require_sudo () {
    #Stops the script if the user does not have root priviledges and cannot sudo
    #Additionally, sets $SUDO to "sudo" and $SUDO_E to "sudo -E" if needed.

    if [ "$EUID" -eq 0 ]; then
        SUDO=""
        SUDO_E=""
        return 0
    elif sudo -v; then			#Confirms I'm allowed to run commands via sudo
        SUDO="sudo"
        SUDO_E="sudo -E"
        return 0
    else
	#I'm _not_ allowed to run commands as sudo.
	echo "It does not appear that user $USER has permission to run commands under sudo." >&2
	if grep -q '^wheel:' /etc/group ; then
	    fail "Please run    usermod -aG wheel $USER   as root, log out, log back in, and retry the install"
	elif grep -q '^sudo:' /etc/group ; then
	    fail "Please run    usermod -aG sudo $USER   as root, log out, log back in, and retry the install"
        else
	    fail "Please give this user the ability to run commands as root under sudo, log out, log back in, and retry the install"
	fi
    fi
}


tmp_dir () {
	mkdir -p "$HOME/tmp/"
	tdirname=`mktemp -d -q "$HOME/tmp/install-tools.XXXXXXXX" </dev/null`
	if [ ! -d "$tdirname" ]; then
		fail "Unable to create temporary directory."
	fi
	echo "$tdirname"
}


patch_system() {
	#Make sure all currently installed packages are updated.  This has the added benefit
	#that we update the package metadata for later installing new packages.

	if [ -x /usr/bin/apt-get -a -x /usr/bin/dpkg-query ]; then
		while ! $SUDO sudo add-apt-repository universe ; do
			echo "Error subscribing to universe repository, perhaps because a system update is running; will wait 60 seconds and try again." >&2
			sleep 60
		done
		while ! $SUDO apt-get -q -y update >/dev/null ; do
			echo "Error updating package metadata, perhaps because a system update is running; will wait 60 seconds and try again." >&2
			sleep 60
		done
		while ! $SUDO apt-get -q -y upgrade >/dev/null ; do
			echo "Error updating packages, perhaps because a system update is running; will wait 60 seconds and try again." >&2
			sleep 60
		done
			while ! $SUDO apt-get -q -y install lsb-release >/dev/null ; do
				echo "Error installing lsb-release, perhaps because a system update is running; will wait 60 seconds and try again." >&2
				sleep 60
			done
	elif [ -x /usr/bin/yum -a -x /bin/rpm ]; then
		$SUDO yum -q -e 0 makecache
		$SUDO yum -y -q -e 0 -y install deltarpm
		$SUDO yum -q -e 0 -y update
		$SUDO yum -y -q -e 0 -y install redhat-lsb-core yum-utils
		if [ -s /etc/redhat-release -a -s /etc/os-release ]; then
			. /etc/os-release
			if [ "$VERSION_ID" = "7" ]; then
				$SUDO yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
				if [ ! -e /etc/centos-release ]; then
					$SUDO yum -y install subscription-manager
					$SUDO subscription-manager repos --enable "rhel-*-optional-rpms" --enable "rhel-*-extras-rpms"  --enable "rhel-ha-for-rhel-*-server-rpms"
				fi
			elif [ "$VERSION_ID" = "8" ]; then
				$SUDO yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
				if [ -e /etc/centos-release ]; then
					$SUDO dnf config-manager --set-enabled powertools
				else
					$SUDO yum -y install subscription-manager
					$SUDO subscription-manager repos --enable "codeready-builder-for-rhel-8-`/bin/arch`-rpms"
				fi
			fi
		fi
		$SUDO yum -q -e 0 makecache
	fi
}


install_tool() {
	#Install a program.  $1 holds the name of the executable we need
	#$2 is one or more packages that can supply that executable (put preferred package names early in the list).


	binary="$1"
	echo "Installing package that contains $binary" >&2
	potential_packages="$2"

	if type -path "$binary" >/dev/null ; then
		echo "$binary executable is installed." >&2
	else
		if [ -x /usr/bin/apt-get -a -x /usr/bin/dpkg-query ]; then
			for one_package in $potential_packages ; do
				if ! type -path "$binary" >/dev/null ; then		#if a previous package was successfully able to install, don't try again.
					$SUDO apt-get -q -y install $one_package
				fi
			done
		elif [ -x /usr/bin/yum -a -x /bin/rpm ]; then
			#Yum takes care of the lock loop for us
			for one_package in $potential_packages ; do
				if ! type -path "$binary" >/dev/null ; then		#if a previous package was successfully able to install, don't try again.
					$SUDO yum -y -q -e 0 install $one_package
				fi
			done
		else
			fail "Neither (apt-get and dpkg-query) nor (yum, rpm, and yum-config-manager) is installed on the system"
		fi
	fi

	if type -path "$binary" >/dev/null ; then
		return 0
	else
		echo "WARNING: Unable to install $binary from a system package" >&2
		return 1
	fi
}

echo "install_tools version $install_tools_version" >&2

if [ -n "$1" ]; then
	if [ "$1" = "thunt" ]; then
		data_needed="thunt"
	elif [ "$1" = "packet-decode" ]; then
		data_needed="packet-decode"
	else
		echo "I do not recognize the command line parameter you specified - please put   thunt   or   packet-decode   as the sole command line parameter to say which data set you need installed.  Exiting."
		exit 1
	fi
fi

echo "Checking sudo" >&2
require_sudo

echo "Patching system" >&2
patch_system

install_tool realpath "coreutils realpath"
install_tool git "git"
install_tool make "make"
install_tool nc "netcat nc nmap-ncat"
install_tool wget "wget"
install_tool curl "curl"
install_tool ngrep "ngrep"
install_tool tcpdump "tcpdump"
install_tool tshark "tshark wireshark"
install_tool wireshark "wireshark"
install_tool datamash "datamash"
install_tool sha256sum "coreutils"
install_tool sshd "openssh-server"
install_tool hping3 "hping3"
install_tool ifconfig "net-tools"
install_tool pip3 "python3-pip"

if ! $SUDO pip3 install scapy ; then
	echo "We were not able to install scapy, skipping." >&2
fi

# #We need to install zeek through the rita installer in order to install both
# #install_tool zeek "zeek"
# #install_tool zeekctl "zeekctl"
#
# $SUDO setcap cap_net_raw,cap_net_admin+eip `which dumpcap`
#
# echo "Installing Zeek and RITA" >&2
# if ! type -path "zeek" >/dev/null || ! type -path "rita" >/dev/null ; then
# 	#Install zeek and rita by hand
#
# 	rita_install_dir=`tmp_dir`
# 	cd "$rita_install_dir"
# 	git clone https://github.com/activecm/rita.git
# 	cd rita
# 	$SUDO ./install.sh
#
# 	cd -
# fi
#
#
# #Try to add /opt/zeek/bin/ to path (though the better way is to log out and log back in)
# if ! echo "$PATH" | grep -q '/opt/zeek/bin' ; then
# 	echo "Adding Zeek to path" >&2
# 	#For this login only...
# 	export PATH="$PATH:/opt/zeek/bin/"
# 	#...and for future logins
# 	if [ -s /etc/profile.d/zeek-path.sh -o -s /etc/profile.d/zeek.sh ]; then
# 		:
# 	elif [ -s /etc/environment ]; then
# 		echo 'export PATH="$PATH:/opt/zeek/bin/"' | sudo tee -a /etc/environment >/dev/null
# 	elif [ -s /etc/profile ]; then
# 		echo 'export PATH="$PATH:/opt/zeek/bin/"' | sudo tee -a /etc/profile >/dev/null
# 	fi
#
# 	cd /usr/local/bin/
# 	if [ ! -e zeek ]; then
# 		if [ -x /opt/zeek/bin/zeek ]; then
# 			sudo ln -s /opt/zeek/bin/zeek zeek
# 		else
# 			echo "Warning: zeek does not appear to be installed." >&2
# 		fi
# 	fi
# 	if [ ! -e zeekctl ]; then
# 		if [ -x /opt/zeek/bin/zeekctl ]; then
# 			sudo ln -s /opt/zeek/bin/zeekctl zeekctl
# 		else
# 			echo "Warning: zeekctl does not appear to be installed." >&2
# 		fi
# 	fi
# 	cd - >/dev/null
# fi


if [ "$data_needed" = "thunt" ]; then
	if [ -s thunt-labs.tar.gz -a `sha256sum thunt-labs.tar.gz | awk '{print $1}'` = '6c2bc8cd9de66de01928e1fc79c22301082d75e566f4dfd3ca855d2651b6f816' -a -d lab1 -a -d lab2 -a -d lab3 -a -s lab1/conn.log -a -s lab2/conn.log -a -s lab3/conn.log ]; then
		echo "It appears all the lab data is in place, not downloading again." >&2
	else
		echo "Downloading sample data" >&2
		cd
		wget https://threat-huntiing.s3.amazonaws.com/thunt-labs.tar.gz
		if [ `sha256sum thunt-labs.tar.gz | awk '{print $1}'` = '6c2bc8cd9de66de01928e1fc79c22301082d75e566f4dfd3ca855d2651b6f816' ]; then
			echo "Download successful, opening sample data." >&2
			tar -xzf thunt-labs.tar.gz
			if [ $? -eq 0 -a -d lab1 -a -d lab2 -a -d lab3 -a -f lab1/conn.log -a -f lab2/conn.log -a -f lab3/conn.log ]; then
				echo "Sample data files are in the following directories $HOME/lab1 , $HOME/lab2 , and $HOME/lab3" >&2
				echo "Creating rita databases from the lab directories." >&2
				rita import "$HOME/lab1/" lab1
				rita import "$HOME/lab2/" lab2
				rita import "$HOME/lab3/" lab3
			else
				echo "It does not appear we were able to open the sample data files." >&2
			fi
		else
			echo "Downloaded sample data file does not appear to match the original.  Perhaps the download didn't succeed or was corrupted?" >&2
		fi
	fi
elif [ "$data_needed" = "packet-decode" ]; then
	if [ -s packet-decode-labs.tar.gz -a `sha256sum packet-decode-labs.tar.gz | awk '{print $1}'` = '8944d5bf0a3694666ac1d814721f505a203273d377de562401e5f3dbbcde5081' -a -d lab1 -a -d lab2 -a -s lab1/decode1.pcap -a -s lab2/ping-linux.pcap ]; then
		echo "It appears all the lab data is in place, not downloading again." >&2
	else
		echo "Downloading sample data" >&2
		cd
		wget https://random-class.s3.amazonaws.com/packet-decode-labs.tar.gz
		if [ `sha256sum packet-decode-labs.tar.gz | awk '{print $1}'` = '8944d5bf0a3694666ac1d814721f505a203273d377de562401e5f3dbbcde5081' ]; then
			echo "Download successful, opening sample data." >&2
			tar -xzf packet-decode-labs.tar.gz
			if [ $? -eq 0 -a -d lab1 -a -d lab2 -a -s lab1/decode1.pcap -a -s lab2/ping-linux.pcap ]; then
				echo "Sample data files are in the following directories $HOME/lab1 and $HOME/lab2" >&2
			else
				echo "It does not appear we were able to open the sample data files." >&2
			fi
		else
			echo "Downloaded sample data file does not appear to match the original.  Perhaps the download didn't succeed or was corrupted?" >&2
		fi
	fi
else
	echo 'I do not know what data files to download, skipping.' >&2
fi

echo "Unless you see warnings above that an install failed, you should have the needed tools and sample data installed." >&2
echo "You must log out and log back in to make sure that Zeek is in your PATH." >&2
if [ -d "$rita_install_dir" ]; then
	echo "You can safely remove the $rita_install_dir tree now." >&2
fi
