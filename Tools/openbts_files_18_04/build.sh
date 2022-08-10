#!/bin/bash
#
# Copyright 2014-2016 Range Networks, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# See the COPYING file in the main directory for details.
#

source $(dirname $0)/common.source

usage () {
	echo "# usage: ./build.sh.sh radio-type (component-name)"
	echo "# valid radio types are: SDR1, USRP1, B100, B110, B200, B210, N200, N210"
	echo "# (optional) valid component names are: libcoredumper, liba53, subscriberRegistry, smqueue, openbts, asterisk, asterisk-config, system-config"
	exit 1
}

installIfMissing () {
	dpkg -s $@ > /dev/null
	if [ $? -ne 0 ]; then
		echo "# - missing $@, installing dependency"
		sudo apt-get install $@ -y
		if [ $? -ne 0 ]; then
			echo "# - ERROR : $@ package was unable to be installed"
			exit 1
		fi
	fi
}

RADIO=$1
MANUFACTURER=""
echo "# checking for a supported radio type"
if [ -z "$RADIO" ]; then
	echo "# - ERROR : radio type must be specified"
	usage
elif [ "$RADIO" == "SDR1" ] || [ "$RADIO" == "RAD1" ]; then
	RADIO="SDR1"
	MANUFACTURER="Range"
	EXTRA_CONFIGURE_FLAGS=""
elif [ "$RADIO" == "USRP1" ]; then
	MANUFACTURER="Ettus"
	EXTRA_CONFIGURE_FLAGS="--with-usrp1"
elif [ "$RADIO" == "B100" ] || [ "$RADIO" == "B110" ] || [ "$RADIO" == "B200" ] || [ "$RADIO" == "B210" ] || [ "$RADIO" == "N200" ] || [ "$RADIO" == "N210" ]; then
	MANUFACTURER="Ettus"
	EXTRA_CONFIGURE_FLAGS="--with-uhd"
fi
export EXTRA_CONFIGURE_FLAGS

if [ -z "$MANUFACTURER" ]; then
	echo "# - ERROR : invalid radio target ($RADIO)"
	usage
else
	echo "# - found"
fi

COMPONENT="all"
if [ ! -z "$2" ]; then
	COMPONENT="$2"
	echo "# single component specified"
	if [ "$COMPONENT" == "libcoredumper" ] || [ "$COMPONENT" == "liba53" ]; then
		echo "# - found, building and installing $COMPONENT"
	elif [ "$COMPONENT" == "subscriberRegistry" ] || [ "$COMPONENT" == "smqueue" ] || [ "$COMPONENT" == "openbts" ] || [ "$COMPONENT" == "asterisk" ] || [ "$COMPONENT" == "asterisk-config" ] || [ "$COMPONENT" == "system-config" ]; then
		echo "# - found, building $COMPONENT"
	else
		echo "# - ERROR : invalid component ($COMPONENT)"
		usage
	fi
fi

echo "# checking for a compatible build host"
if hash lsb_release 2>/dev/null; then
	ubuntu=`lsb_release -r -s`
	if [ $ubuntu != "16.04" ]; then
		echo "# - WARNING : dev-tools is currently only tested on Ubuntu 16.04, YMMV. Please open an issue if you've used it successfully on another version of Ubuntu."
	else
		echo "# - fully supported host detected: Ubuntu 16.04"
	fi
else
	echo "# - ERROR : Sorry, dev-tools currently only supports Ubuntu as the host OS. Please open an issue for your desired host."
	echo "# - exiting"
	exit 1
fi
echo "#"

echo "# adding additional repo tools"
installIfMissing software-properties-common
#installIfMissing python-software-properties
echo "# - done"
echo

echo "# checking build dependencies"
installIfMissing autoconf
installIfMissing automake
installIfMissing libtool
installIfMissing debhelper
installIfMissing sqlite3
installIfMissing libsqlite3-dev
installIfMissing libusb-1.0-0
installIfMissing libusb-1.0-0-dev
installIfMissing libortp-dev
installIfMissing libortp9
installIfMissing libosip2-dev
installIfMissing libreadline-dev
installIfMissing libncurses5
installIfMissing libncurses5-dev
installIfMissing pkg-config
# libsqliteodbc deps
installIfMissing cdbs
installIfMissing libsqlite0-dev
# asterisk deps
installIfMissing unixodbc
installIfMissing unixodbc-dev
installIfMissing libssl-dev
installIfMissing libsrtp0
installIfMissing libsrtp0-dev
installIfMissing libsqliteodbc
installIfMissing uuid-dev
installIfMissing libjansson-dev
installIfMissing libxml2-dev
# zmq
installIfMissing libzmq3-dev
installIfMissing libzmq5
installIfMissing python-zmq
if [ "$MANUFACTURER" == "Ettus" ]; then
	installIfMissing libuhd-dev
	installIfMissing libuhd003*
	installIfMissing uhd-host
fi
echo "# - done"
echo

BUILDNAME="BUILDS/`date +"%Y-%m-%d--%H-%M-%S"`"
echo "# make a home for this build"
sayAndDo mkdir -p $BUILDNAME

if [ "$COMPONENT" == "all" ] || [ "$COMPONENT" == "libcoredumper" ]; then
	echo "# libcoredumper - building Debian package and installing as dependency"
	sayAndDo cd libcoredumper
	#sayAndDo ./build.sh
	#sayAndDo mv libcoredumper* ../$BUILDNAME
	sayAndDo cd ..
	#sayAndDo sudo dpkg -i $BUILDNAME/libcoredumper*.deb
	echo "# - done"
	echo
fi

if [ "$COMPONENT" == "all" ] || [ "$COMPONENT" == "liba53" ]; then
	echo "# liba53 - building Debian package and installing as dependency"
	sayAndDo cd liba53
	sayAndDo dpkg-buildpackage -us -uc
	sayAndDo cd ..
	sayAndDo mv liba53_* $BUILDNAME
	sayAndDo sudo dpkg -i $BUILDNAME/liba53_*.deb
	echo "# - done"
	echo
fi

if [ "$COMPONENT" == "all" ] || [ "$COMPONENT" == "subscriberRegistry" ]; then
	echo "# subscriberRegistry - building Debian package"
	sayAndDo cd subscriberRegistry
	sayAndDo dpkg-buildpackage -us -uc
	sayAndDo cd ..
	sayAndDo mv sipauthserve_* $BUILDNAME
	echo "# - done"
	echo
fi

if [ "$COMPONENT" == "all" ] || [ "$COMPONENT" == "smqueue" ]; then
	echo "# smqueue - building Debian package"
	sayAndDo cd smqueue
	sayAndDo dpkg-buildpackage -us -uc
	sayAndDo cd ..
	sayAndDo mv smqueue_* $BUILDNAME
	echo "# - done"
	echo
fi

if [ "$COMPONENT" == "all" ] || [ "$COMPONENT" == "openbts" ]; then
	echo "# openbts - building Debian package"
	sayAndDo cd openbts
	sayAndDo dpkg-buildpackage -us -uc
	sayAndDo cd ..
	sayAndDo mv openbts_* $BUILDNAME
	echo "# - done"
	echo
fi

if [ "$COMPONENT" == "all" ] || [ "$COMPONENT" == "asterisk" ]; then
	echo "# asterisk - building Debian package"
	#sayAndDo cd asterisk
	#rm -rf range-asterisk* asterisk-*
	#sayAndDo ./build.sh
	#sayAndDo mv range-asterisk_* ../$BUILDNAME
	#sayAndDo cd ..
	echo "# - done"
	echo
fi

if [ "$COMPONENT" == "all" ] || [ "$COMPONENT" == "asterisk-config" ]; then
	echo "# asterisk-config - building Debian package"
	sayAndDo cd asterisk-config
	sayAndDo dpkg-buildpackage -us -uc
	sayAndDo cd ..
	sayAndDo mv range-asterisk-config_* $BUILDNAME
	echo "# - done"
	echo
fi

if [ "$COMPONENT" == "all" ] || [ "$COMPONENT" == "system-config" ]; then
	echo "# system-config - building Debian package"
	sayAndDo cd system-config
	sayAndDo dpkg-buildpackage -us -uc
	sayAndDo cd ..
	sayAndDo mv range-configs_* $BUILDNAME
	echo "# - done"
	echo
fi
