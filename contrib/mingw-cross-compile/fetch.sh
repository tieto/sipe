#!/bin/bash
#
# Based on:
#
#   http://code.google.com/p/pidgin-privacy-please/wiki/HowToCrossCompileForWindowsAgainstLatestPidgin
#
# Latest Windows Pidgin build instractions:
#
#   https://developer.pidgin.im/wiki/BuildingWinPidgin
#
# Check these page for latest MinGW/Pidgin URLs if you get fetch errors!
#
# update Pidgin version here
export PIDGIN_VERSION=2.10.11

# must be absolute path
export PIDGIN_DEV_ROOT=$(pwd -P)/build-${PIDGIN_VERSION}
export SOURCES_DIR=${PIDGIN_DEV_ROOT}/sources/
export DEV_DIR=${PIDGIN_DEV_ROOT}/win32-dev
export MINGW_DIR=${DEV_DIR}/mingw
export PIDGIN_DIR=${PIDGIN_DEV_ROOT}/pidgin-${PIDGIN_VERSION}

exec >fetch-${PIDGIN_VERSION}.log
set -e

echo 1>&2 create directory tree...
rm -rf ${PIDGIN_DEV_ROOT}
mkdir -p ${SOURCES_DIR}
mkdir -p ${MINGW_DIR}

echo 1>&2 fetching mingw...
cd ${SOURCES_DIR}
#wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/binutils/binutils-2.23.1/binutils-2.23.1-1-mingw32-bin.tar.lzma
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/mingw-rt/mingwrt-3.20/mingwrt-3.20-2-mingw32-dev.tar.lzma
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/mingw-rt/mingwrt-3.20/mingwrt-3.20-2-mingw32-dll.tar.lzma
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/w32api/w32api-3.17/w32api-3.17-2-mingw32-dev.tar.lzma
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/gmp/gmp-5.0.1-1/gmp-5.0.1-1-mingw32-dev.tar.lzma
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/libiconv/libiconv-1.14-2/libiconv-1.14-2-mingw32-dev.tar.lzma
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/mpfr/mpfr-2.4.1-1/mpfr-2.4.1-1-mingw32-dev.tar.lzma
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/pthreads-w32/pthreads-w32-2.9.0-pre-20110507-2/pthreads-w32-2.9.0-mingw32-pre-20110507-2-dev.tar.lzma
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/gcc/Version4/gcc-4.7.2-1/gcc-core-4.7.2-1-mingw32-bin.tar.lzma
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/gcc/Version4/gcc-4.7.2-1/libgcc-4.7.2-1-mingw32-dll-1.tar.lzma

echo 1>&2 unpacking mingw...
cd ${MINGW_DIR}
for file in ${SOURCES_DIR}/*tar.lzma ; do tar xf ${file} ; done

echo 1>&2 fetching pidgin dev stuff...
cd ${SOURCES_DIR}
wget -nv http://ftp.gnome.org/pub/gnome/binaries/win32/gtk+/2.14/gtk+-bundle_2.14.7-20090119_win32.zip
wget -nv http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/gettext-tools-0.17.zip
wget -nv http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/gettext-runtime-0.17-1.zip
wget -nv http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/libxml2-dev_2.9.0-1_win32.zip
wget -nv http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/libxml2_2.9.0-1_win32.zip
wget -nv https://developer.pidgin.im/static/win32/tcl-8.4.5.tar.gz
wget -nv https://developer.pidgin.im/static/win32/gtkspell-2.0.16.tar.bz2
wget -nv https://developer.pidgin.im/static/win32/enchant_1.6.0_win32.zip
wget -nv https://developer.pidgin.im/static/win32/nss-3.17.1-nspr-4.10.7.tar.gz
wget -nv https://developer.pidgin.im/static/win32/silc-toolkit-1.1.10.tar.gz
wget -nv https://developer.pidgin.im/static/win32/meanwhile-1.0.2_daa3-win32.zip
wget -nv https://developer.pidgin.im/static/win32/cyrus-sasl-2.1.25.tar.gz
wget -nv http://ftp.acc.umu.se/pub/GNOME/binaries/win32/intltool/0.40/intltool_0.40.4-1_win32.zip
wget -nv http://prdownloads.sourceforge.net/pidgin/pidgin-${PIDGIN_VERSION}.tar.bz2

echo 1>&2 unpacking pidgin dev stuff...
unzip ${SOURCES_DIR}/gtk+-bundle_2.14.7-20090119_win32.zip -d ${DEV_DIR}/gtk_2_0-2.14
unzip ${SOURCES_DIR}/gettext-tools-0.17.zip -d ${DEV_DIR}/gettext-0.17
unzip ${SOURCES_DIR}/gettext-runtime-0.17-1.zip -d ${DEV_DIR}/gettext-0.17
unzip ${SOURCES_DIR}/libxml2-dev_2.9.0-1_win32.zip -d ${DEV_DIR}/libxml2-2.9.0
unzip ${SOURCES_DIR}/libxml2_2.9.0-1_win32.zip -d ${DEV_DIR}/libxml2-2.9.0
unzip ${SOURCES_DIR}/enchant_1.6.0_win32.zip -d ${DEV_DIR}/enchant_1.6.0_win32
unzip ${SOURCES_DIR}/meanwhile-1.0.2_daa3-win32.zip -d ${DEV_DIR}
unzip ${SOURCES_DIR}/intltool_0.40.4-1_win32.zip -d ${DEV_DIR}/intltool_0.40.4-1_win32

cd ${DEV_DIR}
tar xzf ${SOURCES_DIR}/tcl-8.4.5.tar.gz
tar xjf ${SOURCES_DIR}/gtkspell-2.0.16.tar.bz2
tar xzf ${SOURCES_DIR}/nss-3.17.1-nspr-4.10.7.tar.gz
tar xzf ${SOURCES_DIR}/silc-toolkit-1.1.10.tar.gz
tar xzf ${SOURCES_DIR}/cyrus-sasl-2.1.25.tar.gz

cd ${PIDGIN_DEV_ROOT}
tar xjf ${SOURCES_DIR}/pidgin-${PIDGIN_VERSION}.tar.bz2

echo 1>&2 done
