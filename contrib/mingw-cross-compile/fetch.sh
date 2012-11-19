#!/bin/bash
#
# Based on:
#
#   http://code.google.com/p/pidgin-privacy-please/wiki/HowToCrossCompileForWindowsAgainstLatestPidgin
#
# Check this page for latest MinGW/Pidgin URLs if you get fetch errors!
#
# update Pidgin version here
export PIDGIN_VERSION=2.10.6

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
#wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/binutils-2.20/binutils-2.20-1-mingw32-bin.tar.gz
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/mingw-rt/mingwrt-3.17/mingwrt-3.17-mingw32-dev.tar.gz
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/mingw-rt/mingwrt-3.17/mingwrt-3.17-mingw32-dll.tar.gz
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/w32api/w32api-3.14/w32api-3.14-mingw32-dev.tar.gz
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/gcc/Version4/Previous%20Release%20gcc-4.4.0/gmp-4.2.4-mingw32-dll.tar.gz
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/libiconv/libiconv-1.13.1-1/libiconv-1.13.1-1-mingw32-dll-2.tar.lzma
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/gcc/Version4/Previous%20Release%20gcc-4.4.0/mpfr-2.4.1-mingw32-dll.tar.gz
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/gcc/Version4/Previous%20Release%20gcc-4.4.0/pthreads-w32-2.8.0-mingw32-dll.tar.gz
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/gcc/Version4/Previous%20Release%20gcc-4.4.0/gcc-core-4.4.0-mingw32-bin.tar.gz
wget -nv http://sourceforge.net/projects/mingw/files/MinGW/Base/gcc/Version4/Previous%20Release%20gcc-4.4.0/gcc-core-4.4.0-mingw32-dll.tar.gz

echo 1>&2 unpacking mingw...
cd ${MINGW_DIR}
for file in ${SOURCES_DIR}/*tar.gz ; do tar xzf ${file} ; done
tar xf ${SOURCES_DIR}/libiconv-1.13.1-1-mingw32-dll-2.tar.lzma

echo 1>&2 fetching pidgin dev stuff...
cd ${SOURCES_DIR}
wget -nv http://ftp.gnome.org/pub/gnome/binaries/win32/gtk+/2.14/gtk+-bundle_2.14.7-20090119_win32.zip
wget -nv http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/gettext-tools-0.17.zip
wget -nv http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/gettext-runtime-0.17-1.zip
wget -nv http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/libxml2-dev_2.7.4-1_win32.zip
wget -nv http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/libxml2_2.7.4-1_win32.zip
wget -nv http://developer.pidgin.im/static/win32/tcl-8.4.5.tar.gz
wget -nv http://developer.pidgin.im/static/win32/gtkspell-2.0.16.tar.bz2
wget -nv http://developer.pidgin.im/static/win32/enchant_1.6.0_win32.zip
wget -nv http://developer.pidgin.im/static/win32/nss-3.12.5-nspr-4.8.2.tar.gz
wget -nv http://developer.pidgin.im/static/win32/silc-toolkit-1.1.8.tar.gz
wget -nv http://developer.pidgin.im/static/win32/meanwhile-1.0.2_daa2-win32.zip
wget -nv http://developer.pidgin.im/static/win32/cyrus-sasl-2.1.22-daa1.zip
wget -nv http://ftp.acc.umu.se/pub/GNOME/binaries/win32/intltool/0.40/intltool_0.40.4-1_win32.zip
wget -nv http://prdownloads.sourceforge.net/pidgin/pidgin-${PIDGIN_VERSION}.tar.bz2

echo 1>&2 unpacking pidgin dev stuff...
unzip ${SOURCES_DIR}/gtk+-bundle_2.14.7-20090119_win32.zip -d ${DEV_DIR}/gtk_2_0-2.14
unzip ${SOURCES_DIR}/gettext-tools-0.17.zip -d ${DEV_DIR}/gettext-0.17
unzip ${SOURCES_DIR}/gettext-runtime-0.17-1.zip -d ${DEV_DIR}/gettext-0.17
unzip ${SOURCES_DIR}/libxml2-dev_2.7.4-1_win32.zip -d ${DEV_DIR}/libxml2-2.7.4
unzip ${SOURCES_DIR}/libxml2_2.7.4-1_win32.zip -d ${DEV_DIR}/libxml2-2.7.4
unzip ${SOURCES_DIR}/enchant_1.6.0_win32.zip -d ${DEV_DIR}/enchant_1.6.0_win32
unzip ${SOURCES_DIR}/meanwhile-1.0.2_daa2-win32.zip -d ${DEV_DIR}
unzip ${SOURCES_DIR}/cyrus-sasl-2.1.22-daa1.zip -d ${DEV_DIR}
unzip ${SOURCES_DIR}/intltool_0.40.4-1_win32.zip -d ${DEV_DIR}/intltool_0.40.4-1_win32

cd ${DEV_DIR}
tar xzf ${SOURCES_DIR}/tcl-8.4.5.tar.gz
tar xjf ${SOURCES_DIR}/gtkspell-2.0.16.tar.bz2
tar xzf ${SOURCES_DIR}/nss-3.12.5-nspr-4.8.2.tar.gz
tar xzf ${SOURCES_DIR}/silc-toolkit-1.1.8.tar.gz

cd ${PIDGIN_DEV_ROOT}
tar xjf ${SOURCES_DIR}/pidgin-${PIDGIN_VERSION}.tar.bz2

echo 1>&2 done
