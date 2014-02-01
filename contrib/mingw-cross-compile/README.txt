Introduction
============

With these instructions you will be able to generate libsipe.dll on a Linux
machine that is compatible with the official Pidgin Windows releases.

The approach described here is based on this wiki page:

   http://code.google.com/p/pidgin-privacy-please/wiki/HowToCrossCompileForWindowsAgainstLatestPidgin

The build has been verified to work at the time this text was written. When
you read this some things in Pidgin or MinGW might changed, so make sure to
check the comments on that wiki page for updates.


Preparation
===========

You'll need a Linux machine with the following MinGW cross-compilation
packages installed:

Ubuntu:
   sudo apt-get install mingw32 mingw32-binutils mingw32-runtime

Fedora:
   sudo yum install mingw32-gcc

This will most likely work also for other Linux distros, but you'll have
to check what names the MinGW cross-compilation packages are for your
distro.

If you are trying to build the source code from the git repository then
you'll need additional tools installed, at least:

   autoconf
   automake

If you want to build the NSIS installer package then you'll need to install:

   mingw32-nsis


Build
=====

 - [pidgin-sipe source code from git instead from a release tarball]
   run the following commands inside the git work area:

      ./autogen.sh
      ./configure
      make dist-gzip

   This will generate pidgin-sipe-<VERSION>.tar.gz

 - create an empty directory and cd into it

 - run contrib/mingw-cross-compile/fetch.sh from pidgin-sipe source
   * make sure to check for fetch & unpack errors before proceeding!

 - cd into build-<...REPLACE PIDGIN VERSION HERE...>/pidgin-<...REPLACE PIDGIN VERSION HERE...>

 - copy/unpack pidgin-sipe source code tree into into current directory

 - run

     cp pidgin-sipe-<...REPLACE PIDGIN-SIPE VERSION HERE...>/contrib/mingw-cross-compile/local.mak .

 - run (this is one line on the command line!)

     make -C pidgin-sipe-<...REPLACE PIDGIN-SIPE VERSION HERE...>/src/core
          -f Makefile.mingw

     (to compile without SSPI support add " USE_SSPI=" to the command line)

If everything goes well you should now have

  pidgin-sipe-<...REPLACE PIDGIN-SIPE VERSION HERE...>/src/core/libsipe.dll

which you can copy into your Pidgin Windows installation directory.

NOTE: PLEASE make sure that there is NO OTHER libsipe.dll in that installation
      or in your PATH!


NSIS Installer Package
======================

After you have successfully executed the build:

 - run (this is one line on the command line!)

     PIDGIN_TREE_TOP=.. make
          -C pidgin-sipe-<...REPLACE PIDGIN-SIPE VERSION HERE...>
          -f Makefile.mingw cross-compile-nsis

     (to compile without SSPI support add " USE_SSPI=" to the command line)

If everything goes well you should now have

  pidgin-sipe-<...REPLACE PIDGIN-SIPE VERSION HERE...>.exe

which you now can execute on your Windows machine.
