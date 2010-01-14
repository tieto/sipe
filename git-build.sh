#!/bin/sh
#
# Convenience to (re-)build pidgin-sipe from git repository.
#
# Example: add configure parameters
#
#  $ ./git-build.sh --with-krb5
#
# Example: setup debug build, e.g. for valgrind ((ba)sh style)
#
#  $ CFLAGS="-g -O0" ./git-build.sh
#
# Sanity check
if [ ! -x autogen.sh ]; then
    echo 1>&2 "Your pidgin-sipe repository seems to be broken..."
    exit 1
fi

# Check for previous build artifacts
rm -f build.log
if [ -r Makefile ]; then
    echo "Cleaning up previous build artifacts..."
    echo >build.log "------ Cleanup ------"
    make >>build.log 2>&1 -k maintainer-clean
fi

# Rebuild
(
    set -e
    echo "Generating configure script..."
    echo >>build.log "------ Generate Configure Script ------"
    ./autogen.sh >>build.log 2>&1
    echo -n "Configuring build with"
    if [ $# -eq 0  ]; then
	echo "out any options..."
    else
	echo " '$@'..."
    fi
    echo >>build.log "------ Configure ------"
    ./configure >>build.log 2>&1 "$@"
    echo "Running build..."
    echo >>build.log "------ Build ------"
    make >>build.log 2>&1
)
if [ $? -eq 0 ]; then
    echo >>build.log "------ SUCCESS ------"
    echo "Congratulations: the build was successful!"
else
    echo >>build.log "------ FAILED ------"
    echo 1>&2 "Build FAILED!"
fi
echo "Details can be found in 'build.log'."
