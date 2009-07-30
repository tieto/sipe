#!/bin/sh
#
# Take a snapshot of the current pidgin-sipe git HEAD from the mob branch.
#
# You can specify the path to a local repository to speed up the cloning
# process. The output will be a bzip2 compressed tarball whose name includes
# the current date and the abbreviated commit object name of HEAD.
#
# Adapted from several examples found on the Internet.
#
# Configuration
PROJECT=pidgin-sipe
BRANCH=mob

# Create clone
set -e
TODAY=$(date +%Y%m%d)
CLONEDIR=${PROJECT}-${TODAY}
echo "Clone directory '$CLONEDIR'."
REFERENCE=${1:+--reference $1}
if [ -n "$1" ]; then
    echo "Using local repository under '$1'."
fi
rm -rf $CLONEDIR
git clone -n $REFERENCE git+ssh://mob@repo.or.cz/srv/git/siplcs.git $CLONEDIR
cd $CLONEDIR
git checkout -q -b $CLONEDIR origin/$BRANCH

# Create archive
COMMIT=$(git log -n 1 --abbrev-commit --pretty=oneline | cut -d' ' -f1| sed -e 's/\.//g')
PREFIX=${PROJECT}-${TODAY}git${COMMIT}
ARCHIVE=${PREFIX}.tar.bz2
echo "Creating archive '$ARCHIVE'..."
git archive --format=tar --prefix=$PREFIX/ HEAD | bzip2 >../${PREFIX}.tar.bz2

# Cleanup
echo "Cleanup..."
cd ..
rm -rf $CLONEDIR
echo "DONE."
