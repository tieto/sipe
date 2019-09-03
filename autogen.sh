#! /bin/sh
###############################################################################
# Generate GITVERSION
###############################################################################
_gitversion=$(git describe | grep -e -)
if [ -n "${_gitversion}" ]; then
	_gitversion=$(echo ${_gitversion} | cut -d- -f3 | sed 's/^g//')
	echo -n ${_gitversion} >GITVERSION
else
	rm -f GITVERSION
fi

###############################################################################
# Set up build from git tree
###############################################################################
set -e

# Set up initial NLS stuff...
autopoint --force

# ...now replace "autopoint" with "intltoolize" in full setup run
AUTOPOINT="intltoolize --copy --force --automake" \
	 autoreconf --force --install
