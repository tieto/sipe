#! /bin/sh
set -e

# Set up initial NLS stuff...
autopoint --force

# ...now replace "autopoint" with "intltoolize" in full setup run
AUTOPOINT="intltoolize --copy --force --automake" \
	 autoreconf --force --install
