#!/bin/sh
set -e
#set -x

# remove old symlink setup
rm -rf adium-frameworks

# create empty directory to keep linker happy
mkdir adium-frameworks

# if Adium is built as sub-project -> skip
if [[ ( -d "${BUILT_PRODUCTS_DIR}/Adium.framework" )          ||
      ( -d "${BUILT_PRODUCTS_DIR}/AdiumLibPurple.framework" ) ||
      ( -d "${BUILT_PRODUCTS_DIR}/AIUtilities.framework" ) ]]; then
	echo 1>&2 "Building Adium within SIPEAdiumPlugin - aborting..."
	exit 0
fi

_sipe_build_dir=$(cd "${BUILT_PRODUCTS_DIR}/../../.."; pwd -P)
if [[ ! -d "${_sipe_build_dir}" ]]; then
	echo 1>&2 "can't detect SIPE build directory from '${BUILT_PRODUCTS_DIR}'"
	exit 1
fi

_build_dir=$(cd "${_sipe_build_dir}/.."; pwd -P)
if [[ ! -d "${_build_dir}" ]]; then
	echo 1>&2 "can't detect common build directory from '${_sipe_build_dir}'"
	exit 1
fi

_adium_build_dir=( $(find "${_build_dir}" -maxdepth 1 -type d -name "Adium-*" ) )
if [[ ${#_adium_build_dir[@]} -ne 1 ]]; then
	echo 1>&2 "can't detect Adium build directory from '${_build_dir}'"
	exit 1
fi

# create symlinks to Adium frameworks
_frameworks_dir="${BUILT_PRODUCTS_DIR/#${_sipe_build_dir}/${_adium_build_dir[0]}}"
_adium_dirs=(
	Adium.framework
	AdiumLibPurple.framework
	AIUtilities.framework
)
ln -s ${_adium_dirs[@]/#/${_frameworks_dir}/} adium-frameworks/

# log result
ls -lhtR adium-frameworks
exit 0
