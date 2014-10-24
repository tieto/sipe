#!/bin/bash
#
# Compare release contents with golden list to ensure release correctness
#
if [[ -z "$1" ]]; then
    echo 1>&2 "usage: $0 <SIPEAdiumPlugin zip file>"
    exit 1
fi

# examine release archive
echo "Checking release archive '$1'..."
files=$(set -o pipefail; unzip -l "$1" |
    grep SIPEAdiumPlugin.AdiumLibpurplePlugin/ |
    awk '{ print $4, $1 }' |
    grep -v '/ 0')
if [[ $? -ne 0 ]]; then
    echo 1>&2 "ERROR: can't analyze release archive '$1'!"
    exit 1
fi

# the following files *MUST* be in the release archive
declare -A golden_list
golden_list=(
    [SIPEAdiumPlugin.AdiumLibpurplePlugin/Contents/Info.plist]=1
    [SIPEAdiumPlugin.AdiumLibpurplePlugin/Contents/MacOS/SIPEAdiumPlugin]=1
    [SIPEAdiumPlugin.AdiumLibpurplePlugin/Contents/Resources/English.lproj/DCPurpleSIPEJoinChatView.nib]=1
    [SIPEAdiumPlugin.AdiumLibpurplePlugin/Contents/Resources/English.lproj/InfoPlist.strings]=1
    [SIPEAdiumPlugin.AdiumLibpurplePlugin/Contents/Resources/ESSIPEAccountView.nib]=1
    [SIPEAdiumPlugin.AdiumLibpurplePlugin/Contents/Resources/PurpleDefaultsSIPE.plist]=1
    [SIPEAdiumPlugin.AdiumLibpurplePlugin/Contents/Resources/sipe.png]=1
)
new_files=()

# compare against golden list
# @TODO: is there a better way to feed in file list?
while read file size; do
    if [[ -z "${golden_list[${file}]}" ]]; then
        new_files+=( $file )
    elif [[ "${size}" -eq 0 ]]; then
        echo 1>&2 "ERROR: file '${file}' is empty!"
    else
        unset golden_list[${file}]
    fi
done <<EOF
${files[@]}
EOF

# check for errors
status=0
if [[ -n "${new_files[@]}" ]]; then
    echo 1>&2 "Release archive contains superfluous files:"
    for file in "${new_files[@]}"; do
        echo -e 1>&2 "\t${file}"
    done
    status=1
fi
if [[ ${#golden_list[@]} -ne 0 ]]; then
    echo 1>&2 "Release archive is missing the following files:"
    for file in "${!golden_list[@]}"; do
        echo -e 1>&2 "\t${file}"
    done
    status=1
fi
if [[ $status -eq 0 ]]; then
    echo "Release archive is OK!"
else
    echo "Release archive is NOT OK!"
fi
exit $status
