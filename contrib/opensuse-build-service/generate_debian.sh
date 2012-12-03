#!/bin/bash
abort() {
    echo "$0: $1 - Aborting"
    exit 1
}
cleanup() {
    rm -rf debian
    abort "$1"
}

# Sanity checks
version=$(ls pidgin-sipe-*.tar.gz | sed 's/^pidgin-sipe-//;s/.tar.gz$//')
[ -z "${version}" ] && abort "can't find pidgin-sipe archive"
[ -e debian ]       && abort "directory 'debian' - already exists"

# Setup temporary directory
mkdir debian || cleanup "can't generate temporary directory"
for f in \
    changelog \
    control \
    rules; \
do \
    mv debian.${f} debian/${f} || cleanup "can't copy Debian file ${f}"; \
done

# Create debian archive
tar cfz pidgin-sipe_${version}-1.debian.tar.gz debian || cleanup "can't create tar archive"
rm -rf debian

# Copy latest source archive
cp pidgin-sipe-${version}.tar.gz pidgin-sipe_${version}.orig.tar.gz

# Update .dsc files
for p in \
    "Checksums-Sha1=sha1sum" \
    "Checksums-Sha256=sha256sum" \
    "Files=md5sum";
do \
    label=${p%=*}; \
    program=${p#*=}; \
    echo "${label}:"
    for t in \
	pidgin-sipe_${version}.orig.tar.gz \
	pidgin-sipe_${version}-1.debian.tar.gz; \
    do \
	echo " $(${program} ${t} | cut -d' ' -f1) $(wc -c ${t})"; \
    done \
done >checksums.txt
for d in *.dsc; do cat checksums.txt >>${d}; done
rm checksums.txt

# That's all folks...
echo "Done."
osc status
exit 0
