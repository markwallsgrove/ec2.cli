#!/usr/bin/env bash

if [[ $# -ne 3 ]]; then
    echo "usage: createRelease.sh [privateCert] [newexe] [oldexe]"
    exit 1;
fi

privateKey=$1
newexe=$2
oldexe=$3

if [[ ! -f $privateKey || ! -f $newexe || ! -f $oldexe ]]; then
    echo "cannot find file(s)"
    exit 1
fi

# TODO: more archiectures
if [[ ! $newexe =~ ^.+/[a-zA-Z0-9\.]+\-(darwin|linux)-amd64$ || ! $oldexe =~ ^.+/[a-zA-Z0-9\.]+\-(darwin|linux)-amd64$ ]]; then
    echo "invalid executable name(s)"
    exit 1
fi

IFS='-' read -ra newchunks <<< "$newexe"
IFS='-' read -ra oldchunks <<< "$oldexe"

os=${newchunks[1]}
arch=${newchunks[2]}
oldos=${oldchunks[1]}
oldarch=${oldchunks[2]}

if [[ "$os" != "$oldos" || "$arch" != "$oldarch" ]]; then
    echo "executables are not from the same arch/os"
    exit 1
fi

rm -rf release 2>/dev/null
mkdir release

shasum -a 256 $newexe | awk '{print $1}' > release/f-$os-$arch.hash
bsdiff $oldexe $newexe release/f-$os-$arch.diff
openssl dgst -sha256 -sign $privateKey $newexe > release/f-$os-$arch.sig

shasum -a 256 $oldexe | awk '{print $1}' > release/b-$os-$arch.hash
bsdiff $newexe $oldexe release/b-$os-$arch.diff
openssl dgst -sha256 -sign $privateKey $oldexe > release/b-$os-$arch.sig
