#!/usr/bin/env bash
set -e

echo "### Move/update v<MAJOR> tag ###"
MAJOR_VERSION=$( echo ${GITHUB_REF#refs/tags/v} | cut -d "." -f 1 )
TAG_MSG=.github/utils/major_version_tag_msg.txt
sed -i "s|MAJOR|${MAJOR_VERSION}|g" "${TAG_MSG}"

git tag -af -F "${TAG_MSG}" v${MAJOR_VERSION}
