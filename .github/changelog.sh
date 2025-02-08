#!/bin/sh
#
# This is a hack to palliate the fact that cargo-release runs the pre-release
# hook once for each crate, instead of only once for the whole workspace.
# Calling git-cliff multiple times with the same argument is idempotent, so we
# call it with settings generating the workspace-level changelog once for every
# crate.
git-cliff -o $WORKSPACE_ROOT/CHANGELOG.md --tag $NEW_VERSION -w $WORKSPACE_ROOT
echo $NEW_VERSION > $WORKSPACE_ROOT/VERSION
