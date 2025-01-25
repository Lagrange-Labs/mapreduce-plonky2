#!/bin/sh
git-cliff -o $WORKSPACE_ROOT/CHANGELOG.md --tag $NEW_VERSION -w $WORKSPACE_ROOT
