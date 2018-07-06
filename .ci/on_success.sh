#!/bin/bash
set -e

export INCLUDE_DIR=`echo $TRAVIS_BUILD_DIR | sed 's/-/%-/g'`

(cd $KONG_DOWNLOAD; luacov-coveralls --include $INCLUDE_DIR)
