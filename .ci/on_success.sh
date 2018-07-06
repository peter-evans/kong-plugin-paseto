#!/bin/bash
set -e

(cd $KONG_DOWNLOAD; luacov-coveralls)
