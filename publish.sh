#!/bin/bash

BASEDIR=$(cd $(dirname $0) && pwd)

# maybe run the build from here

sudo mv $BASEDIR/build/encrypt /usr/local/bin/encrypt

sudo mv $BASEDIR/build/decrypt /usr/local/bin/decrypt
