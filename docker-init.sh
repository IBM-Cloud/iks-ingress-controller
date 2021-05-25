#!/bin/bash -xe

# After new docker version install the cli version stay old so we should work around this. 
rm -rf /usr/local/bin/docker
ln -s /usr/bin/docker /usr/local/bin/docker
usermod -aG docker ${TRAVIS_USER} 