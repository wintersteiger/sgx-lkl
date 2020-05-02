#!/bin/bash

set -x

lsb_release -ds
modinfo intel_sgx
free -h
df -h
ps -aux | grep sgx-lkl-run-oe | grep -v grep 
