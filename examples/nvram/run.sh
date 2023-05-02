#!/bin/bash

rm -rf afl_outputs
afl-fuzz -i ../../afl_inputs -o afl_outputs -U -- \
python3 ../../efi_fuzz.py fuzz ../../../../temp/uefi/TcgPlatformSetupPolicy.efi -v ../../nvram.pickle nvram Setup @@