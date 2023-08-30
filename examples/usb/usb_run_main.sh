#!/bin/bash

rm -rf afl_outputs_fat_meta
afl-fuzz -f -i ../../afl_inputs_fat_meta -o afl_outputs_fat_meta -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbKbDxe_body.efi -v nvram.pickle -v ../../nvram.pickle fat @@