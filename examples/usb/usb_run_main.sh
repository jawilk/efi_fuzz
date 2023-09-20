#!/bin/bash

rm -rf afl_outputs_fat_meta
afl-fuzz -T UsbDriver -D -p explore -i ../../afl_inputs_fat_meta -o afl_outputs_fat_meta -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbBusDxe_BUG.efi -v nvram.pickle -v ../../nvram.pickle fat @@
