#!/bin/bash

rm -rf afl_outputs_usb
afl-fuzz -T UsbDriver -D -p explore -i ../../afl_inputs_usb -o afl_outputs_usb -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbMouseDxe_EDK2.efi -v nvram.pickle -v ../../nvram.pickle fat @@
