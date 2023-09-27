#!/bin/bash

rm -rf afl_outputs_usb_kb
afl-fuzz -T UsbDriver -D -p explore -i ../../afl_inputs_usb -o afl_outputs_usb_kb -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbKbDxe_EDK2.efi -v nvram.pickle -v ../../nvram.pickle fat @@
