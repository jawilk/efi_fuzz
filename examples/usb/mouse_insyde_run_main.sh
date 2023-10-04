#!/bin/bash

rm -rf afl_outputs_mouse_insyde
afl-fuzz -T UsbMouseDriverInsyde -D -p explore -i ../../afl_inputs_usb -o afl_outputs_mouse_insyde -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbMouseDxe_body.efi -v nvram.pickle -v ../../nvram.pickle fat @@
