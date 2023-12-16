#!/bin/bash

rm -rf afl_outputs_keyboard_insyde
afl-fuzz -T UsbMouseDriverInsyde -D -t 4000 -i ../../afl_inputs_usb -o afl_outputs_keyboard_insyde -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbKbDxe_body.efi -v nvram.pickle -v ../../nvram.pickle fat @@
