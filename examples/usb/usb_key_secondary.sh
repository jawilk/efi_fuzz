#!/bin/bash

afl-fuzz -D -p explore -i ../../afl_inputs_usb -o afl_outputs_usb_kb -S fuzzer0$1 -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbKbDxe_EDK2.efi -v nvram.pickle -v ../../nvram.pickle fat @@
