#!/bin/bash

rm -rf afl_outputs_bus_edk2_bug
afl-fuzz -T UsbBusEdk2Bug -D -t 4000 -i ../../afl_inputs_usb -o afl_outputs_bus_edk2_bug -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbBusDxe_BUG_noinline_4.efi -v nvram.pickle -v ../../nvram.pickle fat @@
