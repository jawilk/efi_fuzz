#!/bin/bash

rm -rf afl_outputs_bus_edk2_new
afl-fuzz -T UsbBusEdk2New -D -t 4000 -i ../../afl_inputs_usb -o afl_outputs_bus_edk2_new -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbBusDxe_EDK2_NEW_noinline.efi -v nvram.pickle -v ../../nvram.pickle fat @@
