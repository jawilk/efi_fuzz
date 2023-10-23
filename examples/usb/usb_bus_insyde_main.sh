#!/bin/bash

rm -rf afl_outputs_bus_insyde
afl-fuzz -T UsbBusInsyde -D -t 4000 -i ../../afl_inputs_usb -o afl_outputs_bus_insyde -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbBusDxe_insyde.efi -v nvram.pickle -v ../../nvram.pickle fat @@
