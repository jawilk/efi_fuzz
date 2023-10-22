#!/bin/bash

afl-fuzz -D -p explore -T UsbBusEdk2Bug -t 4000 -i ../../afl_inputs_usb -o afl_outputs_bus_edk2_bug -S fuzzer0$1 -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbBusDxe_BUG_noinline_4.efi -v nvram.pickle -v ../../nvram.pickle fat @@
