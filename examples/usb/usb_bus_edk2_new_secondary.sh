#!/bin/bash

afl-fuzz -D -p explore -T UsbBusEdk2New -t 4000 -i ../../afl_inputs_usb -o afl_outputs_bus_edk2_new -S fuzzer0$1 -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbBusDxe_EDK2_NEW_noinline.efi -v nvram.pickle -v ../../nvram.pickle fat @@
