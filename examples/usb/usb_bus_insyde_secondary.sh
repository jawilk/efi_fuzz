#!/bin/bash

afl-fuzz -D -p explore -T UsbBusInsyde -t 4000 -i ../../afl_inputs_usb -o afl_outputs_bus_insyde -S fuzzer0$1 -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbBusDxe_insyde.efi -v nvram.pickle -v ../../nvram.pickle fat @@
