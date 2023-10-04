#!/bin/bash

afl-fuzz -D -p explore -i ../../afl_inputs_mouse_insyde -o afl_outputs_mouse_insyde -S fuzzer0$1 -U -- \
python3 ../../efi_fuzz.py fuzz modules/UsbMouseDxe_body.efi -v nvram.pickle -v ../../nvram.pickle fat @@
