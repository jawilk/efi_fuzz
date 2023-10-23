#!/bin/bash

afl-fuzz -i ../../afl_inputs_fat_meta -o afl_outputs_fat_meta -t 40000 -S fuzzer0$1 -U -- \
python3 ../../efi_fuzz.py fuzz modules/Fat_noinline.efi -v nvram.pickle --extra-modules modules/EnglishDxe.efi -v ../../nvram.pickle fat @@