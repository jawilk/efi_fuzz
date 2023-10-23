#!/bin/bash

rm -rf afl_outputs_fat_meta
afl-fuzz -T FatDriver -D -p explore -t 4000 -i ../../afl_inputs_fat_meta -o afl_outputs_fat_meta -M default -U -- \
python3 ../../efi_fuzz.py fuzz modules/Fat_noinline.efi -v nvram.pickle --extra-modules modules/EnglishDxe.efi -v ../../nvram.pickle fat @@