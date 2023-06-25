#!/bin/bash

rm -rf afl_outputs_fat_meta
afl-fuzz -i ../../afl_inputs_fat_meta -o afl_outputs_fat_meta -U -- \
python3 ../../efi_fuzz.py fuzz modules/FatDxeNew.efi -v nvram.pickle --extra-modules modules/EnglishDxe.efi modules/FakeController.efi -v ../../nvram.pickle fat @@