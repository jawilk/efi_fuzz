#!/bin/bash

afl-fuzz -i ../../afl_inputs_fat_meta -o afl_outputs_fat_meta -S fuzzer0$1 -U -- \
python3 ../../efi_fuzz.py fuzz modules/FatDxeNew.efi -v nvram.pickle --extra-modules modules/EnglishDxe.efi modules/FakeController.efi -v ../../nvram.pickle fat @@