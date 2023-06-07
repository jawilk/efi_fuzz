#!/bin/bash

rm -rf afl_outputs_fat_meta
afl-fuzz -i ../../afl_inputs_fat_meta -o afl_outputs_fat_meta -U -- \
python3 ../../efi_fuzz.py fuzz /home/wj/temp/uefi/image/FatDxeNew.efi -v nvram.pickle --extra-modules /home/wj/temp/uefi/file-system-modules/EnglishDxe.efi /home/wj/temp/uefi/file-system-modules/FakeController.efi -v ../../nvram.pickle fat @@