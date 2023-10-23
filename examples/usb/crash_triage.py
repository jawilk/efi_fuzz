import os
import subprocess

image = 'modules/UsbBusDxe_EDK2_NEW_noinline.efi'

# Folder containing input files
folder_path = 'compute-afl/usb-bus-EDK2-new/crashes'

# Python script to run
script_path = '../../efi_fuzz.py'

# Get a list of all files in the folder
files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))] 
# Iterate through the list of files and run the Python script with each file as an argument
for file in files:
    file_path = os.path.join(folder_path, file)
    
    # Use subprocess to run the Python script with the file as an argument
    subprocess.run(['python3', script_path, 'run', image, '-v', '../../nvram.pickle', '-a', file_path, 'fat', 'Setup'])
