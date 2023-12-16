import os
import subprocess

image = 'modules/UsbBusDxe_EDK2_NEW_noinline.efi'

# Folder containing input files
folder_path = 'compute-afl/usb-bus-EDK2-new/queue'

# Python script to run
script_path = '../../efi_fuzz.py'

coverage_path = 'compute-afl/usb-bus-EDK2-new/coverage/'

# Get a list of all files in the folder
files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))] 
# Iterate through the list of files and run the Python script with each file as an argument
for i, file in enumerate(files):
    file_path = os.path.join(folder_path, file)
    
    # Use subprocess to run the Python script with the file as an argument
    subprocess.run(['python3', script_path, 'run', image, '--coverage-file', coverage_path+'cov_'+str(i)+'.log', '-v', '../../nvram.pickle', '-a', file_path, 'fat', 'Setup'])

