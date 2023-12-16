import uefi_firmware
import pickle

def extract_nvram_variables(rom_file, output_file):
    firmware = uefi_firmware.parse_file(rom_file)
    variables = {}

    for variable in firmware.nvram_variables:
        name = variable.name
        value = variable.value
        variables[name] = value

    with open(output_file, 'wb') as file:
        pickle.dump(variables, file)

# Usage
rom_file = 'lenovo_sec_disabled_21_06_23_exit_boot_hook_fat_open_READ.rom'
output_file = 'nvram_variables.pickle'
extract_nvram_variables(rom_file, output_file)