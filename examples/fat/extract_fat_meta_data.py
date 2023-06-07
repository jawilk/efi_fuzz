#import fs


#fat = fs.open_fs("fat://dummy_fat.img")

#print(fat)
#print(dir(fat))
#print(fat.getmeta())

#data = None

# Open the FAT image file in binary mode
with open("dummy_fat.img", "rb") as file_read:
    meta_data = file_read.read(1024)
    # Read the boot sector
    #boot_sector_data = file.read(512)  # Assuming the boot sector size is 512 bytes
    # print(boot_sector_data[450:].hex())
    with open("dummy_fat_1kb", "wb") as file_write:
        file_write.write(meta_data)
    # Convert the boot sector data to hexadecimal string
    #boot_sector_hex = boot_sector_data.hex()
    #print(boot_sector_hex)

    #data = file.read()

    # Print the boot sector
    # print(boot_sector_hex[82:])
#print(len(data) / (1024 * 1024))
#print(type(data))
