#### Create dummy fat image
```
~: dd if=/dev/zero of=dummy_fat.img bs=1M count=64
~: mkfs.fat -F32 dummy_fat.img
```
#### Extract fat meta data only
The [FatDriverBindingStart](https://github.com/tianocore/edk2/blob/69abcf1e78b67e7ce9ac53a9fe1ce61877df984c/FatPkg/EnhancedFatDxe/Fat.c#L357) function has only 3 invocations to DiskIo read with the following params:  
* offset: 0x0, size: 0x5a    
* offset: 0x4004, size: 0x4    
* offset: 0x200, size: 0x200  

So we will only use the first `1kb` of the generated `dummy_fat.img` as fuzzing input (`extract_fat_meta_data.py`).

#### Start
```
~: ./fat_run.sh
```
Might need additional flags like `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`

#### Misc
The buffers passed to DiskIo (e.g. [FatBs](https://github.com/tianocore/edk2/blob/69abcf1e78b67e7ce9ac53a9fe1ce61877df984c/FatPkg/EnhancedFatDxe/Init.c#L204)) are are all stored on the stack without any initialization.  
While we cannot read any stack data itself from the usb, it might be possible to use parsed data from previous usb enumeration runs. E.g.: First the firmware is parsing the original boot disk, then our usb, we might be able to skip some stages and let it use the meta data/data from the original boot disk that is still on the stack.  
We could apply some stack tainting between two runs to verify if this is possible.
