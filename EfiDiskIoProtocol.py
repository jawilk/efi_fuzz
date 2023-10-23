#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *

EFI_DISK_READ         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_DISK_WRITE         =         FUNCPTR(EFI_STATUS, PTR(VOID));


class EFI_DISK_IO_PROTOCOL(STRUCT):
	_fields_ = [
	('Revision', UINT64),
	('ReadDisk', EFI_DISK_READ),
	('WriteDisk', EFI_DISK_WRITE),
	]
	
@dxeapi(params = {
	"AllocSize": UINTN,
	"Alignment": UINTN,
	"Pool": PTR(VOID)
})
def hook_DummyHook(ql, address, params):
    print("**************** hook_DummyHook EFI_DISK_IO_PROTOCOL")
    return EFI_SUCCESS 
    
@dxeapi(params = {
	"This": PTR(VOID),
	"MediaId": UINT32,
	"Offset": UINT64,
	"BufferSize": UINTN,
        "Buffer": PTR(VOID)
})
def hook_ReadDisk(ql, address, params):
    print("**************** hook_ReadDisk EFI_DISK_IO_PROTOCOL")
    ql.mem.write(params["Buffer"], ql.env["FUZZ_DATA"][params["Offset"]:params["Offset"]+params["BufferSize"]])
    return EFI_SUCCESS 

descriptor = {
    "guid" : "ce345171-ba0b-11d2-8e4f-00a0c969723b",
    "struct" : EFI_DISK_IO_PROTOCOL,
    "fields" : (
	('Revision', hook_DummyHook),
	('ReadDisk', hook_ReadDisk),
	('WriteDisk', hook_DummyHook),
    )
    }
