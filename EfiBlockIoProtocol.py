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


class EFI_BLOCK_IO_PROTOCOL(STRUCT):
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
    return EFI_SUCCESS 
    
@dxeapi(params = {
	"This": PTR(VOID),
	"MediaId": UINTN,
	"Offset": PTR(VOID),
	"BufferSize": UINTN,
        "Buffer": PTR(VOID)
})
def hook_ReadDisk(ql, address, params):
    return EFI_SUCCESS 

descriptor = {
    "guid" : "964e5b21-6459-11d2-8e39-00a0c969723b",
    "struct" : EFI_BLOCK_IO_PROTOCOL,
    "fields" : (
	('Revision', hook_DummyHook),
	('ReadDisk', hook_DummyHook),
	('WriteDisk', hook_DummyHook),
    )
    }
