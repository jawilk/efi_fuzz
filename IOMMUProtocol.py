#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *


IOMMU_SET_ATTRIBUTE = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID), PTR(VOID), UINT64)
IOMMU_MAP = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID), PTR(VOID), UINTN, PTR(VOID), PTR(VOID))
IOMMU_UNMAP = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID))
IOMMU_ALLOCATE_BUFFER = FUNCPTR(EFI_STATUS, UINTN, PTR(VOID), UINT64)
IOMMU_FREE_BUFFER = FUNCPTR(EFI_STATUS, PTR(VOID), UINTN, PTR(VOID))

class IOMMU_PROTOCOL(STRUCT):
	_fields_ = [
	        ('Revision', UINT64),
	        ('SetAttribute', IOMMU_SET_ATTRIBUTE),
	        ('Map', IOMMU_MAP),
	        ('Unmap', IOMMU_UNMAP),
	        ('AllocateBuffer', IOMMU_ALLOCATE_BUFFER),
	        ('FreeBuffer', IOMMU_FREE_BUFFER)
	]
	
@dxeapi(params = {
	"UsbIo" : PTR(VOID),
	"Request": PTR(VOID),
	"Direction": PTR(VOID), 
	"Timeout": UINT32,
	"Data": PTR(VOID),
	"DataLength": UINT16,
	"Status": PTR(EFI_STATUS)
})
def hook_AllocateBuffer(ql, address, params):
    print("**************** IOMMU hook_AllocateBuffer")
    print(params)
    return EFI_SUCCESS
	

descriptor = {
    "guid" : "4e939de9-d948-4b0f-88ed-e6e1ce517c1e",
    "struct" : IOMMU_PROTOCOL,
    "fields" : (
	    ('Revision', hook_AllocateBuffer),
	    ('SetAttribute', hook_AllocateBuffer),
	    ('Map', hook_AllocateBuffer),
	    ('Unmap', hook_AllocateBuffer),
	    ('AllocateBuffer', hook_AllocateBuffer),
	    ('FreeBuffer', hook_AllocateBuffer)
    )
    }
