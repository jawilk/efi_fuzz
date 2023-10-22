#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *


EFI_PCI_IO_PROTOCOL_POLL_IO_MEM = FUNCPTR(EFI_STATUS)
class EFI_PCI_IO_PROTOCOL_ACCESS(STRUCT):
    _fields_ = [
      ('Read', EFI_PCI_IO_PROTOCOL_POLL_IO_MEM),
      ('Write', EFI_PCI_IO_PROTOCOL_POLL_IO_MEM)
  ]	
EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS = FUNCPTR(EFI_STATUS)
EFI_PCI_IO_PROTOCOL_COPY_MEM = FUNCPTR(EFI_STATUS)
EFI_PCI_IO_PROTOCOL_MAP = FUNCPTR(EFI_STATUS)
EFI_PCI_IO_PROTOCOL_UNMAP = FUNCPTR(EFI_STATUS)
EFI_PCI_IO_PROTOCOL_ALLOCATE_BUFFER = FUNCPTR(EFI_STATUS)
EFI_PCI_IO_PROTOCOL_FREE_BUFFER = FUNCPTR(EFI_STATUS)
EFI_PCI_IO_PROTOCOL_FLUSH = FUNCPTR(EFI_STATUS)
EFI_PCI_IO_PROTOCOL_GET_LOCATION = FUNCPTR(EFI_STATUS)
EFI_PCI_IO_PROTOCOL_ATTRIBUTES = FUNCPTR(EFI_STATUS)
EFI_PCI_IO_PROTOCOL_GET_BAR_ATTRIBUTES = FUNCPTR(EFI_STATUS)
EFI_PCI_IO_PROTOCOL_SET_BAR_ATTRIBUTES = FUNCPTR(EFI_STATUS)

class EFI_PCI_IO_PROTOCOL(STRUCT):
	_fields_ = [
  ('PollMem', EFI_PCI_IO_PROTOCOL_POLL_IO_MEM),
  ('PollIo', EFI_PCI_IO_PROTOCOL_POLL_IO_MEM),
  ('Mem', EFI_PCI_IO_PROTOCOL_ACCESS),
  ('Io', EFI_PCI_IO_PROTOCOL_ACCESS),
  ('Pci', EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS),
  ('CopyMem', EFI_PCI_IO_PROTOCOL_COPY_MEM),
  ('Map', EFI_PCI_IO_PROTOCOL_MAP),
  ('Unmap', EFI_PCI_IO_PROTOCOL_UNMAP),
  ('AllocateBuffer', EFI_PCI_IO_PROTOCOL_ALLOCATE_BUFFER),
  ('FreeBuffer', EFI_PCI_IO_PROTOCOL_FREE_BUFFER),
  ('Flush', EFI_PCI_IO_PROTOCOL_FLUSH),
  ('GetLocation', EFI_PCI_IO_PROTOCOL_GET_LOCATION),
  ('Attributes', EFI_PCI_IO_PROTOCOL_ATTRIBUTES),
  ('GetBarAttributes', EFI_PCI_IO_PROTOCOL_GET_BAR_ATTRIBUTES),
  ('SetBarAttributes', EFI_PCI_IO_PROTOCOL_SET_BAR_ATTRIBUTES),
   # UINT64                                    RomSize;
   # VOID    *RomImage;
	]
	
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_PollMem(ql, address, params):
    print("EFI_PCI_IO_PROTOCOL hook_PollMem")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_PollIo(ql, address, params):
    print("EFI_PCI_IO_PROTOCOL hook_PollIo")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"Read" : EFI_PCI_IO_PROTOCOL_POLL_IO_MEM,
	"Write": EFI_PCI_IO_PROTOCOL_POLL_IO_MEM
})
def hook_Mem(ql, address, params):
    print("EFI_PCI_IO_PROTOCOL hook_Mem")
    return EFI_SUCCESS
	
@dxeapi(params = {
	"Read" : EFI_PCI_IO_PROTOCOL_POLL_IO_MEM,
	"Write": EFI_PCI_IO_PROTOCOL_POLL_IO_MEM
})
def hook_Io(ql, address, params):
    print("EFI_PCI_IO_PROTOCOL hook_Io")
    return EFI_SUCCESS
	
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_Pci(ql, address, params):
    print("EFI_PCI_IO_PROTOCOL hook_Pci")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_CopyMem(ql, address, params):
    print("EFI_PCI_IO_PROTOCOL hook_CopyMem")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_Map(ql, address, params):
    print("EFI_PCI_IO_PROTOCOL hook_Map")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_Unmap(ql, address, params):
    print("EFI_PCI_IO_PROTOCOL hook_Unmap")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"This" : PTR(VOID),
	"SegmentNumber" : UINTN,
	"BusNumber" : UINTN,
	"DeviceNumber" : UINTN,
	"FunctionNumber" : UINTN,
})
def hook_GetLocation(ql, address, params):
    print("EFI_PCI_IO_PROTOCOL hook_GetLocation")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_DummyHook(ql, address, params):
    print("EFI_PCI_IO_PROTOCOL hook_DummyHook")
    return EFI_SUCCESS
    

descriptor = {
    "struct" : EFI_PCI_IO_PROTOCOL_ACCESS,
    "fields" : (
  ('PollMem', hook_PollMem),
  ('PollIo', hook_PollIo),
    )
    }
    
a = EFI_PCI_IO_PROTOCOL_ACCESS()

descriptor = {
    "guid" : "4cf5b200-68b8-4ca5-9eec-b23e3f50029a",
    "struct" : EFI_PCI_IO_PROTOCOL,
    "fields" : (
  ('PollMem', hook_PollMem),
  ('PollIo', hook_PollIo),
  ('Mem', a),
  ('Io', a),
  ('Pci', hook_Pci),
  ('CopyMem', hook_CopyMem),
  ('Map', hook_Map),
  ('Unmap', hook_Unmap),
  ('AllocateBuffer', hook_DummyHook),
  ('FreeBuffer', hook_DummyHook),
  ('Flush', hook_DummyHook),
  ('GetLocation', hook_GetLocation),
  ('Attributes', hook_DummyHook),
  ('GetBarAttributes', hook_DummyHook),
  ('SetBarAttributes', hook_DummyHook),
    )
    }
