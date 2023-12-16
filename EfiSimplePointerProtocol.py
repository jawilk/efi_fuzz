#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *

EFI_SIMPLE_POINTER_PROTOCOL         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_SIMPLE_POINTER_GET_STATE         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_EVENT         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_SIMPLE_POINTER_MODE         =         FUNCPTR(EFI_STATUS, PTR(VOID));

class EFI_SIMPLE_POINTER_PROTOCOL(STRUCT):
	_fields_ = [
	('Reset', EFI_SIMPLE_POINTER_PROTOCOL),
	('GetState', EFI_SIMPLE_POINTER_GET_STATE),
	('WaitForInput', EFI_EVENT),
	('Mode', EFI_SIMPLE_POINTER_MODE)
	]
	
@dxeapi(params = {
	"AllocSize": UINTN,
	"Alignment": UINTN,
	"Pool": PTR(VOID)
})
def hook_DummyHook(ql, address, params):
    print("EFI_SIMPLE_POINTER_PROTOCOL hook_DummyHook")
    return EFI_SUCCESS 

descriptor = {
    "guid" : "31878c87-0b75-11d5-9a4f-0090273fc14d",
    "struct" : EFI_SIMPLE_POINTER_PROTOCOL,
    "fields" : (
	('Reset', hook_DummyHook),
	('GetState', hook_DummyHook),
	('WaitForInput', hook_DummyHook),
	('Mode', hook_DummyHook)
    )
    }
