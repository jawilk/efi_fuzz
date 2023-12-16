#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *

import random


EFI_HII_DATABASE_NEW_PACK      = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_HII_DATABASE_REMOVE_PACK = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_HII_DATABASE_UPDATE_PACK = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_HII_DATABASE_LIST_PACKS = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_HII_DATABASE_EXPORT_PACKS = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_HII_DATABASE_REGISTER_NOTIFY = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_HII_DATABASE_UNREGISTER_NOTIFY = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_HII_FIND_KEYBOARD_LAYOUTS = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_HII_GET_KEYBOARD_LAYOUT = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_HII_SET_KEYBOARD_LAYOUT = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_HII_DATABASE_GET_PACK_HANDLE = FUNCPTR(EFI_STATUS, PTR(VOID));

class EFI_HII_DATABASE_PROTOCOL(STRUCT):
	_fields_ = [
	('NewPackageList', EFI_HII_DATABASE_NEW_PACK),
           ('RemovePackageList', EFI_HII_DATABASE_REMOVE_PACK),
           ('UpdatePackageList', EFI_HII_DATABASE_UPDATE_PACK),
            ('ListPackageLists', EFI_HII_DATABASE_LIST_PACKS),
          ('ExportPackageLists', EFI_HII_DATABASE_EXPORT_PACKS),
       ('RegisterPackageNotify', EFI_HII_DATABASE_REGISTER_NOTIFY),
     ('UnregisterPackageNotify', EFI_HII_DATABASE_UNREGISTER_NOTIFY),
          ('FindKeyboardLayouts', EFI_HII_FIND_KEYBOARD_LAYOUTS),
            ('GetKeyboardLayout', EFI_HII_GET_KEYBOARD_LAYOUT),
            ('SetKeyboardLayout', EFI_HII_SET_KEYBOARD_LAYOUT),
       ('GetPackageListHandle', EFI_HII_DATABASE_GET_PACK_HANDLE)
       ]
       
@dxeapi(params = {
	"This": PTR(VOID),
	"KeyGuid": UINTN,
	"KeyboardLayoutLength": UINT16,
	"KeyboardLayout": PTR(VOID)
})
def hook_GetKeyboardLayout(ql, address, params):
    print("EFI_HII_DATABASE_PROTOCOL hook_GetKeyboardLayout")
    rand = random.choice([EFI_SUCCESS, EFI_BUFFER_TOO_SMALL])
    return rand
    
@dxeapi(params = {
	"This": PTR(VOID),
	"KeyGuid": UINTN,
})
def hook_SetKeyboardLayout(ql, address, params):
    return EFI_SUCCESS  
    
@dxeapi(params = {
	"AllocSize": UINTN,
	"Alignment": UINTN,
	"Pool": PTR(VOID)
})
def hook_DummyHook(ql, address, params):
    return EFI_SUCCESS 
		
descriptor = {    "guid" : "ef9fc172-a1b2-4693-b327-6d32fc416042",
    "struct" : EFI_HII_DATABASE_PROTOCOL,
    "fields" : [
              ('NewPackageList', hook_DummyHook),
           ('RemovePackageList', hook_DummyHook),
           ('UpdatePackageList', hook_DummyHook),
            ('ListPackageLists', hook_DummyHook),
          ('ExportPackageLists', hook_DummyHook),
       ('RegisterPackageNotify', hook_DummyHook),
     ('UnregisterPackageNotify', hook_DummyHook),
          ('FindKeyboardLayouts', hook_DummyHook),
            ('GetKeyboardLayout', hook_GetKeyboardLayout),
            ('SetKeyboardLayout', hook_SetKeyboardLayout),
       ('GetPackageListHandle', hook_DummyHook)
]
    }
