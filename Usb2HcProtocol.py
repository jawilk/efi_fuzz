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

# 1st arg return type, then func argument types
EFI_ASYNC_USB_TRANSFER_CALLBACK = FUNCPTR(EFI_STATUS, PTR(VOID), UINTN, PTR(VOID), UINT32)

### API
# Note 2nd arg VOID = EFI_USB_IO_PROTOCOL
EFI_USB2_HC_PROTOCOL_GET_CAPABILITY = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID), PTR(VOID), UINT32, PTR(VOID), UINTN, UINT32)

EFI_USB2_HC_PROTOCOL_RESET = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID), UINTN, UINTN, UINT32)

EFI_USB2_HC_PROTOCOL_GET_STATE = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, BOOLEAN, UINTN, UINTN, PTR(VOID), PTR(VOID))

EFI_USB2_HC_PROTOCOL_SET_STATE = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID), UINTN, UINTN, UINT32)

EFI_USB2_HC_PROTOCOL_CONTROL_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID), UINTN, UINT32)

EFI_USB2_HC_PROTOCOL_BULK_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID), UINTN, UINT32)

EFI_USB2_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID), UINTN, EFI_ASYNC_USB_TRANSFER_CALLBACK, PTR(VOID))

EFI_USB2_HC_PROTOCOL_SYNC_INTERRUPT_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID))

EFI_USB2_HC_PROTOCOL_ISOCHRONOUS_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID))
EFI_USB2_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID))

EFI_USB2_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID))

EFI_USB2_HC_PROTOCOL_SET_ROOTHUB_PORT_FEATURE = FUNCPTR(EFI_STATUS, PTR(VOID), UINT16, UINT8, CHAR16)
EFI_USB2_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE = FUNCPTR(EFI_STATUS, PTR(VOID), UINT16, UINT16)


class USB2_HC_PROTOCOL(STRUCT):
	_fields_ = [
		('GetCapability', EFI_USB2_HC_PROTOCOL_GET_CAPABILITY),
		('Reset',	EFI_USB2_HC_PROTOCOL_RESET),
		('GetState', EFI_USB2_HC_PROTOCOL_GET_STATE),
		('SetState', EFI_USB2_HC_PROTOCOL_SET_STATE),
		('ControlTransfer', EFI_USB2_HC_PROTOCOL_CONTROL_TRANSFER),
		('BulkTransfer',	EFI_USB2_HC_PROTOCOL_BULK_TRANSFER),
		('AsyncInterruptTransfer', EFI_USB2_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER),
		('SyncInterruptTransfer', EFI_USB2_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER),
		('IsochronousTransfer', EFI_USB2_HC_PROTOCOL_ISOCHRONOUS_TRANSFER),
		('AsyncIsochronousTransfer', EFI_USB2_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER),
		('GetRootHubPortStatus', EFI_USB2_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS),
		('SetRootHubPortFeature', EFI_USB2_HC_PROTOCOL_SET_ROOTHUB_PORT_FEATURE),
		('ClearRootHubPortFeature', EFI_USB2_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE),
               ('MajorRevision', UINT16),
		('MinorRevision', UINT16)
	]
	
def check_fuzz_data_len(ql, length):
	diff = length - len(ql.env["FUZZ_DATA"])
	if diff > 0:
		ql.env["FUZZ_DATA"] = ql.env["FUZZ_DATA"] + b'\x00' * diff

@dxeapi(params = {
	"This" : PTR(VOID),
	"MaxSpeed" : UINT8,
	"PortNumber" : UINT8,
	"Is64BitCapable" : UINT8,
})
def hook_GetCapability(ql, address, params):
    print("USB2_HC_PROTOCOL hook_GetCapability")
    max_speed = 0xcc
    print(hex(params["MaxSpeed"]))
    ql.mem.write(params["MaxSpeed"], max_speed.to_bytes(1, byteorder='little'))
    ql.mem.write(params["PortNumber"], b'\x01')#max_speed.to_bytes(8, byteorder='little'))
    ql.mem.write(params["Is64BitCapable"], b'\x01')#max_speed.to_bytes(8, byteorder='little'))
    return EFI_SUCCESS
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_Reset(ql, address, params):
    print("USB2_HC_PROTOCOL hook_Reset")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_GetState(ql, address, params):
    print("USB2_HC_PROTOCOL hook_GetState")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_SetState(ql, address, params):
    print("USB2_HC_PROTOCOL hook_SetState")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"This" : PTR(VOID),
	"DeviceAddress" : UINT8,
	"DeviceSpeed" : UINT8,
	"MaximumPacketLength" : UINTN,
	"Request" : PTR(VOID),
	"TransferDirection" : UINTN,
	"Data" : PTR(VOID),
	"DataLength" : PTR(UINTN),
	"TimeOut" : UINTN,
	"Translator" : PTR(VOID),
	"TransferResult" : UINT32,
})
def hook_ControlTransfer(ql, address, params):
    print("USB2_HC_PROTOCOL hook_ControlTransfer")
    #print(params)
    data = ql.mem.read(params["Request"], 8)
    print("data", data)
    length = ql.mem.read(params["DataLength"], 8)
    length = int.from_bytes(length, byteorder='little')
    print("length", length)
    if length > 1000:
        return EFI_SUCCESS
    check_fuzz_data_len(ql, length)
    #print("len", length)
    #random_bytes = bytes([random.randint(1, 10) for _ in range(length)])
    #print(random_bytes)
    print("RANDOMMMMM", ql.env["FUZZ_DATA"][:length])
    ql.mem.write(params["Data"], ql.env["FUZZ_DATA"][:length])
    return EFI_SUCCESS
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_BulkTransfer(ql, address, params):
    print("USB2_HC_PROTOCOL hook_BulkTransfer")
    return EFI_SUCCESS
   
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_AsyncInterruptTransfer(ql, address, params):
    print("USB2_HC_PROTOCOL hook_AsyncInterruptTransfer")
    return EFI_SUCCESS
   
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_SyncInterruptTransfer(ql, address, params):
    print("USB2_HC_PROTOCOL hook_SyncInterruptTransfer")
    return EFI_SUCCESS

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_IsochronousTransfer(ql, address, params):
    print("USB2_HC_PROTOCOL hook_IsochronousTransfer")
    return EFI_SUCCESS

@dxeapi(params = {
	"This" : PTR(VOID),
	"PortNumber" : UINT8,
	"PortStatus" : PTR(VOID),
})
def hook_GetRootHubPortStatus(ql, address, params):
    print("USB2_HC_PROTOCOL hook_GetRootHubPortStatus")
    status = 0x00100001
    ql.mem.write(params["PortStatus"], status.to_bytes(4, byteorder='little'))
    data = ql.mem.read(params["PortStatus"], 4)
    print("data", data)
    return EFI_SUCCESS

@dxeapi(params = {
	"This" : PTR(VOID),
	"PortNumber" : UINT8,
	"PortStatus" : PTR(VOID),
})
def hook_SetRootHubPortFeature(ql, address, params):
    print("USB2_HC_PROTOCOL hook_SetRootHubPortFeature")
    return EFI_SUCCESS    
    
@dxeapi(params = {
	"This" : PTR(VOID),
	"PortNumber" : UINT8,
	"PortStatus" : PTR(VOID),
})
def hook_ClearRootHubPortFeature(ql, address, params):
    print("USB2_HC_PROTOCOL hook_ClearRootHubPortFeature")
    return EFI_SUCCESS  
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_MajorRevision(ql, address, params):
    print("USB2_HC_PROTOCOL hook_MajorRevision")
    return EFI_SUCCESS

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_MinorRevision(ql, address, params):
    print("USB2_HC_PROTOCOL hook_MinorRevision")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_DummyHook(ql, address, params):
    print("USB2_HC_PROTOCOL hook_DummyHook")
    return EFI_SUCCESS

descriptor = {
	"guid" : "3e745226-9818-45b6-a2ac-d7cd0e8ba2bc",
	"struct" : USB2_HC_PROTOCOL,
	"fields" : (
		('GetCapability', hook_GetCapability),
		('Reset',	hook_Reset),
		('GetState', hook_GetState),
		('SetState', hook_SetState),
		('ControlTransfer', hook_ControlTransfer),
		('BulkTransfer',	hook_BulkTransfer),
		('AsyncInterruptTransfer', hook_AsyncInterruptTransfer),
		('SyncInterruptTransfer', hook_SyncInterruptTransfer),
		('IsochronousTransfer', hook_IsochronousTransfer),
		('AsyncIsochronousTransfer', hook_AsyncInterruptTransfer),
		('GetRootHubPortStatus', hook_GetRootHubPortStatus),
		('SetRootHubPortFeature', hook_SetRootHubPortFeature),
		('ClearRootHubPortFeature', hook_ClearRootHubPortFeature),
               ('MajorRevision', hook_MajorRevision),
		('MinorRevision', hook_MinorRevision)
	)
}
