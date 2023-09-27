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
		('UsbControlTransfer', EFI_USB2_HC_PROTOCOL_GET_CAPABILITY),
		('UsbBulkTransfer',	EFI_USB2_HC_PROTOCOL_RESET),
		('UsbAsyncInterruptTransfer', EFI_USB2_HC_PROTOCOL_GET_STATE),
		('UsbSyncInterruptTransfer', EFI_USB2_HC_PROTOCOL_SET_STATE),
		('UsbIsochronousTransfer', EFI_USB2_HC_PROTOCOL_BULK_TRANSFER),
		('UsbAsyncIsochronousTransfer',	EFI_USB2_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER),
		('UsbGetDeviceDescriptor', EFI_USB2_HC_PROTOCOL_SYNC_INTERRUPT_TRANSFER),
		('UsbGetConfigDescriptor', EFI_USB2_HC_PROTOCOL_ISOCHRONOUS_TRANSFER),
		('UsbGetInterfaceDescriptor', EFI_USB2_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER),
		('UsbGetEndpointDescriptor', EFI_USB2_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS),
		('UsbGetStringDescriptor', EFI_USB2_HC_PROTOCOL_SET_ROOTHUB_PORT_FEATURE),
		('UsbGetSupportedLanguages', EFI_USB2_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE),
        ('MajorRevision', UINT16),
		('MinorRevision', UINT16)
	]
	
@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbControlTransfer(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})

def hook_UsbBulkTransfer(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})

def hook_UsbAsyncInterruptTransfer(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbSyncInterruptTransfer(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbIsochronousTransfer(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbAsyncIsochronousTransfer(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbGetDeviceDescriptor(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbGetConfigDescriptor(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbGetInterfaceDescriptor(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbGetEndpointDescriptor(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbGetStringDescriptor(ql, address, params):
	pass

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbGetSupportedLanguages(ql, address, params):
	pass


@dxeapi(params = {
	"SkuId" : UINT
})
def hook_UsbAsyncTransferCallback(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber" : UINT
})
def hook_UsbAsyncInterruptTransfer(ql, address, params):
	pass

descriptor = {
	"guid" : "3e745226-9818-45b6-a2ac-d7cd0e8ba2bc",
	"struct" : USB2_HC_PROTOCOL,
	"fields" : (
		('UsbControlTransfer', hook_UsbControlTransfer),
		('UsbBulkTransfer', hook_UsbBulkTransfer),
		('UsbAsyncInterruptTransfer', hook_UsbAsyncInterruptTransfer),
		('UsbSyncInterruptTransfer', hook_UsbSyncInterruptTransfer),
		('UsbIsochronousTransfer', hook_UsbIsochronousTransfer),
		('UsbAsyncIsochronousTransfer', hook_UsbAsyncIsochronousTransfer),
		('UsbGetDeviceDescriptor', hook_UsbGetDeviceDescriptor),
		('UsbGetConfigDescriptor', hook_UsbGetConfigDescriptor),
		('UsbGetInterfaceDescriptor', hook_UsbGetInterfaceDescriptor),
		('UsbGetEndpointDescriptor', hook_UsbGetEndpointDescriptor),
		('UsbGetStringDescriptor', hook_UsbGetStringDescriptor),
        ('UsbGetSupportedLanguages', hook_UsbGetSupportedLanguages),
	)
}
