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
EFI_USB_IO_CONTROL_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID), PTR(VOID), UINT32, PTR(VOID), UINTN, UINT32)

EFI_USB_IO_BULK_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID), UINTN, UINTN, UINT32)

EFI_USB_IO_ASYNC_INTERRUPT_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, BOOLEAN, UINTN, UINTN, EFI_ASYNC_USB_TRANSFER_CALLBACK, PTR(VOID))

EFI_USB_IO_SYNC_INTERRUPT_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID), UINTN, UINTN, UINT32)

EFI_USB_IO_ISOCHRONOUS_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID), UINTN, UINT32)

EFI_USB_IO_ASYNC_ISOCHRONOUS_TRANSFER = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID), UINTN, EFI_ASYNC_USB_TRANSFER_CALLBACK, PTR(VOID))

EFI_USB_IO_GET_DEVICE_DESCRIPTOR = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID))

EFI_USB_IO_GET_CONFIG_DESCRIPTOR = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID))

EFI_USB_IO_GET_INTERFACE_DESCRIPTOR = FUNCPTR(EFI_STATUS, PTR(VOID), PTR(VOID))

EFI_USB_IO_GET_ENDPOINT_DESCRIPTOR = FUNCPTR(EFI_STATUS, PTR(VOID), UINT8, PTR(VOID))

EFI_USB_IO_GET_STRING_DESCRIPTOR = FUNCPTR(EFI_STATUS, PTR(VOID), UINT16, UINT8, CHAR16)

EFI_USB_IO_GET_SUPPORTED_LANGUAGE = FUNCPTR(EFI_STATUS, PTR(VOID), UINT16, UINT16)


class USB_IO_PROTOCOL(STRUCT):
	_fields_ = [
		('UsbControlTransfer', EFI_USB_IO_CONTROL_TRANSFER),
		('UsbBulkTransfer',	EFI_USB_IO_BULK_TRANSFER),
		('UsbAsyncInterruptTransfer', EFI_USB_IO_ASYNC_INTERRUPT_TRANSFER),
		('UsbSyncInterruptTransfer', EFI_USB_IO_SYNC_INTERRUPT_TRANSFER),
		('UsbIsochronousTransfer', EFI_USB_IO_ISOCHRONOUS_TRANSFER),
		('UsbAsyncIsochronousTransfer',	EFI_USB_IO_ASYNC_ISOCHRONOUS_TRANSFER),
		('UsbGetDeviceDescriptor', EFI_USB_IO_GET_DEVICE_DESCRIPTOR),
		('UsbGetConfigDescriptor', EFI_USB_IO_GET_CONFIG_DESCRIPTOR),
		('UsbGetInterfaceDescriptor', EFI_USB_IO_GET_INTERFACE_DESCRIPTOR),
		('UsbGetEndpointDescriptor', EFI_USB_IO_GET_ENDPOINT_DESCRIPTOR),
		('UsbGetStringDescriptor', EFI_USB_IO_GET_STRING_DESCRIPTOR),
		('UsbGetSupportedLanguages', EFI_USB_IO_GET_SUPPORTED_LANGUAGE)
	]
	
class InterfaceDescriptor(STRUCT):
	_fields_ = [
		('Length', UINT8),
		('DescriptorType', UINT8),
		('InterfaceNumber', UINT8),
		('AlternateSetting', UINT8),
		('NumEndpoints', UINT8),
		('InterfaceClass', UINT8),
		('InterfaceSubClass', UINT8),
		('InterfaceProtocol', UINT8),
		('Interface', UINT8),
	]
	
class EndpointDescriptor(STRUCT):
	_fields_ = [
		('Length', UINT8),
		('DescriptorType', UINT8),
		('EndpointAddress', UINT8),
		('Attributes', UINT8),
		('MaxPacketSize', UINT16),
		('Interval', UINT8),
	]

def check_usb_meta_len(ql, length):
	diff = length - len(ql.env["USB_META"])
	if diff > 0:
		ql.env["USB_META"] = ql.env["USB_META"] + b'\x00' * diff
	
@dxeapi(params = {
	"UsbIo" : PTR(VOID),
	"Request": PTR(VOID),
	"Direction": PTR(VOID), 
	"Timeout": UINT32,
	"Data": PTR(VOID),
	"DataLength": UINT16,
	"Status": PTR(EFI_STATUS)
})
def hook_UsbControlTransfer(ql, address, params):
    print("**************** hook_UsbControlTransfer")
    print(params)
    random_bytes = bytes([random.randint(0, 255) for _ in range(params["DataLength"])])
    ql.mem.write(params["Data"], random_bytes)
    return EFI_SUCCESS
	    
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
	"UsbIo" : PTR(VOID),
	"ConfigDesc": PTR(VOID)
})
def hook_UsbGetConfigDescriptor(ql, address, params):
    #random_bytes = bytes([random.randint(0, 255) for _ in range(9)])
    # print(random_bytes[4])
    check_usb_meta_len(ql, 9)
    ql.mem.write(params["ConfigDesc"], ql.env["USB_META"][:9])
    print("TotalLength:", int.from_bytes(ql.env["USB_META"][:9][2:4], byteorder='little'))
    return EFI_SUCCESS

@dxeapi(params = {
	"UsbIo" : PTR(VOID),
	"InterfaceDescriptor": PTR(VOID)
})
def hook_UsbGetInterfaceDescriptor(ql, address, params):
    #interface_descriptor = InterfaceDescriptor()
    #ql.mem.write(address, ctypes.byref(interface_descriptor), ctypes.sizeof(interface_descriptor))
    #random_bytes = bytes([random.randint(3, 10) for _ in range(9)])
    # print(random_bytes[4])
    check_usb_meta_len(ql, 18)
    #a = ql.env["USB_META"][9:18]
    ql.mem.write(params["InterfaceDescriptor"], ql.env["USB_META"][9:18])
    return EFI_SUCCESS


@dxeapi(params = {
	"This" : PTR(VOID),
	"EndpointIndex": UINT8,
	"EndpointDescriptor": PTR(VOID)
})
def hook_UsbGetEndpointDescriptor(ql, address, params):
    #random_bytes = bytes([random.randint(0, 255) for _ in range(6)])
    #byte_array = bytearray([random.randint(0x00, 0xFF) for _ in range(6)])
    #byte_array[2] = 0x80
    #byte_array[3] = 0x03
    #random_bytes = bytes(byte_array)
    endpoint_index = 7 * params["EndpointIndex"]
    check_usb_meta_len(ql, 25 + endpoint_index)
    ql.mem.write(params["EndpointDescriptor"], ql.env["USB_META"][18+endpoint_index:25+endpoint_index])
    return EFI_SUCCESS

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
    "guid" : "2b2f68d6-0cd2-44cf-8e8b-bba20b1b5b75",
    "struct" : USB_IO_PROTOCOL,
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
