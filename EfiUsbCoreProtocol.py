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


EFI_USB_CORE_GET_DESCRIPTOR         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SET_DESCRIPTOR         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_DEV_INTERFACE      =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SET_DEV_INTERFACE      =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_DEV_CONFIGURATION  =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SET_DEV_CONFIGURATION  =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SET_DEV_FEATURE        =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_CLR_DEV_FEATURE        =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_DEV_STATUS         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_DEV_STRING         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_CLR_ENDPOINT_HALT      =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_HID_DESCRIPTOR     =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_REPORT_DESCRIPTOR  =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_PROTOCOL_REQUEST   =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SET_PROTOCOL_REQUEST   =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_IDLE_REQUEST       =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SET_IDLE_REQUEST       =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_REPORT_REQUEST     =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SET_REPORT_REQUEST     =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_ALLOCATE_BUFFER        =         FUNCPTR(EFI_STATUS, UINTN, UINTN, PTR(VOID));
EFI_USB_CORE_FREE_BUFFER            =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_MEMORY_MAPPING         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_MEMORY_UNMAPPING       =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_PCIIO_PCI_READ         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_PCIIO_PCI_WRITE        =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_PCIIO_MEM_READ         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_PCIIO_MEM_WRITE        =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_PCIIO_IO_READ          =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_PCIIO_IO_WRITE         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_IO_READ8               =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_IO_WRITE8              =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_IO_READ16              =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_IO_WRITE16             =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_IO_READ32              =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_IO_WRITE32             =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_BSWAP16                =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_BSWAP32                =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_STALL                  =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_CPU_SAVE_STATE         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_MODE               =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SET_MODE               =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SMI_REGISTER           =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SMI_UNREGISTER         =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_INSERT_KBC_KEYCODE     =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_KBC_TRAP_PROCESSOR     =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_LEGACY_SUPPORT_PROVIDER =    FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_INSERT_LEGACY_SUPPORT_PROVIDER =  FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_REMOVE_LEGACY_SUPPORT_PROVIDER = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_INSERT_PERIODIC_TIMER  =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_REMOVE_PERIODIC_TIMER  =         FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_INSERT_PERIODIC_TIMER_PROVIDER = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_REMOVE_PERIODIC_TIMER_PROVIDER = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_ENTER_CRITICAL_SECTION         = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_LEAVE_CRITICAL_SECTION         = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_DISPATCH_HC_CALLBACK           = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_REGISTER_USB_BINDING_PROTOCOL  = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_USB_DEVICES                = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_INSERT_USB_DEVICE              = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_REMOVE_USB_DEVICE              = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_CONNECT_USB_DEVICES            = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_DISCONNECT_USB_DEVICES         = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_REGISTER_NON_SMM_CALLBACK      = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_CHECK_IGNORED_DEVICE           = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_CHECK_DEVICE_DETACHED          = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_CPU_WBINVD                     = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_IS_KBC_EXIST                   = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_MODULE_REGISTRATION            = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_IS_IN_SMM                      = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_INSERT_ADDRESS_CONVERT_TABLE   = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_REMOVE_ADDRESS_CONVERT_TABLE   = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_ADDRESS_CONVERT                = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SCHEDULAR_CONNECTION           = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_IS_CSM_ENABLED                 = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_GET_SWSMI_PORT                 = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_REGISTER_LEGACYFREEHC_CALLBACK = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_UNREGISTER_LEGACYFREEHC_CALLBACK = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_SYNC_KBD_LED                   = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_REGISTER_HID_DESCRIPTOR        = FUNCPTR(EFI_STATUS, PTR(VOID));
EFI_USB_CORE_UNREGISTER_HID_DESCRIPTOR      = FUNCPTR(EFI_STATUS, PTR(VOID));

class EFI_USB_CORE_PROTOCOL(STRUCT):
	_fields_ = [
('UsbGetDescriptor', EFI_USB_CORE_GET_DESCRIPTOR),
('UsbSetDescriptor', EFI_USB_CORE_SET_DESCRIPTOR),
('UsbGetDeviceInterface', EFI_USB_CORE_GET_DEV_INTERFACE),
('UsbSetDeviceInterface', EFI_USB_CORE_SET_DEV_INTERFACE),
('UsbGetDeviceConfiguration', EFI_USB_CORE_GET_DEV_CONFIGURATION),
('UsbSetDeviceConfiguration', EFI_USB_CORE_SET_DEV_CONFIGURATION),
('UsbSetDeviceFeature', EFI_USB_CORE_SET_DEV_FEATURE),
('UsbClearDeviceFeature', EFI_USB_CORE_CLR_DEV_FEATURE),
('UsbGetDeviceStatus', EFI_USB_CORE_GET_DEV_STATUS),
('UsbGetString', EFI_USB_CORE_GET_DEV_STRING),
('UsbClearEndpointHalt', EFI_USB_CORE_CLR_ENDPOINT_HALT),
('UsbGetHidDescriptor', EFI_USB_CORE_GET_HID_DESCRIPTOR),
('UsbGetReportDescriptor', EFI_USB_CORE_GET_REPORT_DESCRIPTOR),
('UsbGetProtocolRequest', EFI_USB_CORE_GET_PROTOCOL_REQUEST),
('UsbSetProtocolRequest', EFI_USB_CORE_SET_PROTOCOL_REQUEST),
('UsbGetIdleRequest', EFI_USB_CORE_GET_IDLE_REQUEST),
('UsbSetIdleRequest', EFI_USB_CORE_SET_IDLE_REQUEST),
('UsbGetReportRequest', EFI_USB_CORE_GET_REPORT_REQUEST),
('UsbSetReportRequest', EFI_USB_CORE_SET_REPORT_REQUEST),
('AllocateBuffer', EFI_USB_CORE_ALLOCATE_BUFFER),
('FreeBuffer', EFI_USB_CORE_FREE_BUFFER),
('MemoryMapping', EFI_USB_CORE_MEMORY_MAPPING),
('MemoryUnmapping', EFI_USB_CORE_MEMORY_UNMAPPING),
('PciIoPciRead', EFI_USB_CORE_PCIIO_PCI_READ),
('PciIoPciWrite', EFI_USB_CORE_PCIIO_PCI_WRITE),
('PciIoMemRead', EFI_USB_CORE_PCIIO_MEM_READ),
('PciIoMemWrite', EFI_USB_CORE_PCIIO_MEM_WRITE),
('PciIoIoRead', EFI_USB_CORE_PCIIO_IO_READ),
('PciIoIoWrite', EFI_USB_CORE_PCIIO_IO_WRITE),
('IoRead8', EFI_USB_CORE_IO_READ8),
('IoWrite8', EFI_USB_CORE_IO_WRITE8),
('IoRead16', EFI_USB_CORE_IO_READ16),
('IoWrite16', EFI_USB_CORE_IO_WRITE16),
('IoRead32', EFI_USB_CORE_IO_READ32),
('IoWrite32', EFI_USB_CORE_IO_WRITE32),
('Bswap16', EFI_USB_CORE_BSWAP16),
('Bswap32', EFI_USB_CORE_BSWAP32),
('Stall', EFI_USB_CORE_STALL),
('CpuSaveState', EFI_USB_CORE_CPU_SAVE_STATE),
('GetMode', EFI_USB_CORE_GET_MODE),
('SetMode', EFI_USB_CORE_SET_MODE),
('UsbSmiRegister', EFI_USB_CORE_SMI_REGISTER),
('UsbSmiUnregister', EFI_USB_CORE_SMI_UNREGISTER),
('InsertKbcKeyCode', EFI_USB_CORE_INSERT_KBC_KEYCODE),
('KbcTrapProcessor', EFI_USB_CORE_KBC_TRAP_PROCESSOR),
('GetLegacySupportProvider', EFI_USB_CORE_GET_LEGACY_SUPPORT_PROVIDER),
('InsertLegacySupportProvider', EFI_USB_CORE_INSERT_LEGACY_SUPPORT_PROVIDER),
('RemoveLegacySupportProvider', EFI_USB_CORE_REMOVE_LEGACY_SUPPORT_PROVIDER),
('InsertPeriodicTimer', EFI_USB_CORE_INSERT_PERIODIC_TIMER),
('RemovePeriodicTimer', EFI_USB_CORE_REMOVE_PERIODIC_TIMER),
('InsertPeriodicTimerProvider', EFI_USB_CORE_INSERT_PERIODIC_TIMER_PROVIDER),
('RemovePeriodicTimerProvider', EFI_USB_CORE_REMOVE_PERIODIC_TIMER_PROVIDER),
('EnterCriticalSection', EFI_USB_CORE_ENTER_CRITICAL_SECTION),
('LeaveCriticalSection', EFI_USB_CORE_LEAVE_CRITICAL_SECTION),
('DispatchHcCallback', EFI_USB_CORE_DISPATCH_HC_CALLBACK),
('RegisterUsbBindingProtocol', EFI_USB_CORE_REGISTER_USB_BINDING_PROTOCOL),
('GetUsbDevices', EFI_USB_CORE_GET_USB_DEVICES),
('InsertUsbDevice', EFI_USB_CORE_INSERT_USB_DEVICE),
('RemoveUsbDevice', EFI_USB_CORE_REMOVE_USB_DEVICE),
('ConnectUsbDevices', EFI_USB_CORE_CONNECT_USB_DEVICES),
('DisconnectUsbDevices', EFI_USB_CORE_DISCONNECT_USB_DEVICES),
('RegisterNonSmmCallback', EFI_USB_CORE_REGISTER_NON_SMM_CALLBACK),
('CheckIgnoredDevice', EFI_USB_CORE_CHECK_IGNORED_DEVICE),
('CheckDeviceDetached', EFI_USB_CORE_CHECK_DEVICE_DETACHED),
('CpuWbinvd', EFI_USB_CORE_CPU_WBINVD),
('IsKbcExist', EFI_USB_CORE_IS_KBC_EXIST),
('ModuleRegistration', EFI_USB_CORE_MODULE_REGISTRATION),
('IsInSmm', EFI_USB_CORE_IS_IN_SMM),
('InsertAddressConvertTable', EFI_USB_CORE_INSERT_ADDRESS_CONVERT_TABLE),
('RemoveAddressConvertTable', EFI_USB_CORE_REMOVE_ADDRESS_CONVERT_TABLE),
('AddressConvert', EFI_USB_CORE_ADDRESS_CONVERT),
('SchedularConnection', EFI_USB_CORE_SCHEDULAR_CONNECTION),
('IsCsmEnabled', EFI_USB_CORE_IS_CSM_ENABLED),
('GetSwSmiPort', EFI_USB_CORE_GET_SWSMI_PORT),
('RegisterLegacyFreeHcCallback', EFI_USB_CORE_REGISTER_LEGACYFREEHC_CALLBACK),
('UnregisterLegacyFreeHcCallback', EFI_USB_CORE_UNREGISTER_LEGACYFREEHC_CALLBACK),
('SyncKbdLed', EFI_USB_CORE_SYNC_KBD_LED),
('RegisterHidDescriptor', EFI_USB_CORE_REGISTER_HID_DESCRIPTOR),
('UnregisterHidDescriptor', EFI_USB_CORE_UNREGISTER_HID_DESCRIPTOR)
	]
	
def check_fuzz_data_len(ql, length):
	diff = length - len(ql.env["FUZZ_DATA"])
	if diff > 0:
		ql.env["FUZZ_DATA"] = ql.env["FUZZ_DATA"] + b'\x00' * diff	
	
@dxeapi(params = {
	"AllocSize": UINTN,
	"Alignment": UINTN,
	"Pool": PTR(VOID)
})
def hook_AllocateBuffer(ql, address, params):
    print("**************** UsbCore hook_AllocateBuffer USB_CORE_PROTOCOL")
    print(params)
    print(hex(params["Pool"]))
    print(hex(params["AllocSize"]))    
    ptr = ql.os.heap.alloc(params['AllocSize'])
    print(hex(ptr))
    #pool = ql.mem.read(params["Pool"], 16)
    #pool = int.from_bytes(pool, 'little')
    #print("pool", hex(pool))
    ql.mem.write(params["Pool"], ptr.to_bytes(8, byteorder='little'))
    return EFI_SUCCESS

@dxeapi(params = {
	"AllocSize": UINTN,
	"Pool": PTR(VOID)
})
def hook_FreeBuffer(ql, address, params):
    print("**************** hook_FreeBuffer USB_CORE_PROTOCOL")
    print(params)
    ptr = ql.os.heap.free(params['Pool'])
    return EFI_SUCCESS

@dxeapi(params = {
	"AllocSize": UINTN,
	"Alignment": UINTN,
	"Pool": PTR(VOID)
})
def hook_UsbSmiRegister(ql, address, params):
    #print("**************** hook_UsbSmiRegister USB_CORE_PROTOCOL")
    return EFI_SUCCESS
	
@dxeapi(params = {
	"AllocSize": UINTN,
	"Alignment": UINTN,
	"Pool": PTR(VOID)
})
def hook_UsbSmiUnregister(ql, address, params):
    #print("**************** hook_UsbSmiUnregister USB_CORE_PROTOCOL")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"AllocSize": UINTN,
	"Alignment": UINTN,
	"Pool": PTR(VOID)
})
def hook_DummyHook(ql, address, params):
    print("**************** hook_DummyHook USB_CORE_PROTOCOL")
    return EFI_SUCCESS 
    
@dxeapi(params = {
	"AllocSize": UINTN,
	"Alignment": UINTN,
	"Pool": PTR(VOID)
})
def hook_PciIoIoRead(ql, address, params):
    #print("**************** hook_PciIoIoRead USB_CORE_PROTOCOL")
    return EFI_SUCCESS
    
@dxeapi(params = {
	"AllocSize": UINTN,
	"Alignment": UINTN,
	"Pool": PTR(VOID)
})
def hook_PciIoIoWrite(ql, address, params):
    #print("**************** hook_PciIoIoWrite USB_CORE_PROTOCOL")
    return EFI_SUCCESS     
	
@dxeapi(params = {
	"Mode": UINTN,
})
def hook_GetMode(ql, address, params):
    #print("**************** hook_GetMode USB_CORE_PROTOCOL")
    mode = 0x03
    ql.mem.write(params["Mode"], mode.to_bytes(8, byteorder='little'))
    return EFI_SUCCESS  
    
@dxeapi(params = {
	"UsbIo": PTR(VOID),
	"InterfaceNum": UINT8,
	"HidDescriptor": PTR(VOID)
})
def hook_UsbGetHidDescriptor(ql, address, params):
    #print("**************** hook_UsbGetHidDescriptor USB_CORE_PROTOCOL")
    check_fuzz_data_len(ql, 49)
    #data = ql.env["FUZZ_DATA"][40:49]
    #new_bytes = data[:6] + bytes([0x22]) + data[7:]
    ql.mem.write(params["HidDescriptor"], ql.env["FUZZ_DATA"][40:49])#new_bytes
    #random_bytes = bytes([random.randint(0, 255) for _ in range(9-1)])
    #ql.mem.write(params["HidDescriptor"], random_bytes)
    return EFI_SUCCESS 
 
@dxeapi(params = {
	"UsbIo": PTR(VOID),
	"InterfaceNum": UINT8,
	"DescriptorSize": UINT16,
	"DescriptorBuffer": UINT8
})
def hook_UsbGetReportDescriptor(ql, address, params):
    #print("**************** hook_UsbGetReportDescriptor USB_CORE_PROTOCOL")
    check_fuzz_data_len(ql, 50+params["DescriptorSize"])
    print(hex(params["DescriptorSize"]))
    #print(ql.env["FUZZ_DATA"][50:50+params["DescriptorSize"]])
    ql.mem.write(params["DescriptorBuffer"], ql.env["FUZZ_DATA"][50:50+params["DescriptorSize"]])
    #random_bytes = bytes([random.randint(0, 255) for _ in range(params["DescriptorSize"]-1)])
    #ql.mem.write(params["DescriptorBuffer"], random_bytes)#ql.env["FUZZ_DATA"
    return EFI_SUCCESS   
   
@dxeapi(params = {
	"UsbIo": PTR(VOID),
	"Interface": UINT8,
	"Protocol": UINT8
})
def hook_UsbGetProtocolRequest(ql, address, params):
    #print("**************** hook_UsbGetProtocolRequest USB_CORE_PROTOCOL")
    check_fuzz_data_len(ql, 65)
    ql.mem.write(params["Protocol"], ql.env["FUZZ_DATA"][65:66])
    return EFI_SUCCESS  
 

@dxeapi(params = {
	"UsbIo": PTR(VOID),
	"Interface": UINT8,
	"ReportId": UINT8,
	"ReportType": UINT8,
	"ReportLen": UINT16,
	"Report": UINT8
})
def hook_UsbSetReportRequest(ql, address, params):
    #print("**************** hook_UsbSetReportRequest USB_CORE_PROTOCOL")
    return EFI_SUCCESS    
    
@dxeapi(params = {
	"Timeout": UINTN
})
def hook_Stall(ql, address, params):
    #print("**************** hook_Stall USB_CORE_PROTOCOL")
    return EFI_SUCCESS 
  
@dxeapi(params = {
	"Timeout": UINTN
})
def hook_UsbSetIdleRequest(ql, address, params):
    print("**************** hook_UsbSetIdleRequest USB_CORE_PROTOCOL")
    return EFI_SUCCESS     

@dxeapi(params = {
	"Timeout": UINTN
})
def hook_UsbSetProtocolRequest(ql, address, params):
    print("**************** hook_UsbSetProtocolRequest USB_CORE_PROTOCOL")
    return EFI_SUCCESS   
    
@dxeapi(params = {
	"Timeout": UINTN
})
def hook_RemoveUsbDevice(ql, address, params):
    print("**************** hook_RemoveUsbDevice USB_CORE_PROTOCOL")
    return EFI_SUCCESS   

@dxeapi(params = {
	"Timeout": UINTN
})
def hook_EnterCriticalSection(ql, address, params):
    print("**************** hook_EnterCriticalSection USB_CORE_PROTOCOL")
    return EFI_SUCCESS  
    
@dxeapi(params = {
	"Timeout": UINTN
})
def hook_LeaveCriticalSection(ql, address, params):
    print("**************** hook_LeaveCriticalSection USB_CORE_PROTOCOL")
    return EFI_SUCCESS   
       
@dxeapi(params = {
	"Timeout": UINTN
})
def hook_IsCsmEnabled(ql, address, params):
    print("**************** hook_IsCsmEnabled USB_CORE_PROTOCOL")
    return EFI_SUCCESS         
    
@dxeapi(params = {
	"Timeout": UINTN
})
def hook_InsertAddressConvertTable(ql, address, params):
    print("**************** hook_InsertAddressConvertTable USB_CORE_PROTOCOL")
    return EFI_SUCCESS     
 
@dxeapi(params = {
	"Timeout": UINTN
})
def hook_RegisterLegacyFreeHcCallback(ql, address, params):
    print("**************** hook_RegisterLegacyFreeHcCallback USB_CORE_PROTOCOL")
    return EFI_SUCCESS 
    
@dxeapi(params = {
	"Timeout": UINTN
})
def hook_ModuleRegistration(ql, address, params):
    print("**************** hook_ModuleRegistration USB_CORE_PROTOCOL")
    return EFI_SUCCESS  
 
@dxeapi(params = {
	"Timeout": UINTN
})
def hook_AddressConvert(ql, address, params):
    print("**************** hook_AddressConvert USB_CORE_PROTOCOL")
    return EFI_SUCCESS   
    
@dxeapi(params = {
	"Timeout": UINTN
})
def hook_RemoveAddressConvertTable(ql, address, params):
    print("**************** hook_RemoveAddressConvertTable USB_CORE_PROTOCOL")
    return EFI_SUCCESS 
    
@dxeapi(params = {
	"InSmm": BOOLEAN
})
def hook_IsInSmm(ql, address, params):
    print("**************** hook_IsInSmm USB_CORE_PROTOCOL")
    in_smm = 0
    ql.mem.write(params["InSmm"], in_smm.to_bytes(1, byteorder='little'))
    return EFI_SUCCESS    
    

descriptor = {
    "guid" : "c965c76a-d71e-4e66-ab06-c6230d528425",
    "struct" : EFI_USB_CORE_PROTOCOL,
    "fields" : (
('UsbGetDescriptor', hook_DummyHook),
('UsbSetDescriptor', hook_DummyHook),
('UsbGetDeviceInterface', hook_DummyHook),
('UsbSetDeviceInterface', hook_DummyHook),
('UsbGetDeviceConfiguration', hook_DummyHook),
('UsbSetDeviceConfiguration', hook_DummyHook),
('UsbSetDeviceFeature', hook_DummyHook),
('UsbClearDeviceFeature', hook_DummyHook),
('UsbGetDeviceStatus', hook_DummyHook),
('UsbGetString', hook_DummyHook),
('UsbClearEndpointHalt', hook_DummyHook),
('UsbGetHidDescriptor', hook_UsbGetHidDescriptor),
('UsbGetReportDescriptor', hook_UsbGetReportDescriptor),
('UsbGetProtocolRequest', hook_UsbGetProtocolRequest),
('UsbSetProtocolRequest', hook_UsbSetProtocolRequest),
('UsbGetIdleRequest', hook_DummyHook),
('UsbSetIdleRequest', hook_UsbSetIdleRequest),
('UsbGetReportRequest', hook_DummyHook),
('UsbSetReportRequest', hook_UsbSetReportRequest),
('AllocateBuffer', hook_AllocateBuffer),
('FreeBuffer', hook_FreeBuffer),
('MemoryMapping', hook_DummyHook),
('MemoryUnmapping', hook_DummyHook),
('PciIoPciRead', hook_DummyHook),
('PciIoPciWrite', hook_DummyHook),
('PciIoMemRead', hook_DummyHook),
('PciIoMemWrite', hook_DummyHook),
('PciIoIoRead', hook_PciIoIoRead),
('PciIoIoWrite', hook_PciIoIoWrite),
('IoRead8', hook_DummyHook),
('IoWrite8', hook_DummyHook),
('IoRead16', hook_DummyHook),
('IoWrite16', hook_DummyHook),
('IoRead32', hook_DummyHook),
('IoWrite32', hook_DummyHook),
('Bswap16', hook_DummyHook),
('Bswap32', hook_DummyHook),
('Stall', hook_Stall),
('CpuSaveState', hook_DummyHook),
('GetMode', hook_GetMode),
('SetMode', hook_DummyHook),
('UsbSmiRegister', hook_UsbSmiRegister),
('UsbSmiUnregister', hook_UsbSmiUnregister),
('InsertKbcKeyCode', hook_DummyHook),
('KbcTrapProcessor', hook_DummyHook),
('GetLegacySupportProvider', hook_DummyHook),
('InsertLegacySupportProvider', hook_DummyHook),
('RemoveLegacySupportProvider', hook_DummyHook),
('InsertPeriodicTimer', hook_DummyHook),
('RemovePeriodicTimer', hook_DummyHook),
('InsertPeriodicTimerProvider', hook_DummyHook),
('RemovePeriodicTimerProvider', hook_DummyHook),
('EnterCriticalSection', hook_EnterCriticalSection),
('LeaveCriticalSection', hook_LeaveCriticalSection),
('DispatchHcCallback', hook_DummyHook),
('RegisterUsbBindingProtocol', hook_DummyHook),
('GetUsbDevices', hook_DummyHook),
('InsertUsbDevice', hook_DummyHook),
('RemoveUsbDevice', hook_RemoveUsbDevice),
('ConnectUsbDevices', hook_DummyHook),
('DisconnectUsbDevices', hook_DummyHook),
('RegisterNonSmmCallback', hook_DummyHook),
('CheckIgnoredDevice', hook_DummyHook),
('CheckDeviceDetached', hook_DummyHook),
('CpuWbinvd', hook_DummyHook),
('IsKbcExist', hook_DummyHook),
('ModuleRegistration', hook_ModuleRegistration),
('IsInSmm', hook_IsInSmm),
('InsertAddressConvertTable', hook_InsertAddressConvertTable),
('RemoveAddressConvertTable', hook_RemoveAddressConvertTable),
('AddressConvert', hook_AddressConvert),
('SchedularConnection', hook_DummyHook),
('IsCsmEnabled', hook_IsCsmEnabled),
('GetSwSmiPort', hook_DummyHook),
('RegisterLegacyFreeHcCallback', hook_RegisterLegacyFreeHcCallback),
('UnregisterLegacyFreeHcCallback', hook_DummyHook),
('SyncKbdLed', hook_DummyHook),
('RegisterHidDescriptor', hook_DummyHook),
('UnregisterHidDescriptor', hook_DummyHook)
	)
    }
