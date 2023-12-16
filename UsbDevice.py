#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *


class InterfaceDescriptor(STRUCT):
	_fields_ = [
		('Bus', UINT8),
		('Speed', UINT8),
		('Address', UINT8),
		('MaxPacket0', UINT32),
		('DevDesc', UINT8),
		('ActiveConfig', UINT8),
		('LangId', UINT16),
		('TotalLangId', UINT16),
		('NumOfInterface', UINT8),
		('Interfaces', UINT8),
		('Interface', UINT8),
	]
