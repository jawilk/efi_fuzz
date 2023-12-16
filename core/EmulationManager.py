import time
import pickle
import rom
from qiling import Qiling
from qiling.const import QL_VERBOSE
from . import callbacks
import sanitizers
import smm
from qiling.extensions.coverage import utils as cov_utils
import json
import dummy_protocol
import UsbIoProtocol
import Usb2HcProtocol
import DevicePathProtocol
import PcdProtocol
import EfiPcdProtocol
import GetPcdInfoProtocol
import EfiGetPcdInfoProtocol
import IOMMUProtocol
import EfiUsbCoreProtocol
import EfiHiiDatabaseProtocol
import EfiPciIoProtocol
import EfiDiskIoProtocol
import EfiDiskIo2Protocol
import EfiBlockIoProtocol
import EfiSimplePointerProtocol
from qiling.os.uefi import guids_db
from . import fault
import os
import binascii
from qiling.os.uefi.ProcessorBind import STRUCT, PAGE_SIZE
import capstone
from unicorn.x86_const import *
from conditional import conditional
import random

from qiling.os.const import PARAM_INTN, PARAM_PTRX


class EmulationManager:

    # ['smm_callout', 'smm', 'uninitialized'] # @TODO: add 'memory' sanitizer as default
    DEFAULT_SANITIZERS = ['memory']

    def __init__(self, target_module, extra_modules=None, afl_crash_file=None):

        if extra_modules is None:
            extra_modules = []
        if afl_crash_file:
            self.load_afl_crash_file(afl_crash_file)
        else:
            self.afl_crash_data = "aaaaaaaaaaaaaaaaaaaaaa"
            self.afl_crash_file = None

        self.ql = Qiling(extra_modules + [target_module],
                         ".", verbose=QL_VERBOSE.DEBUG)#DEBUG)#DISABLED

        # Load fat image into the env
        #self.load_fat_image(
         #   "dummy_esp.img")

        # callbacks.init_callbacks(self.ql)

        self.coverage_file = None

        self.sanitizers = EmulationManager.DEFAULT_SANITIZERS
        self.fault_handler = 'abort'
        
        descriptor = UsbIoProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = DevicePathProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = Usb2HcProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = PcdProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = EfiPcdProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = GetPcdInfoProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = EfiGetPcdInfoProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = IOMMUProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = EfiUsbCoreProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = EfiHiiDatabaseProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = EfiPciIoProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = EfiDiskIoProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = EfiDiskIo2Protocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = EfiBlockIoProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        descriptor = EfiSimplePointerProtocol.descriptor
        self.ql.loader.dxe_context.install_protocol(descriptor, 1)
        
    def load_afl_crash_file(self, path):
        with open(path, "rb") as file:
            self.afl_crash_data = file.read()
        self.afl_crash_file = os.path.basename(path)

    #def load_fat_image(self, path):
     #   with open('compute-afl/queue/'+path, "rb") as file:
      #      self.ql.env["FUZZ_DATA"] = file.read()

    def load_input_data(self):
        self.ql.env["counter"] = 0
        folder_path = 'compute-afl/queue'
        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))] 
        self.input_files_path = files[1:]

    def load_nvram(self, nvram_file):
        # Load NVRAM environment.
        with open(nvram_file, 'rb') as nvram:
            self.ql.env.update(pickle.load(nvram))
            # self.ql.env['FaultType'] = b'\x0e'


    def load_rom(self, rom_file):
        # Init firmware volumes from the provided ROM file.
        rom.install(self.ql, rom_file)

    def _enable_sanitizers(self):
        # Enable sanitizers.
        self.ql.log.info(f'Enabling sanitizers {self.sanitizers}')
        for sanitizer in self.sanitizers:
            sanitizers.get(sanitizer)(self.ql).enable()

    def enable_smm(self):
        profile = os.path.join(os.path.dirname(
            __file__), os.path.pardir, 'smm', 'smm.ini')
        self.ql.profile.read(profile)
        # Init SMM related protocols.
        smm.init(self.ql, True)

    @property
    def coverage_file(self):
        return self._coverage_file

    @coverage_file.setter
    def coverage_file(self, cov):
        self._coverage_file = cov

    def apply(self, json_conf):
        if not json_conf:
            return

        with open(json_conf, 'r') as f:
            conf = json.load(f)

        # Install protocols
        if conf.get('protocols'):
            for proto in conf['protocols']:
                descriptor = dummy_protocol.make_descriptor(proto['guid'])
                self.ql.loader.dxe_:qcontext.install_protocol(descriptor, 1)

        if conf.get('registers'):
            self.ql.os.smm.swsmi_args['registers'] = conf['registers']

        if conf.get('memory'):
            # Apply memory.
            for (address, data) in conf['memory'].items():
                address = int(address, 0)
                data = binascii.unhexlify(data.replace(' ', ''))
                if not self.ql.mem.is_mapped(address, len(data)):
                    if address % PAGE_SIZE == 0:
                        page = address
                    else:
                        page = self.ql.mem.align(address) - PAGE_SIZE
                    size = self.ql.mem.align(len(data))
                    self.ql.mem.map(page, size)
                self.ql.mem.write(address, data)

    @property
    def fault_handler(self):
        return self._fault_handler

    @fault_handler.setter
    def fault_handler(self, value):
        self._fault_handler = value

        if value == 'exit':
            self.ql.os.fault_handler = fault.exit
        elif value == 'abort':
            self.ql.os.fault_handler = fault.abort
        elif value == 'ignore':
            self.ql.os.fault_handler = fault.ignore
        elif value == 'break':
            self.ql.os.fault_handler = fault._break

    def fat_binding_start(self, m):
        print("!"*10, "FAT DRIVER BINDING START")
        #self.ql.os.emit_context()
        # print(hex(self.ql.arch.regs.arch_pc))

    def fat_open_device(self, m):
        print("!"*10, "On call FatOpenDevice")

    def fat_allocate_volume(self, m):
        print("!"*10, "After call FatAllocateVolume")

    def disk_io_read_blocks(self, m):
        """Mock DiskIo through hooking into the FakeController FakeControllerReadDisk func
        offset in r8
        size param is in r9
        &buf pointer is in RSP+0x28
        """
        # Fetch func args
        offset = self.ql.arch.regs.r8
        size = self.ql.arch.regs.r9
        buf_addr = self.ql.mem.read(
            self.ql.arch.regs.rsp + 0x28, 8)
        buf_addr = int.from_bytes(buf_addr, 'little')

        # Write fuzz data onto stack
        self.ql.mem.write(
            buf_addr, self.ql.env["FUZZ_DATA"][offset:offset+size])

        print("!"*10, "END DISKIO READ BLOCKS")
        
    def usb_bus_binding_start(self, m):
        print("!"*10, "USB DRIVER BINDING START")
        
    def breakpoint(self, m):
        print("!"*10, "BREAKPOINT")
        
    def restart(self, m):
        print("RESTART")
        if self.ql.env["counter"] == len(self.input_files_path):
            return
        path = self.input_files_path[self.ql.env["counter"]]
        self.load_fat_image(path)
        self.ql.env["counter"] += 1
        args = [0x1078b9, 0x1]
        types = (PARAM_INTN, ) * len(args)
        targs = tuple(zip(types, args))
        self.ql.os.fcall.call_native(self.ql.env["address_to_call"], targs, None)
        
    def setup_driver_binding_start(self, modules_left):
        if modules_left != 0:
            return False
        
        # Fat
        #self.load_input_data()
        
        self.ql.env["FUZZ_DATA"] = self.afl_crash_data
        # UsbBus UsbBusControllerDriverStart
        image_base = self.ql.loader.images[-1].base

        # mouse 0x21e7 keyboard 0x38a1 mouse lenovo 0x18e4 busdxe bug 0x452d inline 0x618b (UsbBuildDescTable) kb lenovo 0x17bc busdxe bug edk2 noinline_4 0x66ad
        address_to_call = self.get_driver_start_addr() #0xc89 (fat inline) #0x1a3c (insyde) #0x66ad #0x452d #0x4236
        #self.ql.env["address_to_call"] = address_to_call
        self.ql.hook_address(address=address_to_call,
                             callback=self.usb_bus_binding_start)
        
        # Breakpoints
        #address_to_call_2 = image_base + 0xa55
        #self.ql.hook_address(address=address_to_call_2,
         #                   callback=self.breakpoint)
        ### USB            
        args = [self.ql.loader.entry_point, 0x1]
        ### FAT
        # 1st arg is fat driver, 2nd is our FakeController handle
        #args = [0x1078b9, 0x1]
        
        types = (PARAM_INTN, ) * len(args)
        targs = tuple(zip(types, args))
        
        def __cleanup2(ql: Qiling):
            # Give afl this func's address as fuzzing end address
            # os.abort()
            return True

        def __cleanup(ql: Qiling):
            # Give afl this func's address as fuzzing end
            address_to_call2 = image_base + 0x27a1 #0x27a1 #0x285e #0x6e96 # UsbRootHubEnumeration
            # Event, Context
            args2 = [0x0401304c, 0x04012f9c] # UsbRootHubEnumeration(Event, *Context)
            targs2 = tuple(zip(types, args2))
            cleanup_trap = self.ql.os.heap.alloc(self.ql.arch.pointersize)
            self.ql.hook_address(__cleanup2, cleanup_trap)
            #self.ql.os.fcall.call_native(address_to_call2, targs2, cleanup_trap)
            return True
            
        cleanup_trap = self.ql.os.heap.alloc(self.ql.arch.pointersize)
        self.ql.hook_address(address=cleanup_trap, callback=__cleanup)
        #self.ql.hook_address(address=image_base+0xe62, callback=self.restart)
        
        def __cleanup(ql: Qiling):
            return True
        cleanup_trap = self.ql.os.heap.alloc(self.ql.arch.pointersize)
        address_to_call = self.get_driver_start_addr()
        args = [self.ql.loader.entry_point, 0x1]
        self.ql.os.fcall.call_native(address_to_call, targs, cleanup_trap)
        return True
        
    def get_driver_start_addr(self):
        EfiDriverBindingProtocolGuid = "18A031AB-B443-4D1A-A5C0-0C09261E9F71".lower()
        handle = None
        for handle, guid_dic in self.ql.loader.dxe_context.protocols.items():
            if EfiDriverBindingProtocolGuid in guid_dic:
                handle = hex(guid_dic[EfiDriverBindingProtocolGuid])
                break
        # +8 because StartDriver is 2nd pointer in driver binding struct
        ptr = self.ql.mem.read(int(handle, 16)+8, 8)
        print("DriverBindingStart @", hex(int.from_bytes(ptr, byteorder='little')))
        return int.from_bytes(ptr, byteorder='little')
        
    def dump_driver_start(self, modules_left):
        if modules_left != 0:
            return False
        self.get_driver_start_addr()
        return True
        
    def run(self, end=None, timeout=0, mode='normal', **kwargs):
        if mode == 'normal':
            self.ql.os.on_module_exit.append(self.setup_driver_binding_start)
            
        if mode == 'dump_driver_start':
            self.ql.os.on_module_exit.append(self.dump_driver_start)
        
        if end:
            end = callbacks.set_end_of_execution_callback(self.ql, end)

        self._enable_sanitizers()

        # try:
            # Don't collect coverage information unless explicitly requested by the user.
        with conditional(self.coverage_file, cov_utils.collect_coverage(self.ql, 'drcov', self.coverage_file)):
            try:
                self.ql.run(end=end, timeout=timeout)
            except Exception as e:
                print("EXCEPTION", e)
                print("PC", hex(self.ql.arch.regs.arch_pc))
                if self.afl_crash_file:
                    pcs_file = "unique-pcs/pcs.txt"
                    with open(pcs_file, "r") as file:
                        file_contents = file.read()
                    if hex(self.ql.arch.regs.arch_pc) not in file_contents:
                        with open(pcs_file, "a") as f:
                            f.write(hex(self.ql.arch.regs.arch_pc) + '\n')
                        with open("unique-pcs/run_id.txt", "a") as f:
                            f.write(self.afl_crash_file + '\n')
        print(hex(self.ql.arch.regs.arch_pc))
        print("EMU END run")
        print(mode)
