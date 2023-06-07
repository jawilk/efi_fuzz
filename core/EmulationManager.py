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
from . import fault
import os
import binascii
from qiling.os.uefi.ProcessorBind import STRUCT, PAGE_SIZE
import capstone
from unicorn.x86_const import *
from conditional import conditional

from qiling.os.const import PARAM_INTN


class EmulationManager:

    # ['smm_callout', 'smm', 'uninitialized'] # @TODO: add 'memory' sanitizer as default
    DEFAULT_SANITIZERS = ['memory']

    def __init__(self, target_module, extra_modules=None):

        if extra_modules is None:
            extra_modules = []

        self.ql = Qiling(extra_modules + [target_module],
                         ".", verbose=QL_VERBOSE.DEBUG)  # ,                                      # rootfs
        # output="trace")

        # callbacks.init_callbacks(self.ql)

        self.coverage_file = None

        self.sanitizers = EmulationManager.DEFAULT_SANITIZERS
        self.fault_handler = 'exit'  # By default we prefer to exit the emulation cleanly
        self.fat_image = None
        self.load_fat_image(
            "/home/wj/temp/uefi/test-fat/dummy_esp.img")

    def load_fat_image(self, path):
        with open(path, "rb") as file:
            self.fat_image = file.read()

    def load_nvram(self, nvram_file):
        # Load NVRAM environment.
        with open(nvram_file, 'rb') as nvram:
            self.ql.env.update(pickle.load(nvram))

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
                self.ql.loader.dxe_context.install_protocol(descriptor, 1)

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

    def hi2(self, m):
        print("ENDHEREEEEEEEEEEEEEEEEEEEEE")
        self.ql.os.emit_context()
        # print(hex(self.ql.arch.regs.arch_pc))

    def hi3(self, m):
        print("!!!!!!!!!!!!!!! On call FatOpenDevice")

    def hi4(self, m):
        print("!!!!!!!!!!!!!!! After call FatAllocateVolume")

    def hi5(self, m):
        # addr start in r8
        # size param is in r9
        # &buf pointer is in RSP+0x28

        print("!!!!!!!!!!!!!!! DISK IO READ BLOCKS")
        offset = self.ql.arch.regs.r8
        size = self.ql.arch.regs.r9
        buf_addr = self.ql.mem.read(
            self.ql.arch.regs.rsp + 0x28, 8)
        buf_addr = int.from_bytes(buf_addr, 'little')
        # self.ql.mem.read(self.ql.arch.stack_read(
        # 5 * self.ql.arch.pointersize), 8)
        print("offset:", hex(offset))
        print("size:", size)
        print("buf addr:", buf_addr, hex(buf_addr))
        self.ql.os.emit_context()
        self.ql.os.emit_stack(12)
        pc = self.ql.arch.regs.arch_pc
        data = self.ql.mem.read(pc, size=64)
        self.ql.os.emit_disasm(pc, data, 32)
        # print(self.fat_image[:size])
        # bytes([1, 2, 3, 4]))
        print("data:", self.fat_image[offset:offset+size])
        self.ql.mem.write(buf_addr, self.fat_image[offset:offset+size])
        self.ql.os.emit_stack(12)
        print("HEREEEEEE AFTER STACK WRITE")

    def hi(self, a):
        print(hex(self.ql.arch.regs.arch_pc), a)
        print("2222HEREEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
        if a != 0:
            return False
        print(self.ql)
        print("3333HEREEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")

        # FatDriverBindingStart
        address_to_call = 0x00103658
        self.ql.hook_address(address=address_to_call, callback=self.hi2)

        # On call FatAllocateVolume
        self.ql.hook_address(address=0x001041d2, callback=self.hi3)
        # After call FatAllocateVolume
        self.ql.hook_address(address=0x001037fa, callback=self.hi4)
        # DiskIo read blocks
        self.ql.hook_address(address=0x001012a6, callback=self.hi5)

        # Set pc
        # self.ql.arch.regs.arch_pc = address_to_call

        # Execute the code at the desired address
        # self.ql.uc.emu_start(address_to_call, timeout=0, count=1)
        args = [0x109140, 0x101000]
        types = (PARAM_INTN, ) * len(args)
        targs = tuple(zip(types, args))

        def __cleanup(ql: Qiling):
            # Give afl this address as fuzzing end
            print("END CLEANUP 4444HEREEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")

        cleanup_trap = self.ql.os.heap.alloc(self.ql.arch.pointersize)
        hret = self.ql.hook_address(__cleanup, cleanup_trap)
        self.ql.os.fcall.call_native(address_to_call, targs, cleanup_trap)
        print("END 4444HEREEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
        return True

    def endend(self):
        print("END 4444HEREEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")

    def entry(self, a):
        print("MOOOOOOOIN", a)
        self.ql.os.emit_context()
        return False

    def run(self, end=None, timeout=0, **kwargs):
        self.ql.os.on_module_exit.append(self.hi)
        # self.ql.os.on_module_enter.append(self.entry)
        # self.ql.hook_address(address=0x100412, callback=self.hi)

        # if end:
        #   end = callbacks.set_end_of_execution_callback(self.ql, end)

        self._enable_sanitizers()

        try:
            # Don't collect coverage information unless explicitly requested by the user.
            with conditional(self.coverage_file, cov_utils.collect_coverage(self.ql, 'drcov_exact', self.coverage_file)):
                self.ql.run(end=end, timeout=timeout)
        except fault.ExitEmulation:
            # Exit cleanly.
            pass
