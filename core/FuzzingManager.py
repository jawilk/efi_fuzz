# Make sure Qiling uses our patched Unicorn instead of it's own.
from unicorn.x86_const import UC_X86_INS_CPUID, UC_X86_INS_RDMSR
import unicornafl
unicornafl.monkeypatch()

from unicorn import *

from qiling.os.const import PARAM_INTN
from qiling.extensions.coverage import utils as cov_utils
import core.fault
import os
from qiling import Qiling
from core.EmulationManager import EmulationManager
import pefile
from conditional import conditional
from . import fault


def start_afl(_ql: Qiling, user_data):
    """
    Callback from inside
    """
    # NVRAM/UEFIFault
    #(varname, infile) = user_data
    # Fat
    infile = user_data

    def place_input_callback_nvram(uc, _input, _, data):
    # """
    # Injects the mutated variable to the emulated NVRAM environment.
    # """
        _ql.env[varname] = _input

    def place_input_callback_fuzz_data(uc, _input, _, data):
        _ql.env["FUZZ_DATA"] = _input.raw
        return True

    def validate_crash(uc, err, _input, persistent_round, user_data):
        """
        Informs AFL that a certain condition should be treated as a crash.
        """
        if _ql.arch.regs.arch_pc == 0x0000000000101e2d:
            return False
        if hasattr(_ql.os.heap, "validate"):
            if not _ql.os.heap.validate():
                # Canary was corrupted
                verbose_abort(_ql)
                return True
        print(hex(_ql.arch.regs.arch_pc))
        if _ql.env["END"]:
            print("IS END FUZZ RUN")
            _ql.env["END"] = False
            return False
        crash = (_ql.internal_exception is not None) or (err != UC_ERR_OK)
        return crash

    # Inject mutated FAT images through this callback
    #place_input_callback = place_input_callback_nvram
       
    place_input_callback = place_input_callback_fuzz_data

    _ql.env["END"] = False
    try:
        if not _ql.uc.afl_fuzz(input_file=infile,
                               place_input_callback=place_input_callback,
                               exits=[_ql.os.exit_point],
                               always_validate=True,
                               validate_crash_callback=validate_crash,
                               persistent_iters=10):
            os._exit(0)  # that's a looot faster than tidying up.
    except unicornafl.UcAflError as ex:
        if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
            raise


class FuzzingManager(EmulationManager):

    # Tainting significantly slows down the fuzzing process.
    # Therefore, we won't enable them unless explicitly requested by the user.
    # ['smm_callout'] # @TODO: maybe enable 'memory' sanitizer as well?
    # DEFAULT_SANITIZERS = ['memory']

    def __init__(self, target_module, extra_modules=None, afl_crash_file=None):
        super().__init__(target_module, extra_modules, afl_crash_file)

        # self.sanitizers = FuzzingManager.DEFAULT_SANITIZERS
        # By default we prefer to abort to notify AFL of potential crashes.
        self.fault_handler = 'abort'

    @EmulationManager.coverage_file.setter
    def coverage_file(self, cov):
        # The default behaviour of the fuzzer is to 'abort()' upon encoutering a fault.
        # Since no termination handlers will be called, the coverage collector won't be
        # able to dump the collected coverage entries to a file.
        self.ql.log.warn('Coverage collection is incompatible with fuzzing')
        self._coverage_file = None

    def setup_fuzz_target(self, modules_left):
        if modules_left != 0:
            return False   

        image_base = self.ql.loader.images[-1].base
        address_to_call = image_base + 0x1a3c
        
        # DiskIo read blocks
        #self.ql.hook_address(address=0x001012a6,
         #                    callback=self.disk_io_read_blocks)


        # AFL's forkserver will spawn new copies from here
        self.ql.hook_address(callback=start_afl, address=address_to_call, user_data=(
            'dummy_file'))

        # 1st arg is fat driver, 2nd is our FakeController handle
        #args = [0x109140, 0x101000]
        # Usb mouse 0x102a3e keyboard 0x10498a
        args = [self.ql.loader.entry_point, 0x1]
        
        ### FAT
        # 1st arg is fat driver, 2nd is our FakeController handle
        #args = [0x1078b9, 0x1]
        
        types = (PARAM_INTN, ) * len(args)
        targs = tuple(zip(types, args))

        self.ql.env["END"] = False
        
        def __cleanup2(ql: Qiling):
            # Give afl this func's address as fuzzing end
            self.ql.env["END"] = True
            return True

        def __cleanup(ql: Qiling):
            # Give afl this func's address as fuzzing end
            address_to_call2 = image_base + 0x27a1 #0x6e96 # UsbRootHubEnumeration
            # Event, Context
            args2 = [0x04013004, 0x04012f54] # UsbRootHubEnumeration(Event, *Context)
            targs2 = tuple(zip(types, args2))
            cleanup_trap = self.ql.os.heap.alloc(self.ql.arch.pointersize)
            hret = self.ql.hook_address(__cleanup2, cleanup_trap)
            #self.ql.os.fcall.call_native(address_to_call2, targs2, cleanup_trap)
            self.ql.env["END"] = True
            return True

        cleanup_trap = self.ql.os.heap.alloc(self.ql.arch.pointersize)
        hret = self.ql.hook_address(__cleanup, cleanup_trap)

        # Call the driver start func and invoke the fuzzer (it's hooked on that address)
        self.ql.os.fcall.call_native(address_to_call, targs, cleanup_trap)
        return True

    def fuzz(self, end=None, timeout=0, **kwargs):
	# Fat
        #self.ql.os.on_module_exit.append(self.setup_fuzz_target)

        # Invoke all module entrypoints, the fuzzer will be started after the last module's entrypoint returns (through the `on_module_exit` hook above)
        #self.run(end, timeout, 'fuzz')

	# NVRAM/UEFIFault
        target = self.ql.loader.images[-1].path
        pe = pefile.PE(target, fast_load=True)
        image_base = self.ql.loader.images[-1].base
        entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        # + Usb
        self.ql.os.on_module_exit.append(self.setup_fuzz_target)

        # We want AFL's forkserver to spawn new copies starting from the main module's entrypoint.
        #self.ql.hook_address(callback=start_afl, address=entry_point, user_data=(kwargs['varname'], kwargs['infile']))

        super().run(end, timeout, mode='fuzz')
