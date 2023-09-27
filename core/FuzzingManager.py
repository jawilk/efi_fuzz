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
    print("!"*10, "START AFL")

    # NVRAM/UEFIFault
    #(varname, infile) = user_data
    # Fat
    infile = user_data
    print(infile)

    def place_input_callback_nvram(uc, _input, _, data):
    # """
    # Injects the mutated variable to the emulated NVRAM environment.
    # """
        _ql.env[varname] = _input

    def place_input_callback_fat_meta(uc, _input, _, data):
        print(_input.raw)
        _ql.env["USB_META"] = _input.raw
        return True

    def validate_crash(uc, err, _input, persistent_round, user_data):
        """
        Informs AFL that a certain condition should be treated as a crash.
        """
        print("!"*10, "AFL VALIDATE CRASH")
        # print(hex(_ql.arch.regs.arch_pc))

        if hasattr(_ql.os.heap, "validate"):
            print("!"*10, "AFL IS HEAP VALIDATE CRASH")
            if not _ql.os.heap.validate():
                print("!!"*10, "AFL HEAP INVALID")
                # Canary was corrupted
                verbose_abort(_ql)
                return True
        else:
            print("!"*10, "AFL IS NO HEAP VALIDATE CRASH")
        print(hex(_ql.arch.regs.arch_pc))
        print(_ql.env["END"])
        if _ql.env["END"]:
            print("IS END")
            _ql.env["END"] = False
            return False
        print(err)
        print(_ql.internal_exception)
        crash = (_ql.internal_exception is not None) or (
            err != UC_ERR_OK)
        print("Crash", crash)
        return crash

    # Inject mutated FAT images through this callback
    #place_input_callback = place_input_callback_nvram
       
    place_input_callback = place_input_callback_fat_meta

    print("!"*10, "START AFL BEFORE TRY")
    _ql.env["END"] = False
    try:
        if not _ql.uc.afl_fuzz(input_file=infile,
                               place_input_callback=place_input_callback,
                               exits=[_ql.os.exit_point],
                               always_validate=True,
                               validate_crash_callback=validate_crash):
            print("Dry run completed successfully without AFL attached.")
            os._exit(0)  # that's a looot faster than tidying up.
    except unicornafl.UcAflError as ex:
        print("!"*10, "EXCEPT AFL ERROR", ex)
        if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
            raise


class FuzzingManager(EmulationManager):

    # Tainting significantly slows down the fuzzing process.
    # Therefore, we won't enable them unless explicitly requested by the user.
    # ['smm_callout'] # @TODO: maybe enable 'memory' sanitizer as well?
    # DEFAULT_SANITIZERS = ['memory']

    def __init__(self, target_module, extra_modules=None):
        super().__init__(target_module, extra_modules)

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
        # UsbMouseDriverBindingStart (from ghidra)
        #target = self.ql.loader.images[-1].path
        #pe = pefile.PE(target, fast_load=True)
        image_base = self.ql.loader.images[-1].base
        # mouse 0x21e7 keyboard 0x38a1
        #address_to_call = image_base + 0x21e7  # 0x800021e7
        address_to_call = image_base + 0x38a1
        # FatDriverBindingStart (from ghidra)
        #target = self.ql.loader.images[-1].path
        #pe = pefile.PE(target, fast_load=True)
        #image_base = self.ql.loader.images[-1].base
        # Normal
        #address_to_call = image_base + 0x658  # 0x00103658
        # Overflow
        #address_to_call = 0x00108b49

        # DiskIo read blocks
        #self.ql.hook_address(address=0x001012a6,
         #                    callback=self.disk_io_read_blocks)

        # AFL's forkserver will spawn new copies from here
        self.ql.hook_address(callback=start_afl, address=address_to_call, user_data=(
            '/blah/dummy_file'))

        # 1st arg is fat driver, 2nd is our FakeController handle
        #args = [0x109140, 0x101000]
        # Usb mouse 0x102a3e keyboard 0x10498a
        args = [0x10498a, 0x1]
        types = (PARAM_INTN, ) * len(args)
        targs = tuple(zip(types, args))

        self.ql.env["END"] = False

        def __cleanup(ql: Qiling):
            # Give afl this address as fuzzing end address
            self.ql.env["END"] = True
            print("!"*10, "END CLEANUP")

        cleanup_trap = self.ql.os.heap.alloc(self.ql.arch.pointersize)
        hret = self.ql.hook_address(__cleanup, cleanup_trap)

        # Call the driver start func and invoke the fuzzer (it's hooked on that address)
        self.ql.os.fcall.call_native(address_to_call, targs, cleanup_trap)
        print("!"*10, "END FUZZ")
        return True

    def fuzz(self, end=None, timeout=0, **kwargs):
        print("*"*10, "AFL FUZZ START")

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

        super().run(end, timeout, 'fuzz')
