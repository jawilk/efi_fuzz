# Make sure Qiling uses our patched Unicorn instead of it's own.
from qiling.os.const import PARAM_INTN
from qiling.extensions.coverage import utils as cov_utils
import core.fault
import os
from qiling import Qiling
from core.EmulationManager import EmulationManager
import pefile
from unicorn import *
from unicorn.x86_const import UC_X86_INS_CPUID, UC_X86_INS_RDMSR
import unicornafl
from conditional import conditional
from . import fault
unicornafl.monkeypatch()


def start_afl(_ql: Qiling, user_data):
    """
    Callback from inside
    """
    print("START AFL ***********************")

    # (varname, infile) = user_data
    infile = user_data

    # def place_input_callback_nvram(uc, _input, _, data):
    # """
    # Injects the mutated variable to the emulated NVRAM environment.
    # """
    # _ql.env[varname] = _input

    def place_input_callback_fat_meta(uc, _input, _, data):
        _ql.env["FAT_META"] = _input.raw

    def validate_crash(uc, err, _input, persistent_round, user_data):
        """
        Informs AFL that a certain condition should be treated as a crash.
        """
        print("AFL VALIDATE CRASH *******************************")
        print(hex(_ql.arch.regs.arch_pc))
        return False
        if hasattr(_ql.os.heap, "validate"):
            print("AFL IS VALIDATE CRASH *******************************")
            if not _ql.os.heap.validate():
                print("AFL HEAP INVALID *******************************")
                # Canary was corrupted.
                verbose_abort(_ql)
                return True

        crash = (_ql.internal_exception is not None) or (
            err.errno != UC_ERR_OK)
        return crash

    # Choose the function to inject the mutated input to the emulation environment,
    # based on the fuzzing mode.
    place_input_callback = place_input_callback_fat_meta

    # We start our AFL forkserver or run once if AFL is not available.
    # This will only return after the fuzzing stopped.
    print("START AFL BEFORE TRY FUZZ *********************")
    try:
        if not _ql.uc.afl_fuzz(input_file=infile,
                               place_input_callback=place_input_callback,
                               exits=[_ql.os.exit_point],
                               always_validate=True,
                               validate_crash_callback=validate_crash):
            print("Dry run completed successfully without AFL attached.")
            os._exit(0)  # that's a looot faster than tidying up.
    except unicornafl.UcAflError as ex:
        print("!!!!!!!!!!!!!!! EXCEPT AFL ERROR", ex)
        if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
            raise


class FuzzingManager(EmulationManager):

    # Tainting significantly slows down the fuzzing process.
    # Therefore, we won't enable them unless explicitly requested by the user.
    # ['smm_callout'] # @TODO: maybe enable 'memory' sanitizer as well?
    DEFAULT_SANITIZERS = ['memory']

    def __init__(self, target_module, extra_modules=None):
        super().__init__(target_module, extra_modules)

        self.sanitizers = FuzzingManager.DEFAULT_SANITIZERS
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
        # FatDriverBindingStart
        # target = self.ql.loader.images[-1].path
        # pe = pefile.PE(target, fast_load=True)
        # image_base = self.ql.loader.images[-1].base
        # address_to_call = image_base + 0x658  # 0x00103658
        address_to_call = 0x00103658
        # self.ql.hook_address(address=address_to_call, callback=self.hi2)

        # DiskIo read blocks
        self.ql.hook_address(address=0x001012a6,
                             callback=self.disk_io_read_blocks)

        # We want AFL's forkserver to spawn new copies starting from here
        self.ql.hook_address(callback=start_afl, address=address_to_call, user_data=(
            '/blah/dummy_file'))

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

    def disk_io_read_blocks(self, m):
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
        # self.ql.os.emit_context()
        self.ql.os.emit_stack(12)
        pc = self.ql.arch.regs.arch_pc
        data = self.ql.mem.read(pc, size=64)
        self.ql.os.emit_disasm(pc, data, 32)
        # print(self.fat_image[:size])
        # bytes([1, 2, 3, 4]))
        # self.ql.mem.write(buf_addr, self.fat_image[offset:offset+size])
        print("HEREEEEEE BEFORE STACK WRITE")
        print("FAT_META ", self.ql.env["FAT_META"])
        print("FAT_META len", len(self.ql.env["FAT_META"]))
        print("data:", self.ql.env["FAT_META"][offset:offset+size])
        self.ql.mem.write(
            buf_addr, self.ql.env["FAT_META"][offset:offset+size])
        # self.ql.os.emit_stack(12)
        print("HEREEEEEE AFTER STACK WRITE")

    def fuzz(self, end=None, timeout=0, **kwargs):
        print("AFL FUZZ START *******************************")

        load_fat_image("/home/wj/temp/uefi/test-fat/dummy_esp.img")

        self.ql.os.on_module_exit.append(self.setup_fuzz_target)

        print("AFL BEFORE QILING RUN **********************")
        try:
            # Don't collect coverage information unless explicitly requested by the user.
            with conditional(self.coverage_file, cov_utils.collect_coverage(self.ql, 'drcov_exact', self.coverage_file)):
                self.ql.run(end=end, timeout=timeout)
        except fault.ExitEmulation:
            # Exit cleanly.
            pass

        # super().run(end, timeout)


def load_fat_image(path):
    with open(path, "rb") as file:
        FAT_IMAGE = file.read()
