import os

from qiling.const import *
#from qiling.extensions.sanitizers.heap import QlSanitizedMemoryHeap
from .heap import QlSanitizedMemoryHeap
from .base_sanitizer import base_sanitizer

class memory_sanitizer(base_sanitizer):

    NAME = "memory"

    def __init__(self, ql):
        super().__init__(ql)
        self.assembler = ql.arch.assembler

    def _enable_sanitized_CopyMem(self):
        """
        Replaces the emulated CopyMem() service with an inline assembly implementation.
        This implementation will trigger hooks placed on the Destination and Source buffers.
        """

        # typedef VOID(EFIAPI * EFI_COPY_MEM) (IN VOID *Destination, IN VOID *Source, IN UINTN Length)
        CODE = """
            push rsi
            push rdi
            mov rsi, rdx
            mov rdi, rcx
            mov rcx, r8            
            rep movsb
            pop rdi
            pop rsi
            """
            
        runcode, _ = self.assembler.asm(CODE)
        ptr = self.ql.os.heap.alloc(len(runcode))
        self.ql.mem.write(ptr, bytes(runcode))

        def my_CopyMem(ql, address, params):
            #ql.os.exec_arbitrary(ptr, ptr+len(runcode))
            ql.run(ptr, ptr+len(runcode))
            return 0

        self.ql.os.set_api("CopyMem", my_CopyMem)

    def _enable_sanitized_SetMem(self):
        """
        Replaces the emulated SetMem() service with an inline assembly implementation.
        This implementation will trigger hooks placed on the Buffer argument.
        """

        # typedef VOID(EFIAPI * EFI_SET_MEM) (IN VOID *Buffer, IN UINTN Size, IN UINT8 Value)
        CODE = """
            push rdi
            mov rdi, rcx
            mov rcx, rdx
            mov al, r8b            
            rep stosb
            pop rdi
            """
            
        runcode, _ = self.assembler.asm(CODE)
        ptr = self.ql.os.heap.alloc(len(runcode))
        self.ql.mem.write(ptr, bytes(runcode))

        def my_SetMem(ql, address, params):
            #ql.os.exec_arbitrary(ptr, ptr+len(runcode))
            ql.run(ptr, ptr+len(runcode))
            return 0

        self.ql.os.set_api("SetMem", my_SetMem)
        
    def _enable_sanitized_heap(self, fault_rate=0):
        """
        Enables the sanitized heap, currently capable of detecting:
        - pool overflows
        - pool underflows
        - pool OOB read ahead
        - pool OOB read behind
        - pool double frees
        - pool invalid frees
        - pool use-after-free
        """
        
        def bo_handler(ql, access, addr, size, value):
            print("***************************************************")
            print(f'bo_handler - {access}, {hex(addr)}, {size}, {value}')
            print("***")
            raise Exception("bo_handler")

        def oob_handler(ql, access, addr, size, value):
            print("***************************************************")
            print(f'oob_handler - {access}, {hex(addr)}, {size}, {value}')
            print("***")
            raise Exception("oob_handler")

        def uaf_handler(ql, access, addr, size, value):
            print("***************************************************")
            print(f'uaf_handler - {access}, {hex(addr)}, {size}, {value}')
            print("***")
            #pc = ql.arch.regs.arch_pc
            #print(hex(pc))
            #data = self.ql.mem.read(pc, size=64)
            #data2 = self.ql.mem.read(addr, size=64)
            #ql.os.emit_context()
            #ql.os.emit_hexdump(pc, data)
            #ql.os.emit_hexdump(addr, data2)
            #ql.os.emit_disasm(pc, data)
            #ql.os.emit_stack()
            raise Exception("uaf_handler")

        def bad_free_handler(ql, addr):
            print("***************************************************")
            print(f'bad_free_handler - {hex(addr)}')
            print("***")
            raise Exception("bad_free_handler")

        heap = QlSanitizedMemoryHeap(self.ql, self.ql.os.heap, fault_rate=fault_rate)
        heap.oob_handler = oob_handler
        heap.bo_handler = bo_handler
        heap.bad_free_handler = bad_free_handler
        heap.uaf_handler = uaf_handler
        
        # make sure future allocated buffers are not too close to UEFI data
        heap.alloc(0x1000)
        
        self.ql.os.heap = heap
        self.ql.loader.dxe_context.heap = heap
        
        print("HEAP SANITIZER ENABLED")

    def enable(self):
        print("MEMORY SANITIZER ENABLED")
        #self._enable_sanitized_CopyMem()
        #self._enable_sanitized_SetMem()
        self._enable_sanitized_heap()
