from .smm_cpu_protocol import install_EFI_SMM_CPU_PROTOCOL
from .smm_sw_dispatch_protocol import install_EFI_SMM_SW_DISPATCH_PROTOCOL
from .smm_sx_dispatch_protocol import install_EFI_SMM_SX_DISPATCH_PROTOCOL
from .smm_base_protocol import install_EFI_SMM_BASE_PROTOCOL
from .smm_variable_protocol import install_EFI_SMM_VARIABLE_PROTOCOL
from .guids import *
from qiling.os.uefi.utils import convert_struct_to_bytes

def init(ql):
    protocol_buf_size = 0x1000
    ptr = ql.os.heap.alloc(protocol_buf_size)
    ql.mem.write(ptr, b'\x90' * protocol_buf_size)

    smm_cpu_protocol_ptr = ptr
    (ptr, efi_smm_cpu_protocol) = install_EFI_SMM_CPU_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_CPU_PROTOCOL_GUID] = smm_cpu_protocol_ptr

    smm_sw_dispatch_protocol_ptr = ptr
    (ptr, smm_sw_dispatch_protocol) = install_EFI_SMM_SW_DISPATCH_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_SW_DISPATCH_PROTOCOL_GUID] = smm_sw_dispatch_protocol_ptr

    smm_sx_dispatch_protocol_ptr = ptr
    (ptr, smm_sx_dispatch_protocol) = install_EFI_SMM_SX_DISPATCH_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_SX_DISPATCH_PROTOCOL_GUID] = smm_sx_dispatch_protocol_ptr

    smm_base_protocol_ptr = ptr
    (ptr, smm_base_protocol) = install_EFI_SMM_BASE_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_BASE_PROTOCOL_GUID] = smm_base_protocol_ptr

    smm_variable_protocol_ptr = ptr
    (ptr, smm_variable_protocol) = install_EFI_SMM_VARIABLE_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_VARIABLE_PROTOCOL_GUID] = smm_variable_protocol_ptr

    ql.mem.write(smm_cpu_protocol_ptr, convert_struct_to_bytes(efi_smm_cpu_protocol))
    ql.mem.write(smm_sw_dispatch_protocol_ptr, convert_struct_to_bytes(smm_sw_dispatch_protocol))
    ql.mem.write(smm_sx_dispatch_protocol_ptr, convert_struct_to_bytes(smm_sx_dispatch_protocol))
    ql.mem.write(smm_base_protocol_ptr, convert_struct_to_bytes(smm_base_protocol))
    ql.mem.write(smm_variable_protocol_ptr, convert_struct_to_bytes(smm_variable_protocol))