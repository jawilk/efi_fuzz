#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DiskIo.h>
#include <Protocol/DiskIo2.h>


EFI_STATUS
EFIAPI FakeControllerReadDisk(
  IN EFI_DISK_IO_PROTOCOL         *This,
  IN UINT32                       MediaId,
  IN UINT64                       Offset,
  IN UINTN                        BufferSize,
  OUT VOID                        *Buffer
  ) {
  EFI_STATUS Status;
  Status = 0;  

  return Status;
}

EFI_STATUS
EFIAPI FakeControllerWriteDisk(
  IN EFI_DISK_IO_PROTOCOL         *This,
  IN UINT32                       MediaId,
  IN UINT64                       Offset,
  IN UINTN                        BufferSize,
  OUT VOID                        *Buffer
  ) {
  //EFI_STATUS Status;
    
    
  //return Status;
  return 0; 
}

EFI_BLOCK_IO_PROTOCOL gBlockIoProtocol;
GLOBAL_REMOVE_IF_UNREFERENCED EFI_DISK_IO_PROTOCOL gDiskIoProtocol = {
  0,
  FakeControllerReadDisk,
  FakeControllerWriteDisk
};
EFI_DISK_IO2_PROTOCOL gDiskIo2Protocol;


EFI_STATUS EFIAPI UefiMain (IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE  *SystemTable) {
  EFI_STATUS Status;
  
  Status = gBS->InstallProtocolInterface(
    &ImageHandle,
    &gEfiBlockIoProtocolGuid,
    EFI_NATIVE_INTERFACE,
    &gBlockIoProtocol
  );

    Status = gBS->InstallProtocolInterface(
    &ImageHandle,
    &gEfiDiskIoProtocolGuid,
    EFI_NATIVE_INTERFACE,
    &gDiskIoProtocol
  );

  Status = gBS->InstallProtocolInterface(
    &ImageHandle,
    &gEfiDiskIo2ProtocolGuid,
    EFI_NATIVE_INTERFACE,
    &gDiskIo2Protocol
  );

  return Status;
}