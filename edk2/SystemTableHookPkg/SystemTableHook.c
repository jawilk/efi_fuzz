#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

// EFI_BOOT_SERVICES* ORG_EFI_BOOT_SERVICES;
// EFI_OPEN_PROTOCOL ORG_EFI_OPEN_PROTOCOL;
EFI_EXIT_BOOT_SERVICES ORG_EXIT_BOOT_SERVICES;
UINTN IsExitBootService;

EFI_STATUS EFIAPI ExitBootServicesHook(
    IN EFI_HANDLE Handle,
    IN UINTN MapKey)
{
  // Restore org pointer
  gBS->ExitBootServices = ORG_EXIT_BOOT_SERVICES;

  // EFI_STATUS Status;

  UINTN is_after = 1;
  UINTN Size;
  Size = sizeof(is_after);
  // gRT->SetVariable(
  //     L"FatIsExitBootService2",
  //     &gFatCallGraph,
  //     (EFI_VARIABLE_NON_VOLATILE |
  //      EFI_VARIABLE_BOOTSERVICE_ACCESS |
  //      EFI_VARIABLE_RUNTIME_ACCESS),
  //     Size,
  //     &IsExitBootService);

  // Normal
  gRT->SetVariable(
      L"FatIsExitBootService",
      &gFatCallGraph,
      (EFI_VARIABLE_NON_VOLATILE |
       EFI_VARIABLE_BOOTSERVICE_ACCESS |
       EFI_VARIABLE_RUNTIME_ACCESS),
      Size,
      &is_after);

  return ORG_EXIT_BOOT_SERVICES(Handle, MapKey);
}

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_STATUS Status = EFI_SUCCESS;

  // Print(L"HELLO FROM UEFI DRIVER\n");
  // SystemTable->BootServices->Stall(10000000);

  // SystemTable->ConOut->OutputString (SystemTable->ConOut, L"Hello world\n\r");

  // UINT32 FatStartCounter;
  // char *FatStartCounter = "Hello FAT0";

  // UINTN  Size;
  // Size   = sizeof (FatStartCounter);
  // Status = gRT->SetVariable(
  //     L"FatOpenProtocolHook",
  //     &gFatOpenProtocolHook,
  //     (EFI_VARIABLE_BOOTSERVICE_ACCESS |
  //      EFI_VARIABLE_RUNTIME_ACCESS),
  //     10,
  //     FatStartCounter);

  // UINTN is_exit_boot_services;
  // UINTN Size = sizeof(is_exit_boot_services);
  // Status = gRT->GetVariable(
  //     L"FatIsExitBootService2",
  //     &gFatCallGraph,
  //     NULL,
  //     &Size,
  //     &is_exit_boot_services);

  // is_exit_boot_services++;
  // // UINTN  Size;
  // // Size   = sizeof (IsExitBootService);
  // Status = gRT->SetVariable(
  //     L"FatIsExitBootService2",
  //     &gFatCallGraph,
  //     (EFI_VARIABLE_NON_VOLATILE |
  //      EFI_VARIABLE_BOOTSERVICE_ACCESS |
  //      EFI_VARIABLE_RUNTIME_ACCESS),
  //     Size,
  //     &is_exit_boot_services);

  // ORG_EFI_BOOT_SERVICES = SystemTable->BootServices;

  // EFI_OPEN_PROTOCOL* op = ORG_EFI_BOOT_SERVICES->OpenProtocol;
  // bs->OpenProtocol = &EFI_OPEN_PROTOCOL_HOOK;

  // Save org
  ORG_EXIT_BOOT_SERVICES = gBS->ExitBootServices;
  // Replace
  gBS->ExitBootServices = ExitBootServicesHook;

  return Status;
}