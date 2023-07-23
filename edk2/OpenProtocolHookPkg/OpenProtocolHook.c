#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/PrintLib.h>

// // EFI_BOOT_SERVICES* ORG_EFI_BOOT_SERVICES;
EFI_OPEN_PROTOCOL ORG_OPEN_PROTOCOL;
EFI_EXIT_BOOT_SERVICES ORG_EXIT_BOOT_SERVICES;
int is_init;
// UINTN IsExitBootService;

EFI_STATUS EFIAPI OpenProtocolHook (
  IN  EFI_HANDLE  Handle,
  IN  EFI_GUID    *Protocol,
  OUT VOID        **Interface OPTIONAL,
  IN  EFI_HANDLE  ImageHandle,
  IN  EFI_HANDLE  ControllerHandle,
  IN  UINT32      Attributes
  )
  {
  EFI_STATUS status;
//   Get counter
  UINTN call_count;
  UINTN Size = sizeof(call_count);
  gRT->GetVariable(
        L"OpenProtocolCounter",
        &gFatCallGraph,
        NULL,
        &Size,
        &call_count);
  // Increase counter
  call_count++;
  gRT->SetVariable(
        L"OpenProtocolCounter",
        &gFatCallGraph,
        (EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS),
        Size,
        &call_count);
  // Log guid in nvram var
  CHAR16 id[50];
  UnicodeSPrint(id, sizeof(id), L"OpenProtocol-%d", call_count);
  UINTN GuidSize = sizeof(EFI_GUID);
//   UINT8 GuidBuffer[GuidSize];
//   CopyMem(GuidBuffer, Protocol, GuidSize);


  gRT->SetVariable(
        id,
        &gFatCallGraph,
        (EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS),
        GuidSize,
        Protocol);
  if (call_count == 150) {
    gBS->OpenProtocol = ORG_OPEN_PROTOCOL;
  }

  // Call original OpenProtocol func
  status = ORG_OPEN_PROTOCOL(Handle, Protocol, Interface, ImageHandle, ControllerHandle, Attributes);
  return status;
  }

EFI_STATUS EFIAPI ExitBootServicesHook(
    IN EFI_HANDLE Handle,
    IN UINTN MapKey)
{
  // Restore org pointer
  gBS->ExitBootServices = ORG_EXIT_BOOT_SERVICES;
  gBS->OpenProtocol = ORG_OPEN_PROTOCOL;
  return ORG_EXIT_BOOT_SERVICES(Handle, MapKey);
}


EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_STATUS Status = EFI_SUCCESS;

  UINTN call_count = 0;
  UINTN Size = sizeof(call_count);
  gRT->SetVariable(
        L"OpenProtocolCounter",
        &gFatCallGraph,
        (EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS),
        Size,
        &call_count);


  UINTN call_count2 = 50;
  gRT->SetVariable(
        L"OpenProtocolCounter2",
        &gFatCallGraph,
        (EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS),
        Size,
        &call_count2);


  // Save org
  if (is_init != 1) {
    ORG_OPEN_PROTOCOL = gBS->OpenProtocol;

    // Replace
    gBS->OpenProtocol = OpenProtocolHook;

    // Save org
  ORG_EXIT_BOOT_SERVICES = gBS->ExitBootServices;
  // Replace
  gBS->ExitBootServices = ExitBootServicesHook;
    
    is_init = 1;
  }

  return Status;
}