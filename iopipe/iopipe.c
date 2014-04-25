/*
    ImDisk Virtual Disk Driver for Windows NT/2000/XP.
    This driver emulates harddisk partitions, floppy drives and CD/DVD-ROM
    drives from disk image files, in virtual memory or by redirecting I/O
    requests somewhere else, possibly to another machine, through a
    co-operating user-mode service, ImDskSvc.

    Copyright (C) 2005-2011 Olof Lagerkvist.

    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use,
    copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following
    conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
    OTHER DEALINGS IN THE SOFTWARE.

    This source file contains some GNU GPL licensed code:
    - Parts related to floppy emulation based on VFD by Ken Kato.
      http://chitchat.at.infoseek.co.jp/vmware/vfd.html
    Copyright (C) Free Software Foundation, Inc.
    Read gpl.txt for the full GNU GPL license.

    This source file may contain BSD licensed code:
    - Some code ported to NT from the FreeBSD md driver by Olof Lagerkvist.
      http://www.ltr-data.se
    Copyright (C) The FreeBSD Project.
    Copyright (C) The Regents of the University of California.
*/

#include <ntddk.h>
#include <ntverp.h>

#include "..\inc\ntkmapi.h"

///
/// Definitions and imports are now in the "sources" file and managed by the
/// build utility.
///

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

#if DEBUG_LEVEL >= 2
#define KdPrint2(x) DbgPrint x
#else
#define KdPrint2(x)
#endif

#if DEBUG_LEVEL >= 1
#undef KdPrint
#define KdPrint(x)  DbgPrint x
#endif

#define POOL_TAG                'PIOC'

#define FILE_DEVICE_IMDISK      0x8372

#define IOPIPE_DEVICE_NAME    L"\\Device\\IOPipe"
#define IOPIPE_SYMLINK_NAME   L"\\DosDevices\\IOPipe"

struct _OBJECT_CONTEXT;
typedef struct _OBJECT_CONTEXT OBJECT_CONTEXT, *POBJECT_CONTEXT;

struct _OBJECT_CONTEXT
{
  UNICODE_STRING FileName;

  LONG ReferenceCount;

  LIST_ENTRY ListHead;

  KSPIN_LOCK ListLock;

  KEVENT RequestEvent;

  BOOLEAN Used;

  POBJECT_CONTEXT NextObjectContext;

};

KSEMAPHORE ListLock;

POBJECT_CONTEXT ObjectContext;

// Prototypes for functions defined in this driver

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject,
	    IN PUNICODE_STRING RegistryPath);

VOID
IOPipeUnload(IN PDRIVER_OBJECT DriverObject);

NTSTATUS
IOPipeCreate(IN PDEVICE_OBJECT DeviceObject,
	     IN PIRP Irp);

NTSTATUS
IOPipeClose(IN PDEVICE_OBJECT DeviceObject,
	    IN PIRP Irp);

NTSTATUS
IOPipeQueryInformation(IN PDEVICE_OBJECT DeviceObject,
		       IN PIRP Irp);

NTSTATUS
IOPipeSetInformation(IN PDEVICE_OBJECT DeviceObject,
		     IN PIRP Irp);

NTSTATUS
IOPipeRead(IN PDEVICE_OBJECT DeviceObject,
	   IN PIRP Irp);
NTSTATUS
IOPipeWrite(IN PDEVICE_OBJECT DeviceObject,
	    IN PIRP Irp);

#pragma code_seg("INIT")

//
// This is where it all starts...
//
NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject,
	    IN PUNICODE_STRING RegistryPath)
{
  NTSTATUS status;
  PDEVICE_OBJECT device_object;
  UNICODE_STRING ctl_device_name;
  UNICODE_STRING sym_link;

  MmPageEntireDriver((PVOID)(ULONG_PTR)DriverEntry);

  KeInitializeSemaphore(&ListLock, 1, 1);

  ObjectContext = NULL;

  // Create the control device.
  RtlInitUnicodeString(&ctl_device_name, IOPIPE_DEVICE_NAME);

  status = IoCreateDevice(DriverObject,
			  0,
			  &ctl_device_name,
			  FILE_DEVICE_IMDISK,
			  0,
			  FALSE,
			  &device_object);

  if (!NT_SUCCESS(status))
    return status;

  device_object->Flags |= DO_DIRECT_IO;

  RtlInitUnicodeString(&sym_link, IOPIPE_SYMLINK_NAME);
  IoCreateUnprotectedSymbolicLink(&sym_link, &ctl_device_name);

  DriverObject->MajorFunction[IRP_MJ_CREATE] = IOPipeCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = IOPipeClose;
  DriverObject->MajorFunction[IRP_MJ_READ] = IOPipeRead;
  DriverObject->MajorFunction[IRP_MJ_WRITE] = IOPipeWrite;
  DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] =
    IOPipeQueryInformation;
  DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = IOPipeSetInformation;

  DriverObject->DriverUnload = IOPipeUnload;

  KdPrint(("IOPipe: Initialization done. Leaving DriverEntry().\n", status));

  return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")

NTSTATUS
IOPipeCreate(IN PDEVICE_OBJECT DeviceObject,
	     IN PIRP Irp)
{
  PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(Irp);
  NTSTATUS status;
  POBJECT_CONTEXT context = NULL;
  POBJECT_CONTEXT found_context = NULL;

  KdPrint(("IOPipe: Create.\n"));

  PAGED_CODE();

  if (io_stack->FileObject->FileName.Length == 0)
    {
      KdPrint(("IOPipe: No filename specified.\n"));

      status = STATUS_OBJECT_NAME_NOT_FOUND;

      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT); 
      return status;
    }

  KdPrint(("IOPipe: Request to open file '%.*ws'.\n",
	   io_stack->FileObject->FileName.Length /
	   sizeof(*io_stack->FileObject->FileName.Buffer),
	   io_stack->FileObject->FileName.Buffer));

  status =
    KeWaitForSingleObject(&ListLock, Executive, KernelMode, FALSE, NULL);
  if (!NT_SUCCESS(status))
    {
      KdPrint(("IOPipe: Error waiting for semaphore: %#x.\n", status));

      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT); 
      return status;
    }

  for (found_context = ObjectContext;
       found_context != NULL;
       found_context = found_context->NextObjectContext)
    if (RtlEqualUnicodeString(&io_stack->FileObject->FileName,
			      &found_context->FileName,
			      TRUE))
      {
	if (found_context->ReferenceCount >= 200)
	  {
	    KdPrint(("IOPipe: File name '%.*ws' is busy.\n",
		     io_stack->FileObject->FileName.Length /
		     sizeof(*io_stack->FileObject->FileName.Buffer),
		     io_stack->FileObject->FileName.Buffer));

	    KeReleaseSemaphore(&ListLock, (KPRIORITY) 0, 1, FALSE);

	    status = STATUS_ACCESS_DENIED;

	    Irp->IoStatus.Status = status;
	    Irp->IoStatus.Information = 0;
	    IoCompleteRequest(Irp, IO_NO_INCREMENT); 
	    return status;
	  }

	KdPrint(("IOPipe: Found existing file name '%.*ws'.\n",
		 io_stack->FileObject->FileName.Length /
		 sizeof(*io_stack->FileObject->FileName.Buffer),
		 io_stack->FileObject->FileName.Buffer));

	context = found_context;
	break;
      }

  if (context == NULL)
    {
      KdPrint(("IOPipe: Not found, creating file name '%.*ws'.\n",
	       io_stack->FileObject->FileName.Length /
	       sizeof(*io_stack->FileObject->FileName.Buffer),
	       io_stack->FileObject->FileName.Buffer));

      context =
	ExAllocatePoolWithTag(NonPagedPool, sizeof(OBJECT_CONTEXT), POOL_TAG);

      if (context == NULL)
	{
	  KdPrint(("IOPipe: Error allocating buffer for context.\n"));

	  status = STATUS_INSUFFICIENT_RESOURCES;
	}
      else
	{
	  RtlZeroMemory(context, sizeof(OBJECT_CONTEXT));

	  status = RtlUpcaseUnicodeString(&context->FileName,
					  &io_stack->FileObject->FileName,
					  TRUE);

	  if (!NT_SUCCESS(status))
	    {
	      KdPrint(("IOPipe: Error allocating buffer for file name: %#x.\n",
		       status));

	      ExFreePool(context);
	      context = NULL;
	    }
	  else
	    {
	      InitializeListHead(&context->ListHead);

	      KeInitializeSpinLock(&context->ListLock);

	      KeInitializeEvent(&context->RequestEvent,
				SynchronizationEvent, FALSE);
      
	      context->NextObjectContext = ObjectContext;

	      ObjectContext = context;
	    }
	}
    }

  if (context != NULL)
    {
      status = STATUS_SUCCESS;
      ++context->ReferenceCount;
      io_stack->FileObject->FsContext = context;

      KdPrint(("IOPipe: Setting context of handle to object: %#x\n"
	       "IOPipe: Reference count is: %i\n",
	       context,
	       context->ReferenceCount));
    }

  KeReleaseSemaphore(&ListLock, (KPRIORITY) 0, 1, FALSE);

  MmResetDriverPaging((PVOID)(ULONG_PTR)DriverEntry);

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return status;
}

NTSTATUS
IOPipeClose(IN PDEVICE_OBJECT DeviceObject,
	    IN PIRP Irp)
{
  PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(Irp);
  POBJECT_CONTEXT context = io_stack->FileObject->FsContext;
  NTSTATUS status;
  
  KdPrint(("IOPipe: Object %#x, file name '%.*ws' close request.\n",
	   context,
	   io_stack->FileObject->FileName.Length /
	   sizeof(*io_stack->FileObject->FileName.Buffer),
	   io_stack->FileObject->FileName.Buffer));

  PAGED_CODE();

  if (context != NULL)
    {
      KdPrint(("IOPipe: Waiting for list lock.\n"));

      status =
	KeWaitForSingleObject(&ListLock, Executive, KernelMode, FALSE, NULL);
      if (!NT_SUCCESS(status))
	{
	  Irp->IoStatus.Status = status;
	  Irp->IoStatus.Information = 0;
	  IoCompleteRequest(Irp, IO_NO_INCREMENT); 
	  return status;
	}

      --context->ReferenceCount;

      KdPrint(("IOPipe: Reference counter is %i.\n", context->ReferenceCount));

      KdPrint(("IOPipe: Cancelling requests.\n"));

      for (;;)
	{
	  PIRP pending_irp;
	  PLIST_ENTRY request =
	    ExInterlockedRemoveHeadList(&context->ListHead,
					&context->ListLock);

	  if (request == NULL)
	    break;

	  pending_irp =
	    CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

	  pending_irp->IoStatus.Status = STATUS_SUCCESS;
	  pending_irp->IoStatus.Information = 0;
	  IoCompleteRequest(pending_irp, IO_NO_INCREMENT); 
	}

      if (context->ReferenceCount <= 0)
	{
	  POBJECT_CONTEXT *ptr;

	  for (ptr = &ObjectContext;
	       *ptr != NULL;
	       ptr = &(*ptr)->NextObjectContext)
	    if (*ptr == context)
	      {
		*ptr = context->NextObjectContext;
		break;
	      }

	  KdPrint(("IOPipe: Freeing object data.\n"));

	  RtlFreeUnicodeString(&context->FileName);

	  ExFreePool(context);
	}

      if (ObjectContext == NULL)
	MmPageEntireDriver((PVOID)(ULONG_PTR)DriverEntry);

      KeReleaseSemaphore(&ListLock, (KPRIORITY) 0, 1, FALSE);
    }

  KdPrint(("IOPipe: Closed successfully.\n"));

  status = STATUS_SUCCESS;

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT); 

  return status;
}

NTSTATUS
IOPipeQueryInformation(IN PDEVICE_OBJECT DeviceObject,
			 IN PIRP Irp)
{
  PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(Irp);

  PAGED_CODE();

  KdPrint2(("IOPipe: QueryFileInformation: %u.\n",
	    io_stack->Parameters.QueryFile.FileInformationClass));

  RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer,
		io_stack->Parameters.QueryFile.Length);

  switch (io_stack->Parameters.QueryFile.FileInformationClass)
    {
    case FileAlignmentInformation:
      {
	PFILE_ALIGNMENT_INFORMATION alignment_info =
	  (PFILE_ALIGNMENT_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

	if (io_stack->Parameters.QueryFile.Length <
	    sizeof(FILE_ALIGNMENT_INFORMATION))
	  {
	    Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	    Irp->IoStatus.Information = 0;
	    IoCompleteRequest(Irp, IO_NO_INCREMENT);
	    return STATUS_INVALID_PARAMETER;
	  }

	alignment_info->AlignmentRequirement = FILE_BYTE_ALIGNMENT;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(FILE_ALIGNMENT_INFORMATION);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
      }

    case FileAttributeTagInformation:
    case FileBasicInformation:
    case FileInternalInformation:
      Irp->IoStatus.Status = STATUS_SUCCESS;
      Irp->IoStatus.Information = io_stack->Parameters.QueryFile.Length;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;

    default:
      KdPrint(("IOPipe: Unsupported QueryFile.FileInformationClass: %u\n",
	       io_stack->Parameters.QueryFile.FileInformationClass));

      Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      return STATUS_INVALID_DEVICE_REQUEST;
    }
}

NTSTATUS
IOPipeSetInformation(IN PDEVICE_OBJECT DeviceObject,
		       IN PIRP Irp)
{
  PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(Irp);

  PAGED_CODE();

  KdPrint2(("IOPipe: SetFileInformation: %u.\n",
	    io_stack->Parameters.SetFile.FileInformationClass));

  switch (io_stack->Parameters.SetFile.FileInformationClass)
    {
    case FileBasicInformation:
    case FileDispositionInformation:
    case FileValidDataLengthInformation:
      Irp->IoStatus.Status = STATUS_SUCCESS;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;

    default:
      KdPrint(("IOPipe: Unsupported SetFile.FileInformationClass: %u\n",
	       io_stack->Parameters.SetFile.FileInformationClass));

      Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      return STATUS_INVALID_DEVICE_REQUEST;
    }
}

VOID
IOPipeUnload(IN PDRIVER_OBJECT DriverObject)
{
  PDEVICE_OBJECT device_object = DriverObject->DeviceObject;
  UNICODE_STRING sym_link;

  KdPrint(("IOPipe: Unload.\n"));

  PAGED_CODE();

  RtlInitUnicodeString(&sym_link, IOPIPE_SYMLINK_NAME);
  IoDeleteSymbolicLink(&sym_link);

  while (device_object != NULL)
    {
      PDEVICE_OBJECT next_device = device_object->NextDevice;
      IoDeleteDevice(device_object);
      device_object = next_device;
    }
}

#pragma code_seg()

VOID
IOPipeCancel(IN PDEVICE_OBJECT DeviceObject,
	     IN PIRP Irp)
{
  PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(Irp);
  POBJECT_CONTEXT context = io_stack->FileObject->FsContext;

  IoReleaseCancelSpinLock(Irp->CancelIrql);

  KdPrint2(("IOPipe: Cancel req context=%#x Offset=%p%p Len=%p Minor=%u.\n",
	    context,
	    io_stack->Parameters.Read.ByteOffset.HighPart,
	    io_stack->Parameters.Read.ByteOffset.LowPart,
	    io_stack->Parameters.Read.Length,
	    io_stack->MinorFunction));

  KeSetEvent(&context->RequestEvent, (KPRIORITY) 0, FALSE);

  return;
}

NTSTATUS
IOPipeRead(IN PDEVICE_OBJECT DeviceObject,
	   IN PIRP Irp)
{
  PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(Irp);
  POBJECT_CONTEXT context = io_stack->FileObject->FsContext;
  NTSTATUS status;

  KdPrint2(("IOPipe: Read request context=%#x Offset=%p%p Len=%p Minor=%u.\n",
	    context,
	    io_stack->Parameters.Read.ByteOffset.HighPart,
	    io_stack->Parameters.Read.ByteOffset.LowPart,
	    io_stack->Parameters.Read.Length,
	    io_stack->MinorFunction));

  if (context == NULL)
    {
      KdPrint(("IOPipe: Read request for uninitialized file name '%.*ws'.\n",
	       io_stack->FileObject->FileName.Length /
	       sizeof(*io_stack->FileObject->FileName.Buffer),
	       io_stack->FileObject->FileName.Buffer));

      status = STATUS_NO_MEDIA_IN_DEVICE;

      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;

      IoCompleteRequest(Irp, IO_NO_INCREMENT);

      return status;
    }

  if (context->Used && (context->ReferenceCount < 2))
    {
      KdPrint(("IOPipe: Read request for not connected file name '%.*ws'.\n",
	       io_stack->FileObject->FileName.Length /
	       sizeof(*io_stack->FileObject->FileName.Buffer),
	       io_stack->FileObject->FileName.Buffer));

      status = STATUS_PIPE_DISCONNECTED;

      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;

      IoCompleteRequest(Irp, IO_NO_INCREMENT);

      return status;
    }

  context->Used = TRUE;

  IoSetCancelRoutine(Irp, IOPipeCancel);

  IoMarkIrpPending(Irp);

  ExInterlockedInsertTailList(&context->ListHead,
			      &Irp->Tail.Overlay.ListEntry,
			      &context->ListLock);
  
  KeSetEvent(&context->RequestEvent, (KPRIORITY) 0, FALSE);

  return STATUS_PENDING;
}

NTSTATUS
IOPipeWrite(IN PDEVICE_OBJECT DeviceObject,
	    IN PIRP Irp)
{
  PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(Irp);
  ULONG pending_write_length = io_stack->Parameters.Write.Length;
  ULONG bytes_written = 0;
  POBJECT_CONTEXT context = io_stack->FileObject->FsContext;
  NTSTATUS status;
  PVOID system_buffer;

  // This IOCTL requires work that must be done at IRQL < DISPATCH_LEVEL
  // but must be done in the thread context of the calling application and
  // not by the worker thread so therefore this check is done. Also, the
  // control device does not have a worker thread so that is another
  // reason.
  if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
      status = STATUS_ACCESS_DENIED;

      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT); 
      return status;
    }

  KdPrint2(("IOPipe: Write request context=%#x Offset=%p%p Len=%p Minor=%u.\n",
	    context,
	    io_stack->Parameters.Read.ByteOffset.HighPart,
	    io_stack->Parameters.Read.ByteOffset.LowPart,
	    io_stack->Parameters.Read.Length,
	    io_stack->MinorFunction));

  if (context == NULL)
    {
      KdPrint(("IOPipe: Write request for uninitialized file name '%.*ws'.\n",
	       io_stack->FileObject->FileName.Length /
	       sizeof(*io_stack->FileObject->FileName.Buffer),
	       io_stack->FileObject->FileName.Buffer));

      status = STATUS_NO_MEDIA_IN_DEVICE;

      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;

      IoCompleteRequest(Irp, IO_NO_INCREMENT);

      return status;
    }

  IoSetCancelRoutine(Irp, IOPipeCancel);

  system_buffer =
    MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);

  if (system_buffer == NULL)
    {
      KdPrint(("IOPipe: Failed mapping system buffer.\n"));

      status = STATUS_INSUFFICIENT_RESOURCES;

      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      return status;
    }

  while (pending_write_length > 0)
    {
      LARGE_INTEGER wait_time;
      PIRP pending_irp;
      PIO_STACK_LOCATION pending_io_stack;
      PVOID pending_system_buffer;
      PLIST_ENTRY request;

      for (;;)
	{
	  if (Irp->Cancel)
	    {
	      KdPrint(("IOPipe: Write operation cancelled.\n"));

	      status = STATUS_CANCELLED;

	      Irp->IoStatus.Status = status;
	      Irp->IoStatus.Information = 0;
	      IoCompleteRequest(Irp, IO_NO_INCREMENT);
	      return status;
	    }

	  KdPrint2(("IOPipe: Finding matching read request.\n"));

	  request =
	    ExInterlockedRemoveHeadList(&context->ListHead,
					&context->ListLock);

	  if (request != NULL)
	    break;

	  if (context->ReferenceCount < 2)
	    {
	      KdPrint(("IOPipe: No connected readers.\n"));

	      status = STATUS_PIPE_DISCONNECTED;

	      Irp->IoStatus.Status = status;
	      Irp->IoStatus.Information = 0;
	      IoCompleteRequest(Irp, IO_NO_INCREMENT);
	      return status;
	    }

	  wait_time.QuadPart = -1;
	  KeDelayExecutionThread(KernelMode, FALSE, &wait_time);

	  KeWaitForSingleObject(&context->RequestEvent,
				Executive,
				KernelMode,
				TRUE,
				NULL);
	}

      pending_irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

      if (pending_irp->Cancel)
	{
	  KdPrint(("IOPipe: Read operation cancelled.\n"));

	  status = STATUS_CANCELLED;

	  pending_irp->IoStatus.Status = status;
	  pending_irp->IoStatus.Information = 0;
	  IoCompleteRequest(pending_irp, IO_NO_INCREMENT);

	  Irp->IoStatus.Status = status;
	  Irp->IoStatus.Information = 0;
	  IoCompleteRequest(Irp, IO_NO_INCREMENT);
	  return status;
	}

      pending_io_stack = IoGetCurrentIrpStackLocation(pending_irp);

      KdPrint2(("IOPipe: Matching read request Offset=%p%p Len=%p Minor=%u.\n",
		pending_io_stack->Parameters.Read.ByteOffset.HighPart,
		pending_io_stack->Parameters.Read.ByteOffset.LowPart,
		pending_io_stack->Parameters.Read.Length,
		pending_io_stack->MinorFunction));

      pending_system_buffer =
	MmGetSystemAddressForMdlSafe(pending_irp->MdlAddress,
				     HighPagePriority);

      if (pending_system_buffer == NULL)
	{
	  KdPrint(("IOPipe: Failed mapping system buffer.\n"));

	  break;
	}

      if (pending_write_length < pending_io_stack->Parameters.Read.Length)
	pending_io_stack->Parameters.Read.Length = pending_write_length;

      RtlCopyMemory(pending_system_buffer,
		    ((PUCHAR)system_buffer) + bytes_written,
		    pending_io_stack->Parameters.Read.Length);

      pending_irp->IoStatus.Status = STATUS_SUCCESS;
      pending_irp->IoStatus.Information =
	pending_io_stack->Parameters.Read.Length;

      pending_write_length -= pending_io_stack->Parameters.Read.Length;
      bytes_written += pending_io_stack->Parameters.Read.Length;

      IoCompleteRequest(pending_irp, IO_NO_INCREMENT);

    }

  status = STATUS_SUCCESS;

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = bytes_written;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return status;
}
