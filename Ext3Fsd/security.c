/*
* COPYRIGHT:        See COPYRIGHT.TXT
* PROJECT:          Ext2 File System Driver for Windows >= NT
* FILE:             security.c
* PROGRAMMER:       Matt Wu <mattwu@163.com>  Kaho Ng <ngkaho1234@gmail.com>
* HOMEPAGE:         http://www.ext2fsd.com
* UPDATE HISTORY:
*/

#include <ext2fs.h>
#include <linux/ext4_xattr.h>

NTSTATUS Ext2QuerySecurity(
    IN PEXT2_IRP_CONTEXT    IrpContext
)
{
    PIRP                Irp = NULL;
    PIO_STACK_LOCATION  IrpSp;

    PDEVICE_OBJECT      DeviceObject;

    PEXT2_VCB           Vcb = NULL;
    PEXT2_FCB           Fcb = NULL;
    PEXT2_CCB           Ccb = NULL;
    PEXT2_MCB           Mcb = NULL;

    struct ext4_xattr_ref xattr_ref;

    PSECURITY_DESCRIPTOR *SecurityDescriptor;

    __try {

        Ccb = IrpContext->Ccb;
        ASSERT(Ccb != NULL);
        ASSERT((Ccb->Identifier.Type == EXT2CCB) &&
            (Ccb->Identifier.Size == sizeof(EXT2_CCB)));
        DeviceObject = IrpContext->DeviceObject;
        Vcb = (PEXT2_VCB)DeviceObject->DeviceExtension;
        Fcb = IrpContext->Fcb;
        Mcb = Fcb->Mcb;
        Irp = IrpContext->Irp;
        IrpSp = IoGetCurrentIrpStackLocation(Irp);

    } __finally {
    
    }
}

NTSTATUS Ext2SetSecurity(
    IN PEXT2_IRP_CONTEXT    IrpContext
)
{
    PIRP                Irp = NULL;
    PIO_STACK_LOCATION  IrpSp;

    PDEVICE_OBJECT      DeviceObject;

    PEXT2_VCB           Vcb = NULL;
    PEXT2_FCB           Fcb = NULL;
    PEXT2_CCB           Ccb = NULL;
    PEXT2_MCB           Mcb = NULL;

    struct ext4_xattr_ref xattr_ref;

    PSECURITY_DESCRIPTOR *SecurityDescriptor;

    __try {

        Ccb = IrpContext->Ccb;
        ASSERT(Ccb != NULL);
        ASSERT((Ccb->Identifier.Type == EXT2CCB) &&
            (Ccb->Identifier.Size == sizeof(EXT2_CCB)));
        DeviceObject = IrpContext->DeviceObject;
        Vcb = (PEXT2_VCB)DeviceObject->DeviceExtension;
        Fcb = IrpContext->Fcb;
        Mcb = Fcb->Mcb;
        Irp = IrpContext->Irp;
        IrpSp = IoGetCurrentIrpStackLocation(Irp);

    } __finally {

    }
}