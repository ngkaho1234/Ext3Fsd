#include "ext2fs.h"

int Ext2CheckPermission(PEXT2_MCB Mcb)
{
    int Permission = 0;
    u16 Uid = (u16)Ext2Global->MountAsUid;
    u16 Gid = (u16)Ext2Global->MountAsGid;
    
    if (!Uid || Uid == Mcb->Inode.i_uid) {
        /* Seems I am the owner of this file, or if my Uid is 0. */
        Permission = Ext2FileCanRead | Ext2FileCanWrite;
    } else if (Gid == Mcb->Inode.i_gid) {
        if (Ext2IsGroupReadOnly(Mcb->Inode.i_mode))
            Permission = Ext2FileCanRead;
        else if (Ext2IsGroupWritable(Mcb->Inode.i_mode))
            Permission = Ext2FileCanRead | Ext2FileCanWrite;

    } else {
        if (Ext2IsOtherReadOnly(Mcb->Inode.i_mode))
            Permission = Ext2FileCanRead;
        else if (Ext2IsOtherWritable(Mcb->Inode.i_mode))
            Permission = Ext2FileCanRead | Ext2FileCanWrite;

    }
    return Permission;
}
