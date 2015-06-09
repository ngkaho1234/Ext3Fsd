#include "ext2fs.h"

int Ext2CheckPermissionInode(PEXT2_VCB Vcb, struct inode *inode)
{
    int Permission = 0;
    uid_t Uid = (uid_t)Vcb->MountAsUid;
    gid_t Gid = (gid_t)Vcb->MountAsGid;

    if (!Uid || Uid == inode->i_uid) {
        /* Seems I am the owner of this file, or if my Uid is 0. */
        Permission = Ext2FileCanRead | Ext2FileCanWrite | Ext2FileCanExecute;
    } else if (Gid == inode->i_gid) {
        if (Ext2IsGroupReadOnly(inode->i_mode))
            Permission = Ext2FileCanRead | Ext2FileCanExecute;
        else if (Ext2IsGroupWritable(inode->i_mode))
            Permission = Ext2FileCanRead | Ext2FileCanWrite | Ext2FileCanExecute;

    } else {
        if (Ext2IsOtherReadOnly(inode->i_mode))
            Permission = Ext2FileCanRead | Ext2FileCanExecute;
        else if (Ext2IsOtherWritable(inode->i_mode))
            Permission = Ext2FileCanRead | Ext2FileCanWrite | Ext2FileCanExecute;

    }
    return Permission;
}

int Ext2CheckPermission(PEXT2_VCB Vcb, PEXT2_MCB Mcb)
{
    return Ext2CheckPermissionInode(Vcb, &Mcb->Inode);
}
