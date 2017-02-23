/*
 * linux/fs/mockfs/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/time.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/random.h>
#include <linux/quotaops.h>
#include <asm/uaccess.h>
#include "mockfs_jbd2.h"
#include "mockfs.h"

#define MAX_32_NUM ((((unsigned long long) 1) << 32) - 1)

/**
 * Swap memory between @a and @b for @len bytes.
 *
 * @a:          pointer to first memory area
 * @b:          pointer to second memory area
 * @len:        number of bytes to swap
 *
 */
static void memswap(void *a, void *b, size_t len)
{
	unsigned char *ap, *bp;

	ap = (unsigned char *)a;
	bp = (unsigned char *)b;
	while (len-- > 0) {
		swap(*ap, *bp);
		ap++;
		bp++;
	}
}

/**
 * Swap i_data and associated attributes between @inode1 and @inode2.
 * This function is used for the primary swap between inode1 and inode2
 * and also to revert this primary swap in case of errors.
 *
 * Therefore you have to make sure, that calling this method twice
 * will revert all changes.
 *
 * @inode1:     pointer to first inode
 * @inode2:     pointer to second inode
 */
static void swap_inode_data(struct inode *inode1, struct inode *inode2)
{
	loff_t isize;
	struct mockfs_inode_info *ei1;
	struct mockfs_inode_info *ei2;

	ei1 = MOCKFS_I(inode1);
	ei2 = MOCKFS_I(inode2);

	memswap(&inode1->i_flags, &inode2->i_flags, sizeof(inode1->i_flags));
	memswap(&inode1->i_version, &inode2->i_version,
		  sizeof(inode1->i_version));
	memswap(&inode1->i_blocks, &inode2->i_blocks,
		  sizeof(inode1->i_blocks));
	memswap(&inode1->i_bytes, &inode2->i_bytes, sizeof(inode1->i_bytes));
	memswap(&inode1->i_atime, &inode2->i_atime, sizeof(inode1->i_atime));
	memswap(&inode1->i_mtime, &inode2->i_mtime, sizeof(inode1->i_mtime));

	memswap(ei1->i_data, ei2->i_data, sizeof(ei1->i_data));
	memswap(&ei1->i_flags, &ei2->i_flags, sizeof(ei1->i_flags));
	memswap(&ei1->i_disksize, &ei2->i_disksize, sizeof(ei1->i_disksize));
	mockfs_es_remove_extent(inode1, 0, EXT_MAX_BLOCKS);
	mockfs_es_remove_extent(inode2, 0, EXT_MAX_BLOCKS);

	isize = i_size_read(inode1);
	i_size_write(inode1, i_size_read(inode2));
	i_size_write(inode2, isize);
}

/**
 * Swap the information from the given @inode and the inode
 * MOCKFS_BOOT_LOADER_INO. It will basically swap i_data and all other
 * important fields of the inodes.
 *
 * @sb:         the super block of the filesystem
 * @inode:      the inode to swap with MOCKFS_BOOT_LOADER_INO
 *
 */
static long swap_inode_boot_loader(struct super_block *sb,
				struct inode *inode)
{
	handle_t *handle;
	int err;
	struct inode *inode_bl;
	struct mockfs_inode_info *ei_bl;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);

	if (inode->i_nlink != 1 || !S_ISREG(inode->i_mode))
		return -EINVAL;

	if (!inode_owner_or_capable(inode) || !capable(CAP_SYS_ADMIN))
		return -EPERM;

	inode_bl = mockfs_iget(sb, MOCKFS_BOOT_LOADER_INO);
	if (IS_ERR(inode_bl))
		return PTR_ERR(inode_bl);
	ei_bl = MOCKFS_I(inode_bl);

	filemap_flush(inode->i_mapping);
	filemap_flush(inode_bl->i_mapping);

	/* Protect orig inodes against a truncate and make sure,
	 * that only 1 swap_inode_boot_loader is running. */
	lock_two_nondirectories(inode, inode_bl);

	truncate_inode_pages(&inode->i_data, 0);
	truncate_inode_pages(&inode_bl->i_data, 0);

	/* Wait for all existing dio workers */
	mockfs_inode_block_unlocked_dio(inode);
	mockfs_inode_block_unlocked_dio(inode_bl);
	inode_dio_wait(inode);
	inode_dio_wait(inode_bl);

	handle = mockfs_journal_start(inode_bl, MOCKFS_HT_MOVE_EXTENTS, 2);
	if (IS_ERR(handle)) {
		err = -EINVAL;
		goto journal_err_out;
	}

	/* Protect extent tree against block allocations via delalloc */
	mockfs_double_down_write_data_sem(inode, inode_bl);

	if (inode_bl->i_nlink == 0) {
		/* this inode has never been used as a BOOT_LOADER */
		set_nlink(inode_bl, 1);
		i_uid_write(inode_bl, 0);
		i_gid_write(inode_bl, 0);
		inode_bl->i_flags = 0;
		ei_bl->i_flags = 0;
		inode_bl->i_version = 1;
		i_size_write(inode_bl, 0);
		inode_bl->i_mode = S_IFREG;
		if (mockfs_has_feature_extents(sb)) {
			mockfs_set_inode_flag(inode_bl, MOCKFS_INODE_EXTENTS);
			mockfs_ext_tree_init(handle, inode_bl);
		} else
			memset(ei_bl->i_data, 0, sizeof(ei_bl->i_data));
	}

	swap_inode_data(inode, inode_bl);

	inode->i_ctime = inode_bl->i_ctime = mockfs_current_time(inode);

	spin_lock(&sbi->s_next_gen_lock);
	inode->i_generation = sbi->s_next_generation++;
	inode_bl->i_generation = sbi->s_next_generation++;
	spin_unlock(&sbi->s_next_gen_lock);

	mockfs_discard_preallocations(inode);

	err = mockfs_mark_inode_dirty(handle, inode);
	if (err < 0) {
		mockfs_warning(inode->i_sb,
			"couldn't mark inode #%lu dirty (err %d)",
			inode->i_ino, err);
		/* Revert all changes: */
		swap_inode_data(inode, inode_bl);
	} else {
		err = mockfs_mark_inode_dirty(handle, inode_bl);
		if (err < 0) {
			mockfs_warning(inode_bl->i_sb,
				"couldn't mark inode #%lu dirty (err %d)",
				inode_bl->i_ino, err);
			/* Revert all changes: */
			swap_inode_data(inode, inode_bl);
			mockfs_mark_inode_dirty(handle, inode);
		}
	}
	mockfs_journal_stop(handle);
	mockfs_double_up_write_data_sem(inode, inode_bl);

journal_err_out:
	mockfs_inode_resume_unlocked_dio(inode);
	mockfs_inode_resume_unlocked_dio(inode_bl);
	unlock_two_nondirectories(inode, inode_bl);
	iput(inode_bl);
	return err;
}

static int uuid_is_zero(__u8 u[16])
{
	int	i;

	for (i = 0; i < 16; i++)
		if (u[i])
			return 0;
	return 1;
}

static int mockfs_ioctl_setflags(struct inode *inode,
			       unsigned int flags)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	handle_t *handle = NULL;
	int err = -EPERM, migrate = 0;
	struct mockfs_iloc iloc;
	unsigned int oldflags, mask, i;
	unsigned int jflag;

	/* Is it quota file? Do not allow user to mess with it */
	if (IS_NOQUOTA(inode))
		goto flags_out;

	oldflags = ei->i_flags;

	/* The JOURNAL_DATA flag is modifiable only by root */
	jflag = flags & MOCKFS_JOURNAL_DATA_FL;

	/*
	 * The IMMUTABLE and APPEND_ONLY flags can only be changed by
	 * the relevant capability.
	 *
	 * This test looks nicer. Thanks to Pauline Middelink
	 */
	if ((flags ^ oldflags) & (MOCKFS_APPEND_FL | MOCKFS_IMMUTABLE_FL)) {
		if (!capable(CAP_LINUX_IMMUTABLE))
			goto flags_out;
	}

	/*
	 * The JOURNAL_DATA flag can only be changed by
	 * the relevant capability.
	 */
	if ((jflag ^ oldflags) & (MOCKFS_JOURNAL_DATA_FL)) {
		if (!capable(CAP_SYS_RESOURCE))
			goto flags_out;
	}
	if ((flags ^ oldflags) & MOCKFS_EXTENTS_FL)
		migrate = 1;

	if (flags & MOCKFS_EOFBLOCKS_FL) {
		/* we don't support adding EOFBLOCKS flag */
		if (!(oldflags & MOCKFS_EOFBLOCKS_FL)) {
			err = -EOPNOTSUPP;
			goto flags_out;
		}
	} else if (oldflags & MOCKFS_EOFBLOCKS_FL)
		mockfs_truncate(inode);

	handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, 1);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto flags_out;
	}
	if (IS_SYNC(inode))
		mockfs_handle_sync(handle);
	err = mockfs_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto flags_err;

	for (i = 0, mask = 1; i < 32; i++, mask <<= 1) {
		if (!(mask & MOCKFS_FL_USER_MODIFIABLE))
			continue;
		if (mask & flags)
			mockfs_set_inode_flag(inode, i);
		else
			mockfs_clear_inode_flag(inode, i);
	}

	mockfs_set_inode_flags(inode);
	inode->i_ctime = mockfs_current_time(inode);

	err = mockfs_mark_iloc_dirty(handle, inode, &iloc);
flags_err:
	mockfs_journal_stop(handle);
	if (err)
		goto flags_out;

	if ((jflag ^ oldflags) & (MOCKFS_JOURNAL_DATA_FL))
		err = mockfs_change_inode_journal_flag(inode, jflag);
	if (err)
		goto flags_out;
	if (migrate) {
		if (flags & MOCKFS_EXTENTS_FL)
			err = mockfs_ext_migrate(inode);
		else
			err = mockfs_ind_migrate(inode);
	}

flags_out:
	return err;
}

#ifdef CONFIG_QUOTA
static int mockfs_ioctl_setproject(struct file *filp, __u32 projid)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	int err, rc;
	handle_t *handle;
	kprojid_t kprojid;
	struct mockfs_iloc iloc;
	struct mockfs_inode *raw_inode;

	if (!MOCKFS_HAS_RO_COMPAT_FEATURE(sb,
			MOCKFS_FEATURE_RO_COMPAT_PROJECT)) {
		if (projid != MOCKFS_DEF_PROJID)
			return -EOPNOTSUPP;
		else
			return 0;
	}

	if (MOCKFS_INODE_SIZE(sb) <= MOCKFS_GOOD_OLD_INODE_SIZE)
		return -EOPNOTSUPP;

	kprojid = make_kprojid(&init_user_ns, (projid_t)projid);

	if (projid_eq(kprojid, MOCKFS_I(inode)->i_projid))
		return 0;

	err = mnt_want_write_file(filp);
	if (err)
		return err;

	err = -EPERM;
	inode_lock(inode);
	/* Is it quota file? Do not allow user to mess with it */
	if (IS_NOQUOTA(inode))
		goto out_unlock;

	err = mockfs_get_inode_loc(inode, &iloc);
	if (err)
		goto out_unlock;

	raw_inode = mockfs_raw_inode(&iloc);
	if (!MOCKFS_FITS_IN_INODE(raw_inode, ei, i_projid)) {
		err = -EOVERFLOW;
		brelse(iloc.bh);
		goto out_unlock;
	}
	brelse(iloc.bh);

	dquot_initialize(inode);

	handle = mockfs_journal_start(inode, MOCKFS_HT_QUOTA,
		MOCKFS_QUOTA_INIT_BLOCKS(sb) +
		MOCKFS_QUOTA_DEL_BLOCKS(sb) + 3);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto out_unlock;
	}

	err = mockfs_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto out_stop;

	if (sb_has_quota_limits_enabled(sb, PRJQUOTA)) {
		struct dquot *transfer_to[MAXQUOTAS] = { };

		transfer_to[PRJQUOTA] = dqget(sb, make_kqid_projid(kprojid));
		if (transfer_to[PRJQUOTA]) {
			err = __dquot_transfer(inode, transfer_to);
			dqput(transfer_to[PRJQUOTA]);
			if (err)
				goto out_dirty;
		}
	}
	MOCKFS_I(inode)->i_projid = kprojid;
	inode->i_ctime = mockfs_current_time(inode);
out_dirty:
	rc = mockfs_mark_iloc_dirty(handle, inode, &iloc);
	if (!err)
		err = rc;
out_stop:
	mockfs_journal_stop(handle);
out_unlock:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return err;
}
#else
static int mockfs_ioctl_setproject(struct file *filp, __u32 projid)
{
	if (projid != MOCKFS_DEF_PROJID)
		return -EOPNOTSUPP;
	return 0;
}
#endif

/* Transfer internal flags to xflags */
static inline __u32 mockfs_iflags_to_xflags(unsigned long iflags)
{
	__u32 xflags = 0;

	if (iflags & MOCKFS_SYNC_FL)
		xflags |= FS_XFLAG_SYNC;
	if (iflags & MOCKFS_IMMUTABLE_FL)
		xflags |= FS_XFLAG_IMMUTABLE;
	if (iflags & MOCKFS_APPEND_FL)
		xflags |= FS_XFLAG_APPEND;
	if (iflags & MOCKFS_NODUMP_FL)
		xflags |= FS_XFLAG_NODUMP;
	if (iflags & MOCKFS_NOATIME_FL)
		xflags |= FS_XFLAG_NOATIME;
	if (iflags & MOCKFS_PROJINHERIT_FL)
		xflags |= FS_XFLAG_PROJINHERIT;
	return xflags;
}

/* Transfer xflags flags to internal */
static inline unsigned long mockfs_xflags_to_iflags(__u32 xflags)
{
	unsigned long iflags = 0;

	if (xflags & FS_XFLAG_SYNC)
		iflags |= MOCKFS_SYNC_FL;
	if (xflags & FS_XFLAG_IMMUTABLE)
		iflags |= MOCKFS_IMMUTABLE_FL;
	if (xflags & FS_XFLAG_APPEND)
		iflags |= MOCKFS_APPEND_FL;
	if (xflags & FS_XFLAG_NODUMP)
		iflags |= MOCKFS_NODUMP_FL;
	if (xflags & FS_XFLAG_NOATIME)
		iflags |= MOCKFS_NOATIME_FL;
	if (xflags & FS_XFLAG_PROJINHERIT)
		iflags |= MOCKFS_PROJINHERIT_FL;

	return iflags;
}

long mockfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	unsigned int flags;

	mockfs_debug("cmd = %u, arg = %lu\n", cmd, arg);

	switch (cmd) {
	case MOCKFS_IOC_GETFLAGS:
		mockfs_get_inode_flags(ei);
		flags = ei->i_flags & MOCKFS_FL_USER_VISIBLE;
		return put_user(flags, (int __user *) arg);
	case MOCKFS_IOC_SETFLAGS: {
		int err;

		if (!inode_owner_or_capable(inode))
			return -EACCES;

		if (get_user(flags, (int __user *) arg))
			return -EFAULT;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		flags = mockfs_mask_flags(inode->i_mode, flags);

		inode_lock(inode);
		err = mockfs_ioctl_setflags(inode, flags);
		inode_unlock(inode);
		mnt_drop_write_file(filp);
		return err;
	}
	case MOCKFS_IOC_GETVERSION:
	case MOCKFS_IOC_GETVERSION_OLD:
		return put_user(inode->i_generation, (int __user *) arg);
	case MOCKFS_IOC_SETVERSION:
	case MOCKFS_IOC_SETVERSION_OLD: {
		handle_t *handle;
		struct mockfs_iloc iloc;
		__u32 generation;
		int err;

		if (!inode_owner_or_capable(inode))
			return -EPERM;

		if (mockfs_has_metadata_csum(inode->i_sb)) {
			mockfs_warning(sb, "Setting inode version is not "
				     "supported with metadata_csum enabled.");
			return -ENOTTY;
		}

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		if (get_user(generation, (int __user *) arg)) {
			err = -EFAULT;
			goto setversion_out;
		}

		inode_lock(inode);
		handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, 1);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto unlock_out;
		}
		err = mockfs_reserve_inode_write(handle, inode, &iloc);
		if (err == 0) {
			inode->i_ctime = mockfs_current_time(inode);
			inode->i_generation = generation;
			err = mockfs_mark_iloc_dirty(handle, inode, &iloc);
		}
		mockfs_journal_stop(handle);

unlock_out:
		inode_unlock(inode);
setversion_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case MOCKFS_IOC_GROUP_EXTEND: {
		mockfs_fsblk_t n_blocks_count;
		int err, err2=0;

		err = mockfs_resize_begin(sb);
		if (err)
			return err;

		if (get_user(n_blocks_count, (__u32 __user *)arg)) {
			err = -EFAULT;
			goto group_extend_out;
		}

		if (mockfs_has_feature_bigalloc(sb)) {
			mockfs_msg(sb, KERN_ERR,
				 "Online resizing not supported with bigalloc");
			err = -EOPNOTSUPP;
			goto group_extend_out;
		}

		err = mnt_want_write_file(filp);
		if (err)
			goto group_extend_out;

		err = mockfs_group_extend(sb, MOCKFS_SB(sb)->s_es, n_blocks_count);
		if (MOCKFS_SB(sb)->s_journal) {
			jbd2_journal_lock_updates(MOCKFS_SB(sb)->s_journal);
			err2 = jbd2_journal_flush(MOCKFS_SB(sb)->s_journal);
			jbd2_journal_unlock_updates(MOCKFS_SB(sb)->s_journal);
		}
		if (err == 0)
			err = err2;
		mnt_drop_write_file(filp);
group_extend_out:
		mockfs_resize_end(sb);
		return err;
	}

	case MOCKFS_IOC_MOVE_EXT: {
		struct move_extent me;
		struct fd donor;
		int err;

		if (!(filp->f_mode & FMODE_READ) ||
		    !(filp->f_mode & FMODE_WRITE))
			return -EBADF;

		if (copy_from_user(&me,
			(struct move_extent __user *)arg, sizeof(me)))
			return -EFAULT;
		me.moved_len = 0;

		donor = fdget(me.donor_fd);
		if (!donor.file)
			return -EBADF;

		if (!(donor.file->f_mode & FMODE_WRITE)) {
			err = -EBADF;
			goto mext_out;
		}

		if (mockfs_has_feature_bigalloc(sb)) {
			mockfs_msg(sb, KERN_ERR,
				 "Online defrag not supported with bigalloc");
			err = -EOPNOTSUPP;
			goto mext_out;
		} else if (IS_DAX(inode)) {
			mockfs_msg(sb, KERN_ERR,
				 "Online defrag not supported with DAX");
			err = -EOPNOTSUPP;
			goto mext_out;
		}

		err = mnt_want_write_file(filp);
		if (err)
			goto mext_out;

		err = mockfs_move_extents(filp, donor.file, me.orig_start,
					me.donor_start, me.len, &me.moved_len);
		mnt_drop_write_file(filp);

		if (copy_to_user((struct move_extent __user *)arg,
				 &me, sizeof(me)))
			err = -EFAULT;
mext_out:
		fdput(donor);
		return err;
	}

	case MOCKFS_IOC_GROUP_ADD: {
		struct mockfs_new_group_data input;
		int err, err2=0;

		err = mockfs_resize_begin(sb);
		if (err)
			return err;

		if (copy_from_user(&input, (struct mockfs_new_group_input __user *)arg,
				sizeof(input))) {
			err = -EFAULT;
			goto group_add_out;
		}

		if (mockfs_has_feature_bigalloc(sb)) {
			mockfs_msg(sb, KERN_ERR,
				 "Online resizing not supported with bigalloc");
			err = -EOPNOTSUPP;
			goto group_add_out;
		}

		err = mnt_want_write_file(filp);
		if (err)
			goto group_add_out;

		err = mockfs_group_add(sb, &input);
		if (MOCKFS_SB(sb)->s_journal) {
			jbd2_journal_lock_updates(MOCKFS_SB(sb)->s_journal);
			err2 = jbd2_journal_flush(MOCKFS_SB(sb)->s_journal);
			jbd2_journal_unlock_updates(MOCKFS_SB(sb)->s_journal);
		}
		if (err == 0)
			err = err2;
		mnt_drop_write_file(filp);
		if (!err && mockfs_has_group_desc_csum(sb) &&
		    test_opt(sb, INIT_INODE_TABLE))
			err = mockfs_register_li_request(sb, input.group);
group_add_out:
		mockfs_resize_end(sb);
		return err;
	}

	case MOCKFS_IOC_MIGRATE:
	{
		int err;
		if (!inode_owner_or_capable(inode))
			return -EACCES;

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		/*
		 * inode_mutex prevent write and truncate on the file.
		 * Read still goes through. We take i_data_sem in
		 * mockfs_ext_swap_inode_data before we switch the
		 * inode format to prevent read.
		 */
		inode_lock((inode));
		err = mockfs_ext_migrate(inode);
		inode_unlock((inode));
		mnt_drop_write_file(filp);
		return err;
	}

	case MOCKFS_IOC_ALLOC_DA_BLKS:
	{
		int err;
		if (!inode_owner_or_capable(inode))
			return -EACCES;

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		err = mockfs_alloc_da_blocks(inode);
		mnt_drop_write_file(filp);
		return err;
	}

	case MOCKFS_IOC_SWAP_BOOT:
	{
		int err;
		if (!(filp->f_mode & FMODE_WRITE))
			return -EBADF;
		err = mnt_want_write_file(filp);
		if (err)
			return err;
		err = swap_inode_boot_loader(sb, inode);
		mnt_drop_write_file(filp);
		return err;
	}

	case MOCKFS_IOC_RESIZE_FS: {
		mockfs_fsblk_t n_blocks_count;
		int err = 0, err2 = 0;
		mockfs_group_t o_group = MOCKFS_SB(sb)->s_groups_count;

		if (mockfs_has_feature_bigalloc(sb)) {
			mockfs_msg(sb, KERN_ERR,
				 "Online resizing not (yet) supported with bigalloc");
			return -EOPNOTSUPP;
		}

		if (copy_from_user(&n_blocks_count, (__u64 __user *)arg,
				   sizeof(__u64))) {
			return -EFAULT;
		}

		err = mockfs_resize_begin(sb);
		if (err)
			return err;

		err = mnt_want_write_file(filp);
		if (err)
			goto resizefs_out;

		err = mockfs_resize_fs(sb, n_blocks_count);
		if (MOCKFS_SB(sb)->s_journal) {
			jbd2_journal_lock_updates(MOCKFS_SB(sb)->s_journal);
			err2 = jbd2_journal_flush(MOCKFS_SB(sb)->s_journal);
			jbd2_journal_unlock_updates(MOCKFS_SB(sb)->s_journal);
		}
		if (err == 0)
			err = err2;
		mnt_drop_write_file(filp);
		if (!err && (o_group > MOCKFS_SB(sb)->s_groups_count) &&
		    mockfs_has_group_desc_csum(sb) &&
		    test_opt(sb, INIT_INODE_TABLE))
			err = mockfs_register_li_request(sb, o_group);

resizefs_out:
		mockfs_resize_end(sb);
		return err;
	}

	case FITRIM:
	{
		struct request_queue *q = bdev_get_queue(sb->s_bdev);
		struct fstrim_range range;
		int ret = 0;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (!blk_queue_discard(q))
			return -EOPNOTSUPP;

		if (copy_from_user(&range, (struct fstrim_range __user *)arg,
		    sizeof(range)))
			return -EFAULT;

		range.minlen = max((unsigned int)range.minlen,
				   q->limits.discard_granularity);
		ret = mockfs_trim_fs(sb, &range);
		if (ret < 0)
			return ret;

		if (copy_to_user((struct fstrim_range __user *)arg, &range,
		    sizeof(range)))
			return -EFAULT;

		return 0;
	}
	case MOCKFS_IOC_PRECACHE_EXTENTS:
		return mockfs_ext_precache(inode);
	case MOCKFS_IOC_SET_ENCRYPTION_POLICY: {
#ifdef CONFIG_MOCKFS_FS_ENCRYPTION
		struct mockfs_encryption_policy policy;
		int err = 0;

		if (copy_from_user(&policy,
				   (struct mockfs_encryption_policy __user *)arg,
				   sizeof(policy))) {
			err = -EFAULT;
			goto encryption_policy_out;
		}

		err = mockfs_process_policy(&policy, inode);
encryption_policy_out:
		return err;
#else
		return -EOPNOTSUPP;
#endif
	}
	case MOCKFS_IOC_GET_ENCRYPTION_PWSALT: {
		int err, err2;
		struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
		handle_t *handle;

		if (!mockfs_sb_has_crypto(sb))
			return -EOPNOTSUPP;
		if (uuid_is_zero(sbi->s_es->s_encrypt_pw_salt)) {
			err = mnt_want_write_file(filp);
			if (err)
				return err;
			handle = mockfs_journal_start_sb(sb, MOCKFS_HT_MISC, 1);
			if (IS_ERR(handle)) {
				err = PTR_ERR(handle);
				goto pwsalt_err_exit;
			}
			err = mockfs_journal_get_write_access(handle, sbi->s_sbh);
			if (err)
				goto pwsalt_err_journal;
			generate_random_uuid(sbi->s_es->s_encrypt_pw_salt);
			err = mockfs_handle_dirty_metadata(handle, NULL,
							 sbi->s_sbh);
		pwsalt_err_journal:
			err2 = mockfs_journal_stop(handle);
			if (err2 && !err)
				err = err2;
		pwsalt_err_exit:
			mnt_drop_write_file(filp);
			if (err)
				return err;
		}
		if (copy_to_user((void __user *) arg,
				 sbi->s_es->s_encrypt_pw_salt, 16))
			return -EFAULT;
		return 0;
	}
	case MOCKFS_IOC_GET_ENCRYPTION_POLICY: {
#ifdef CONFIG_MOCKFS_FS_ENCRYPTION
		struct mockfs_encryption_policy policy;
		int err = 0;

		if (!mockfs_encrypted_inode(inode))
			return -ENOENT;
		err = mockfs_get_policy(inode, &policy);
		if (err)
			return err;
		if (copy_to_user((void __user *)arg, &policy, sizeof(policy)))
			return -EFAULT;
		return 0;
#else
		return -EOPNOTSUPP;
#endif
	}
	case MOCKFS_IOC_FSGETXATTR:
	{
		struct fsxattr fa;

		memset(&fa, 0, sizeof(struct fsxattr));
		mockfs_get_inode_flags(ei);
		fa.fsx_xflags = mockfs_iflags_to_xflags(ei->i_flags & MOCKFS_FL_USER_VISIBLE);

		if (MOCKFS_HAS_RO_COMPAT_FEATURE(inode->i_sb,
				MOCKFS_FEATURE_RO_COMPAT_PROJECT)) {
			fa.fsx_projid = (__u32)from_kprojid(&init_user_ns,
				MOCKFS_I(inode)->i_projid);
		}

		if (copy_to_user((struct fsxattr __user *)arg,
				 &fa, sizeof(fa)))
			return -EFAULT;
		return 0;
	}
	case MOCKFS_IOC_FSSETXATTR:
	{
		struct fsxattr fa;
		int err;

		if (copy_from_user(&fa, (struct fsxattr __user *)arg,
				   sizeof(fa)))
			return -EFAULT;

		/* Make sure caller has proper permission */
		if (!inode_owner_or_capable(inode))
			return -EACCES;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		flags = mockfs_xflags_to_iflags(fa.fsx_xflags);
		flags = mockfs_mask_flags(inode->i_mode, flags);

		inode_lock(inode);
		flags = (ei->i_flags & ~MOCKFS_FL_XFLAG_VISIBLE) |
			 (flags & MOCKFS_FL_XFLAG_VISIBLE);
		err = mockfs_ioctl_setflags(inode, flags);
		inode_unlock(inode);
		mnt_drop_write_file(filp);
		if (err)
			return err;

		err = mockfs_ioctl_setproject(filp, fa.fsx_projid);
		if (err)
			return err;

		return 0;
	}
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long mockfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case MOCKFS_IOC32_GETFLAGS:
		cmd = MOCKFS_IOC_GETFLAGS;
		break;
	case MOCKFS_IOC32_SETFLAGS:
		cmd = MOCKFS_IOC_SETFLAGS;
		break;
	case MOCKFS_IOC32_GETVERSION:
		cmd = MOCKFS_IOC_GETVERSION;
		break;
	case MOCKFS_IOC32_SETVERSION:
		cmd = MOCKFS_IOC_SETVERSION;
		break;
	case MOCKFS_IOC32_GROUP_EXTEND:
		cmd = MOCKFS_IOC_GROUP_EXTEND;
		break;
	case MOCKFS_IOC32_GETVERSION_OLD:
		cmd = MOCKFS_IOC_GETVERSION_OLD;
		break;
	case MOCKFS_IOC32_SETVERSION_OLD:
		cmd = MOCKFS_IOC_SETVERSION_OLD;
		break;
	case MOCKFS_IOC32_GETRSVSZ:
		cmd = MOCKFS_IOC_GETRSVSZ;
		break;
	case MOCKFS_IOC32_SETRSVSZ:
		cmd = MOCKFS_IOC_SETRSVSZ;
		break;
	case MOCKFS_IOC32_GROUP_ADD: {
		struct compat_mockfs_new_group_input __user *uinput;
		struct mockfs_new_group_input input;
		mm_segment_t old_fs;
		int err;

		uinput = compat_ptr(arg);
		err = get_user(input.group, &uinput->group);
		err |= get_user(input.block_bitmap, &uinput->block_bitmap);
		err |= get_user(input.inode_bitmap, &uinput->inode_bitmap);
		err |= get_user(input.inode_table, &uinput->inode_table);
		err |= get_user(input.blocks_count, &uinput->blocks_count);
		err |= get_user(input.reserved_blocks,
				&uinput->reserved_blocks);
		if (err)
			return -EFAULT;
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		err = mockfs_ioctl(file, MOCKFS_IOC_GROUP_ADD,
				 (unsigned long) &input);
		set_fs(old_fs);
		return err;
	}
	case MOCKFS_IOC_MOVE_EXT:
	case MOCKFS_IOC_RESIZE_FS:
	case MOCKFS_IOC_PRECACHE_EXTENTS:
	case MOCKFS_IOC_SET_ENCRYPTION_POLICY:
	case MOCKFS_IOC_GET_ENCRYPTION_PWSALT:
	case MOCKFS_IOC_GET_ENCRYPTION_POLICY:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return mockfs_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif
