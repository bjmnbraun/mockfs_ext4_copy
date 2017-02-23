/*
 *  linux/fs/mockfs/inode.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *	(jj@sunsite.ms.mff.cuni.cz)
 *
 *  Assorted race fixes, rewrite of mockfs_get_block() by Al Viro, 2000
 */

#include <linux/fs.h>
#include <linux/time.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/dax.h>
#include <linux/quotaops.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/mpage.h>
#include <linux/namei.h>
#include <linux/uio.h>
#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/bitops.h>

#include "mockfs_jbd2.h"
#include "xattr.h"
#include "acl.h"
#include "truncate.h"


#define MPAGE_DA_EXTENT_TAIL 0x01

static __u32 mockfs_inode_csum(struct inode *inode, struct mockfs_inode *raw,
			      struct mockfs_inode_info *ei)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);
	__u16 csum_lo;
	__u16 csum_hi = 0;
	__u32 csum;

	csum_lo = le16_to_cpu(raw->i_checksum_lo);
	raw->i_checksum_lo = 0;
	if (MOCKFS_INODE_SIZE(inode->i_sb) > MOCKFS_GOOD_OLD_INODE_SIZE &&
	    MOCKFS_FITS_IN_INODE(raw, ei, i_checksum_hi)) {
		csum_hi = le16_to_cpu(raw->i_checksum_hi);
		raw->i_checksum_hi = 0;
	}

	csum = mockfs_chksum(sbi, ei->i_csum_seed, (__u8 *)raw,
			   MOCKFS_INODE_SIZE(inode->i_sb));

	raw->i_checksum_lo = cpu_to_le16(csum_lo);
	if (MOCKFS_INODE_SIZE(inode->i_sb) > MOCKFS_GOOD_OLD_INODE_SIZE &&
	    MOCKFS_FITS_IN_INODE(raw, ei, i_checksum_hi))
		raw->i_checksum_hi = cpu_to_le16(csum_hi);

	return csum;
}

static int mockfs_inode_csum_verify(struct inode *inode, struct mockfs_inode *raw,
				  struct mockfs_inode_info *ei)
{
	__u32 provided, calculated;

	if (MOCKFS_SB(inode->i_sb)->s_es->s_creator_os !=
	    cpu_to_le32(MOCKFS_OS_LINUX) ||
	    !mockfs_has_metadata_csum(inode->i_sb))
		return 1;

	provided = le16_to_cpu(raw->i_checksum_lo);
	calculated = mockfs_inode_csum(inode, raw, ei);
	if (MOCKFS_INODE_SIZE(inode->i_sb) > MOCKFS_GOOD_OLD_INODE_SIZE &&
	    MOCKFS_FITS_IN_INODE(raw, ei, i_checksum_hi))
		provided |= ((__u32)le16_to_cpu(raw->i_checksum_hi)) << 16;
	else
		calculated &= 0xFFFF;

	return provided == calculated;
}

static void mockfs_inode_csum_set(struct inode *inode, struct mockfs_inode *raw,
				struct mockfs_inode_info *ei)
{
	__u32 csum;

	if (MOCKFS_SB(inode->i_sb)->s_es->s_creator_os !=
	    cpu_to_le32(MOCKFS_OS_LINUX) ||
	    !mockfs_has_metadata_csum(inode->i_sb))
		return;

	csum = mockfs_inode_csum(inode, raw, ei);
	raw->i_checksum_lo = cpu_to_le16(csum & 0xFFFF);
	if (MOCKFS_INODE_SIZE(inode->i_sb) > MOCKFS_GOOD_OLD_INODE_SIZE &&
	    MOCKFS_FITS_IN_INODE(raw, ei, i_checksum_hi))
		raw->i_checksum_hi = cpu_to_le16(csum >> 16);
}

static inline int mockfs_begin_ordered_truncate(struct inode *inode,
					      loff_t new_size)
{
	/*
	 * If jinode is zero, then we never opened the file for
	 * writing, so there's no need to call
	 * jbd2_journal_begin_ordered_truncate() since there's no
	 * outstanding writes we need to flush.
	 */
	if (!MOCKFS_I(inode)->jinode)
		return 0;
	return jbd2_journal_begin_ordered_truncate(MOCKFS_JOURNAL(inode),
						   MOCKFS_I(inode)->jinode,
						   new_size);
}

static void mockfs_invalidatepage(struct page *page, unsigned int offset,
				unsigned int length);
static int __mockfs_journalled_writepage(struct page *page, unsigned int len);
static int mockfs_bh_delay_or_unwritten(handle_t *handle, struct buffer_head *bh);
static int mockfs_meta_trans_blocks(struct inode *inode, int lblocks,
				  int pextents);

/*
 * Test whether an inode is a fast symlink.
 */
int mockfs_inode_is_fast_symlink(struct inode *inode)
{
        int ea_blocks = MOCKFS_I(inode)->i_file_acl ?
		MOCKFS_CLUSTER_SIZE(inode->i_sb) >> 9 : 0;

	if (mockfs_has_inline_data(inode))
		return 0;

	return (S_ISLNK(inode->i_mode) && inode->i_blocks - ea_blocks == 0);
}

/*
 * Restart the transaction associated with *handle.  This does a commit,
 * so before we call here everything must be consistently dirtied against
 * this transaction.
 */
int mockfs_truncate_restart_trans(handle_t *handle, struct inode *inode,
				 int nblocks)
{
	int ret;

	/*
	 * Drop i_data_sem to avoid deadlock with mockfs_map_blocks.  At this
	 * moment, get_block can be called only for blocks inside i_size since
	 * page cache has been already dropped and writes are blocked by
	 * i_mutex. So we can safely drop the i_data_sem here.
	 */
	BUG_ON(MOCKFS_JOURNAL(inode) == NULL);
	jbd_debug(2, "restarting handle %p\n", handle);
	up_write(&MOCKFS_I(inode)->i_data_sem);
	ret = mockfs_journal_restart(handle, nblocks);
	down_write(&MOCKFS_I(inode)->i_data_sem);
	mockfs_discard_preallocations(inode);

	return ret;
}

/*
 * Called at the last iput() if i_nlink is zero.
 */
void mockfs_evict_inode(struct inode *inode)
{
	handle_t *handle;
	int err;


	if (inode->i_nlink) {
		/*
		 * When journalling data dirty buffers are tracked only in the
		 * journal. So although mm thinks everything is clean and
		 * ready for reaping the inode might still have some pages to
		 * write in the running transaction or waiting to be
		 * checkpointed. Thus calling jbd2_journal_invalidatepage()
		 * (via truncate_inode_pages()) to discard these buffers can
		 * cause data loss. Also even if we did not discard these
		 * buffers, we would have no way to find them after the inode
		 * is reaped and thus user could see stale data if he tries to
		 * read them before the transaction is checkpointed. So be
		 * careful and force everything to disk here... We use
		 * ei->i_datasync_tid to store the newest transaction
		 * containing inode's data.
		 *
		 * Note that directories do not have this problem because they
		 * don't use page cache.
		 */
		if (mockfs_should_journal_data(inode) &&
		    (S_ISLNK(inode->i_mode) || S_ISREG(inode->i_mode)) &&
		    inode->i_ino != MOCKFS_JOURNAL_INO) {
			journal_t *journal = MOCKFS_SB(inode->i_sb)->s_journal;
			tid_t commit_tid = MOCKFS_I(inode)->i_datasync_tid;

			jbd2_complete_transaction(journal, commit_tid);
			filemap_write_and_wait(&inode->i_data);
		}
		truncate_inode_pages_final(&inode->i_data);

		goto no_delete;
	}

	if (is_bad_inode(inode))
		goto no_delete;
	dquot_initialize(inode);

	if (mockfs_should_order_data(inode))
		mockfs_begin_ordered_truncate(inode, 0);
	truncate_inode_pages_final(&inode->i_data);

	/*
	 * Protect us against freezing - iput() caller didn't have to have any
	 * protection against it
	 */
	sb_start_intwrite(inode->i_sb);
	handle = mockfs_journal_start(inode, MOCKFS_HT_TRUNCATE,
				    mockfs_blocks_for_truncate(inode)+3);
	if (IS_ERR(handle)) {
		mockfs_std_error(inode->i_sb, PTR_ERR(handle));
		/*
		 * If we're going to skip the normal cleanup, we still need to
		 * make sure that the in-core orphan linked list is properly
		 * cleaned up.
		 */
		mockfs_orphan_del(NULL, inode);
		sb_end_intwrite(inode->i_sb);
		goto no_delete;
	}

	if (IS_SYNC(inode))
		mockfs_handle_sync(handle);
	inode->i_size = 0;
	err = mockfs_mark_inode_dirty(handle, inode);
	if (err) {
		mockfs_warning(inode->i_sb,
			     "couldn't mark inode dirty (err %d)", err);
		goto stop_handle;
	}
	if (inode->i_blocks)
		mockfs_truncate(inode);

	/*
	 * mockfs_ext_truncate() doesn't reserve any slop when it
	 * restarts journal transactions; therefore there may not be
	 * enough credits left in the handle to remove the inode from
	 * the orphan list and set the dtime field.
	 */
	if (!mockfs_handle_has_enough_credits(handle, 3)) {
		err = mockfs_journal_extend(handle, 3);
		if (err > 0)
			err = mockfs_journal_restart(handle, 3);
		if (err != 0) {
			mockfs_warning(inode->i_sb,
				     "couldn't extend journal (err %d)", err);
		stop_handle:
			mockfs_journal_stop(handle);
			mockfs_orphan_del(NULL, inode);
			sb_end_intwrite(inode->i_sb);
			goto no_delete;
		}
	}

	/*
	 * Kill off the orphan record which mockfs_truncate created.
	 * AKPM: I think this can be inside the above `if'.
	 * Note that mockfs_orphan_del() has to be able to cope with the
	 * deletion of a non-existent orphan - this is because we don't
	 * know if mockfs_truncate() actually created an orphan record.
	 * (Well, we could do this if we need to, but heck - it works)
	 */
	mockfs_orphan_del(handle, inode);
	MOCKFS_I(inode)->i_dtime	= get_seconds();

	/*
	 * One subtle ordering requirement: if anything has gone wrong
	 * (transaction abort, IO errors, whatever), then we can still
	 * do these next steps (the fs will already have been marked as
	 * having errors), but we can't free the inode if the mark_dirty
	 * fails.
	 */
	if (mockfs_mark_inode_dirty(handle, inode))
		/* If that failed, just do the required in-core inode clear. */
		mockfs_clear_inode(inode);
	else
		mockfs_free_inode(handle, inode);
	mockfs_journal_stop(handle);
	sb_end_intwrite(inode->i_sb);
	return;
no_delete:
	mockfs_clear_inode(inode);	/* We must guarantee clearing of inode... */
}

#ifdef CONFIG_QUOTA
qsize_t *mockfs_get_reserved_space(struct inode *inode)
{
	return &MOCKFS_I(inode)->i_reserved_quota;
}
#endif

/*
 * Called with i_data_sem down, which is important since we can call
 * mockfs_discard_preallocations() from here.
 */
void mockfs_da_update_reserve_space(struct inode *inode,
					int used, int quota_claim)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);
	struct mockfs_inode_info *ei = MOCKFS_I(inode);

	spin_lock(&ei->i_block_reservation_lock);
	if (unlikely(used > ei->i_reserved_data_blocks)) {
		mockfs_warning(inode->i_sb, "%s: ino %lu, used %d "
			 "with only %d reserved data blocks",
			 __func__, inode->i_ino, used,
			 ei->i_reserved_data_blocks);
		WARN_ON(1);
		used = ei->i_reserved_data_blocks;
	}

	/* Update per-inode reservations */
	ei->i_reserved_data_blocks -= used;
	percpu_counter_sub(&sbi->s_dirtyclusters_counter, used);

	spin_unlock(&MOCKFS_I(inode)->i_block_reservation_lock);

	/* Update quota subsystem for data blocks */
	if (quota_claim)
		dquot_claim_block(inode, MOCKFS_C2B(sbi, used));
	else {
		/*
		 * We did fallocate with an offset that is already delayed
		 * allocated. So on delayed allocated writeback we should
		 * not re-claim the quota for fallocated blocks.
		 */
		dquot_release_reservation_block(inode, MOCKFS_C2B(sbi, used));
	}

	/*
	 * If we have done all the pending block allocations and if
	 * there aren't any writers on the inode, we can discard the
	 * inode's preallocations.
	 */
	if ((ei->i_reserved_data_blocks == 0) &&
	    (atomic_read(&inode->i_writecount) == 0))
		mockfs_discard_preallocations(inode);
}

static int __check_block_validity(struct inode *inode, const char *func,
				unsigned int line,
				struct mockfs_map_blocks *map)
{
	if (!mockfs_data_block_valid(MOCKFS_SB(inode->i_sb), map->m_pblk,
				   map->m_len)) {
		mockfs_error_inode(inode, func, line, map->m_pblk,
				 "lblock %lu mapped to illegal pblock "
				 "(length %d)", (unsigned long) map->m_lblk,
				 map->m_len);
		return -EFSCORRUPTED;
	}
	return 0;
}

int mockfs_issue_zeroout(struct inode *inode, mockfs_lblk_t lblk, mockfs_fsblk_t pblk,
		       mockfs_lblk_t len)
{
	int ret;

	if (mockfs_encrypted_inode(inode))
		return mockfs_encrypted_zeroout(inode, lblk, pblk, len);

	ret = sb_issue_zeroout(inode->i_sb, pblk, len, GFP_NOFS);
	if (ret > 0)
		ret = 0;

	return ret;
}

#define check_block_validity(inode, map)	\
	__check_block_validity((inode), __func__, __LINE__, (map))

#ifdef ES_AGGRESSIVE_TEST
static void mockfs_map_blocks_es_recheck(handle_t *handle,
				       struct inode *inode,
				       struct mockfs_map_blocks *es_map,
				       struct mockfs_map_blocks *map,
				       int flags)
{
	int retval;

	map->m_flags = 0;
	/*
	 * There is a race window that the result is not the same.
	 * e.g. xfstests #223 when dioread_nolock enables.  The reason
	 * is that we lookup a block mapping in extent status tree with
	 * out taking i_data_sem.  So at the time the unwritten extent
	 * could be converted.
	 */
	down_read(&MOCKFS_I(inode)->i_data_sem);
	if (mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS)) {
		retval = mockfs_ext_map_blocks(handle, inode, map, flags &
					     MOCKFS_GET_BLOCKS_KEEP_SIZE);
	} else {
		retval = mockfs_ind_map_blocks(handle, inode, map, flags &
					     MOCKFS_GET_BLOCKS_KEEP_SIZE);
	}
	up_read((&MOCKFS_I(inode)->i_data_sem));

	/*
	 * We don't check m_len because extent will be collpased in status
	 * tree.  So the m_len might not equal.
	 */
	if (es_map->m_lblk != map->m_lblk ||
	    es_map->m_flags != map->m_flags ||
	    es_map->m_pblk != map->m_pblk) {
		printk("ES cache assertion failed for inode: %lu "
		       "es_cached ex [%d/%d/%llu/%x] != "
		       "found ex [%d/%d/%llu/%x] retval %d flags %x\n",
		       inode->i_ino, es_map->m_lblk, es_map->m_len,
		       es_map->m_pblk, es_map->m_flags, map->m_lblk,
		       map->m_len, map->m_pblk, map->m_flags,
		       retval, flags);
	}
}
#endif /* ES_AGGRESSIVE_TEST */

/*
 * The mockfs_map_blocks() function tries to look up the requested blocks,
 * and returns if the blocks are already mapped.
 *
 * Otherwise it takes the write lock of the i_data_sem and allocate blocks
 * and store the allocated blocks in the result buffer head and mark it
 * mapped.
 *
 * If file type is extents based, it will call mockfs_ext_map_blocks(),
 * Otherwise, call with mockfs_ind_map_blocks() to handle indirect mapping
 * based files
 *
 * On success, it returns the number of blocks being mapped or allocated.  if
 * create==0 and the blocks are pre-allocated and unwritten, the resulting @map
 * is marked as unwritten. If the create == 1, it will mark @map as mapped.
 *
 * It returns 0 if plain look up failed (blocks have not been allocated), in
 * that case, @map is returned as unmapped but we still do fill map->m_len to
 * indicate the length of a hole starting at map->m_lblk.
 *
 * It returns the error in case of allocation failure.
 */
int mockfs_map_blocks(handle_t *handle, struct inode *inode,
		    struct mockfs_map_blocks *map, int flags)
{
	struct extent_status es;
	int retval;
	int ret = 0;
#ifdef ES_AGGRESSIVE_TEST
	struct mockfs_map_blocks orig_map;

	memcpy(&orig_map, map, sizeof(*map));
#endif

	map->m_flags = 0;
	ext_debug("mockfs_map_blocks(): inode %lu, flag %d, max_blocks %u,"
		  "logical block %lu\n", inode->i_ino, flags, map->m_len,
		  (unsigned long) map->m_lblk);

	/*
	 * mockfs_map_blocks returns an int, and m_len is an unsigned int
	 */
	if (unlikely(map->m_len > INT_MAX))
		map->m_len = INT_MAX;

	/* We can handle the block number less than EXT_MAX_BLOCKS */
	if (unlikely(map->m_lblk >= EXT_MAX_BLOCKS))
		return -EFSCORRUPTED;

	/* Lookup extent status tree firstly */
	if (mockfs_es_lookup_extent(inode, map->m_lblk, &es)) {
		if (mockfs_es_is_written(&es) || mockfs_es_is_unwritten(&es)) {
			map->m_pblk = mockfs_es_pblock(&es) +
					map->m_lblk - es.es_lblk;
			map->m_flags |= mockfs_es_is_written(&es) ?
					MOCKFS_MAP_MAPPED : MOCKFS_MAP_UNWRITTEN;
			retval = es.es_len - (map->m_lblk - es.es_lblk);
			if (retval > map->m_len)
				retval = map->m_len;
			map->m_len = retval;
		} else if (mockfs_es_is_delayed(&es) || mockfs_es_is_hole(&es)) {
			map->m_pblk = 0;
			retval = es.es_len - (map->m_lblk - es.es_lblk);
			if (retval > map->m_len)
				retval = map->m_len;
			map->m_len = retval;
			retval = 0;
		} else {
			BUG_ON(1);
		}
#ifdef ES_AGGRESSIVE_TEST
		mockfs_map_blocks_es_recheck(handle, inode, map,
					   &orig_map, flags);
#endif
		goto found;
	}

	/*
	 * Try to see if we can get the block without requesting a new
	 * file system block.
	 */
	down_read(&MOCKFS_I(inode)->i_data_sem);
	if (mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS)) {
		retval = mockfs_ext_map_blocks(handle, inode, map, flags &
					     MOCKFS_GET_BLOCKS_KEEP_SIZE);
	} else {
		retval = mockfs_ind_map_blocks(handle, inode, map, flags &
					     MOCKFS_GET_BLOCKS_KEEP_SIZE);
	}
	if (retval > 0) {
		unsigned int status;

		if (unlikely(retval != map->m_len)) {
			mockfs_warning(inode->i_sb,
				     "ES len assertion failed for inode "
				     "%lu: retval %d != map->m_len %d",
				     inode->i_ino, retval, map->m_len);
			WARN_ON(1);
		}

		status = map->m_flags & MOCKFS_MAP_UNWRITTEN ?
				EXTENT_STATUS_UNWRITTEN : EXTENT_STATUS_WRITTEN;
		if (!(flags & MOCKFS_GET_BLOCKS_DELALLOC_RESERVE) &&
		    !(status & EXTENT_STATUS_WRITTEN) &&
		    mockfs_find_delalloc_range(inode, map->m_lblk,
					     map->m_lblk + map->m_len - 1))
			status |= EXTENT_STATUS_DELAYED;
		ret = mockfs_es_insert_extent(inode, map->m_lblk,
					    map->m_len, map->m_pblk, status);
		if (ret < 0)
			retval = ret;
	}
	up_read((&MOCKFS_I(inode)->i_data_sem));

found:
	if (retval > 0 && map->m_flags & MOCKFS_MAP_MAPPED) {
		ret = check_block_validity(inode, map);
		if (ret != 0)
			return ret;
	}

	/* If it is only a block(s) look up */
	if ((flags & MOCKFS_GET_BLOCKS_CREATE) == 0)
		return retval;

	/*
	 * Returns if the blocks have already allocated
	 *
	 * Note that if blocks have been preallocated
	 * mockfs_ext_get_block() returns the create = 0
	 * with buffer head unmapped.
	 */
	if (retval > 0 && map->m_flags & MOCKFS_MAP_MAPPED)
		/*
		 * If we need to convert extent to unwritten
		 * we continue and do the actual work in
		 * mockfs_ext_map_blocks()
		 */
		if (!(flags & MOCKFS_GET_BLOCKS_CONVERT_UNWRITTEN))
			return retval;

	/*
	 * Here we clear m_flags because after allocating an new extent,
	 * it will be set again.
	 */
	map->m_flags &= ~MOCKFS_MAP_FLAGS;

	/*
	 * New blocks allocate and/or writing to unwritten extent
	 * will possibly result in updating i_data, so we take
	 * the write lock of i_data_sem, and call get_block()
	 * with create == 1 flag.
	 */
	down_write(&MOCKFS_I(inode)->i_data_sem);

	/*
	 * We need to check for MOCKFS here because migrate
	 * could have changed the inode type in between
	 */
	if (mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS)) {
		retval = mockfs_ext_map_blocks(handle, inode, map, flags);
	} else {
		retval = mockfs_ind_map_blocks(handle, inode, map, flags);

		if (retval > 0 && map->m_flags & MOCKFS_MAP_NEW) {
			/*
			 * We allocated new blocks which will result in
			 * i_data's format changing.  Force the migrate
			 * to fail by clearing migrate flags
			 */
			mockfs_clear_inode_state(inode, MOCKFS_STATE_EXT_MIGRATE);
		}

		/*
		 * Update reserved blocks/metadata blocks after successful
		 * block allocation which had been deferred till now. We don't
		 * support fallocate for non extent files. So we can update
		 * reserve space here.
		 */
		if ((retval > 0) &&
			(flags & MOCKFS_GET_BLOCKS_DELALLOC_RESERVE))
			mockfs_da_update_reserve_space(inode, retval, 1);
	}

	if (retval > 0) {
		unsigned int status;

		if (unlikely(retval != map->m_len)) {
			mockfs_warning(inode->i_sb,
				     "ES len assertion failed for inode "
				     "%lu: retval %d != map->m_len %d",
				     inode->i_ino, retval, map->m_len);
			WARN_ON(1);
		}

		/*
		 * We have to zeroout blocks before inserting them into extent
		 * status tree. Otherwise someone could look them up there and
		 * use them before they are really zeroed.
		 */
		if (flags & MOCKFS_GET_BLOCKS_ZERO &&
		    map->m_flags & MOCKFS_MAP_MAPPED &&
		    map->m_flags & MOCKFS_MAP_NEW) {
			ret = mockfs_issue_zeroout(inode, map->m_lblk,
						 map->m_pblk, map->m_len);
			if (ret) {
				retval = ret;
				goto out_sem;
			}
		}

		/*
		 * If the extent has been zeroed out, we don't need to update
		 * extent status tree.
		 */
		if ((flags & MOCKFS_GET_BLOCKS_PRE_IO) &&
		    mockfs_es_lookup_extent(inode, map->m_lblk, &es)) {
			if (mockfs_es_is_written(&es))
				goto out_sem;
		}
		status = map->m_flags & MOCKFS_MAP_UNWRITTEN ?
				EXTENT_STATUS_UNWRITTEN : EXTENT_STATUS_WRITTEN;
		if (!(flags & MOCKFS_GET_BLOCKS_DELALLOC_RESERVE) &&
		    !(status & EXTENT_STATUS_WRITTEN) &&
		    mockfs_find_delalloc_range(inode, map->m_lblk,
					     map->m_lblk + map->m_len - 1))
			status |= EXTENT_STATUS_DELAYED;
		ret = mockfs_es_insert_extent(inode, map->m_lblk, map->m_len,
					    map->m_pblk, status);
		if (ret < 0) {
			retval = ret;
			goto out_sem;
		}
	}

out_sem:
	up_write((&MOCKFS_I(inode)->i_data_sem));
	if (retval > 0 && map->m_flags & MOCKFS_MAP_MAPPED) {
		ret = check_block_validity(inode, map);
		if (ret != 0)
			return ret;
	}
	return retval;
}

/*
 * Update MOCKFS_MAP_FLAGS in bh->b_state. For buffer heads attached to pages
 * we have to be careful as someone else may be manipulating b_state as well.
 */
static void mockfs_update_bh_state(struct buffer_head *bh, unsigned long flags)
{
	unsigned long old_state;
	unsigned long new_state;

	flags &= MOCKFS_MAP_FLAGS;

	/* Dummy buffer_head? Set non-atomically. */
	if (!bh->b_page) {
		bh->b_state = (bh->b_state & ~MOCKFS_MAP_FLAGS) | flags;
		return;
	}
	/*
	 * Someone else may be modifying b_state. Be careful! This is ugly but
	 * once we get rid of using bh as a container for mapping information
	 * to pass to / from get_block functions, this can go away.
	 */
	do {
		old_state = READ_ONCE(bh->b_state);
		new_state = (old_state & ~MOCKFS_MAP_FLAGS) | flags;
	} while (unlikely(
		 cmpxchg(&bh->b_state, old_state, new_state) != old_state));
}

static int _mockfs_get_block(struct inode *inode, sector_t iblock,
			   struct buffer_head *bh, int flags)
{
	struct mockfs_map_blocks map;
	int ret = 0;

	if (mockfs_has_inline_data(inode))
		return -ERANGE;

	map.m_lblk = iblock;
	map.m_len = bh->b_size >> inode->i_blkbits;

	ret = mockfs_map_blocks(mockfs_journal_current_handle(), inode, &map,
			      flags);
	if (ret > 0) {
		map_bh(bh, inode->i_sb, map.m_pblk);
		mockfs_update_bh_state(bh, map.m_flags);
		bh->b_size = inode->i_sb->s_blocksize * map.m_len;
		ret = 0;
	}
	return ret;
}

int mockfs_get_block(struct inode *inode, sector_t iblock,
		   struct buffer_head *bh, int create)
{
	return _mockfs_get_block(inode, iblock, bh,
			       create ? MOCKFS_GET_BLOCKS_CREATE : 0);
}

/*
 * Get block function used when preparing for buffered write if we require
 * creating an unwritten extent if blocks haven't been allocated.  The extent
 * will be converted to written after the IO is complete.
 */
int mockfs_get_block_unwritten(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh_result, int create)
{
	mockfs_debug("mockfs_get_block_unwritten: inode %lu, create flag %d\n",
		   inode->i_ino, create);
	return _mockfs_get_block(inode, iblock, bh_result,
			       MOCKFS_GET_BLOCKS_IO_CREATE_EXT);
}

/* Maximum number of blocks we map for direct IO at once. */
#define DIO_MAX_BLOCKS 4096

/*
 * Get blocks function for the cases that need to start a transaction -
 * generally difference cases of direct IO and DAX IO. It also handles retries
 * in case of ENOSPC.
 */
static int mockfs_get_block_trans(struct inode *inode, sector_t iblock,
				struct buffer_head *bh_result, int flags)
{
	int dio_credits;
	handle_t *handle;
	int retries = 0;
	int ret;

	/* Trim mapping request to maximum we can map at once for DIO */
	if (bh_result->b_size >> inode->i_blkbits > DIO_MAX_BLOCKS)
		bh_result->b_size = DIO_MAX_BLOCKS << inode->i_blkbits;
	dio_credits = mockfs_chunk_trans_blocks(inode,
				      bh_result->b_size >> inode->i_blkbits);
retry:
	handle = mockfs_journal_start(inode, MOCKFS_HT_MAP_BLOCKS, dio_credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	ret = _mockfs_get_block(inode, iblock, bh_result, flags);
	mockfs_journal_stop(handle);

	if (ret == -ENOSPC && mockfs_should_retry_alloc(inode->i_sb, &retries))
		goto retry;
	return ret;
}

/* Get block function for DIO reads and writes to inodes without extents */
int mockfs_dio_get_block(struct inode *inode, sector_t iblock,
		       struct buffer_head *bh, int create)
{
	/* We don't expect handle for direct IO */
	WARN_ON_ONCE(mockfs_journal_current_handle());

	if (!create)
		return _mockfs_get_block(inode, iblock, bh, 0);
	return mockfs_get_block_trans(inode, iblock, bh, MOCKFS_GET_BLOCKS_CREATE);
}

/*
 * Get block function for AIO DIO writes when we create unwritten extent if
 * blocks are not allocated yet. The extent will be converted to written
 * after IO is complete.
 */
static int mockfs_dio_get_block_unwritten_async(struct inode *inode,
		sector_t iblock, struct buffer_head *bh_result,	int create)
{
	int ret;

	/* We don't expect handle for direct IO */
	WARN_ON_ONCE(mockfs_journal_current_handle());

	ret = mockfs_get_block_trans(inode, iblock, bh_result,
				   MOCKFS_GET_BLOCKS_IO_CREATE_EXT);

	/*
	 * When doing DIO using unwritten extents, we need io_end to convert
	 * unwritten extents to written on IO completion. We allocate io_end
	 * once we spot unwritten extent and store it in b_private. Generic
	 * DIO code keeps b_private set and furthermore passes the value to
	 * our completion callback in 'private' argument.
	 */
	if (!ret && buffer_unwritten(bh_result)) {
		if (!bh_result->b_private) {
			mockfs_io_end_t *io_end;

			io_end = mockfs_init_io_end(inode, GFP_KERNEL);
			if (!io_end)
				return -ENOMEM;
			bh_result->b_private = io_end;
			mockfs_set_io_unwritten_flag(inode, io_end);
		}
		set_buffer_defer_completion(bh_result);
	}

	return ret;
}

/*
 * Get block function for non-AIO DIO writes when we create unwritten extent if
 * blocks are not allocated yet. The extent will be converted to written
 * after IO is complete from mockfs_ext_direct_IO() function.
 */
static int mockfs_dio_get_block_unwritten_sync(struct inode *inode,
		sector_t iblock, struct buffer_head *bh_result,	int create)
{
	int ret;

	/* We don't expect handle for direct IO */
	WARN_ON_ONCE(mockfs_journal_current_handle());

	ret = mockfs_get_block_trans(inode, iblock, bh_result,
				   MOCKFS_GET_BLOCKS_IO_CREATE_EXT);

	/*
	 * Mark inode as having pending DIO writes to unwritten extents.
	 * mockfs_ext_direct_IO() checks this flag and converts extents to
	 * written.
	 */
	if (!ret && buffer_unwritten(bh_result))
		mockfs_set_inode_state(inode, MOCKFS_STATE_DIO_UNWRITTEN);

	return ret;
}

static int mockfs_dio_get_block_overwrite(struct inode *inode, sector_t iblock,
		   struct buffer_head *bh_result, int create)
{
	int ret;

	mockfs_debug("mockfs_dio_get_block_overwrite: inode %lu, create flag %d\n",
		   inode->i_ino, create);
	/* We don't expect handle for direct IO */
	WARN_ON_ONCE(mockfs_journal_current_handle());

	ret = _mockfs_get_block(inode, iblock, bh_result, 0);
	/*
	 * Blocks should have been preallocated! mockfs_file_write_iter() checks
	 * that.
	 */
	WARN_ON_ONCE(!buffer_mapped(bh_result) || buffer_unwritten(bh_result));

	return ret;
}


/*
 * `handle' can be NULL if create is zero
 */
struct buffer_head *mockfs_getblk(handle_t *handle, struct inode *inode,
				mockfs_lblk_t block, int map_flags)
{
	struct mockfs_map_blocks map;
	struct buffer_head *bh;
	int create = map_flags & MOCKFS_GET_BLOCKS_CREATE;
	int err;

	J_ASSERT(handle != NULL || create == 0);

	map.m_lblk = block;
	map.m_len = 1;
	err = mockfs_map_blocks(handle, inode, &map, map_flags);

	if (err == 0)
		return create ? ERR_PTR(-ENOSPC) : NULL;
	if (err < 0)
		return ERR_PTR(err);

	bh = sb_getblk(inode->i_sb, map.m_pblk);
	if (unlikely(!bh))
		return ERR_PTR(-ENOMEM);
	if (map.m_flags & MOCKFS_MAP_NEW) {
		J_ASSERT(create != 0);
		J_ASSERT(handle != NULL);

		/*
		 * Now that we do not always journal data, we should
		 * keep in mind whether this should always journal the
		 * new buffer as metadata.  For now, regular file
		 * writes use mockfs_get_block instead, so it's not a
		 * problem.
		 */
		lock_buffer(bh);
		BUFFER_TRACE(bh, "call get_create_access");
		err = mockfs_journal_get_create_access(handle, bh);
		if (unlikely(err)) {
			unlock_buffer(bh);
			goto errout;
		}
		if (!buffer_uptodate(bh)) {
			memset(bh->b_data, 0, inode->i_sb->s_blocksize);
			set_buffer_uptodate(bh);
		}
		unlock_buffer(bh);
		BUFFER_TRACE(bh, "call mockfs_handle_dirty_metadata");
		err = mockfs_handle_dirty_metadata(handle, inode, bh);
		if (unlikely(err))
			goto errout;
	} else
		BUFFER_TRACE(bh, "not a new buffer");
	return bh;
errout:
	brelse(bh);
	return ERR_PTR(err);
}

struct buffer_head *mockfs_bread(handle_t *handle, struct inode *inode,
			       mockfs_lblk_t block, int map_flags)
{
	struct buffer_head *bh;

	bh = mockfs_getblk(handle, inode, block, map_flags);
	if (IS_ERR(bh))
		return bh;
	if (!bh || buffer_uptodate(bh))
		return bh;
	ll_rw_block(READ | REQ_META | REQ_PRIO, 1, &bh);
	wait_on_buffer(bh);
	if (buffer_uptodate(bh))
		return bh;
	put_bh(bh);
	return ERR_PTR(-EIO);
}

int mockfs_walk_page_buffers(handle_t *handle,
			   struct buffer_head *head,
			   unsigned from,
			   unsigned to,
			   int *partial,
			   int (*fn)(handle_t *handle,
				     struct buffer_head *bh))
{
	struct buffer_head *bh;
	unsigned block_start, block_end;
	unsigned blocksize = head->b_size;
	int err, ret = 0;
	struct buffer_head *next;

	for (bh = head, block_start = 0;
	     ret == 0 && (bh != head || !block_start);
	     block_start = block_end, bh = next) {
		next = bh->b_this_page;
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (partial && !buffer_uptodate(bh))
				*partial = 1;
			continue;
		}
		err = (*fn)(handle, bh);
		if (!ret)
			ret = err;
	}
	return ret;
}

/*
 * To preserve ordering, it is essential that the hole instantiation and
 * the data write be encapsulated in a single transaction.  We cannot
 * close off a transaction and start a new one between the mockfs_get_block()
 * and the commit_write().  So doing the jbd2_journal_start at the start of
 * prepare_write() is the right place.
 *
 * Also, this function can nest inside mockfs_writepage().  In that case, we
 * *know* that mockfs_writepage() has generated enough buffer credits to do the
 * whole page.  So we won't block on the journal in that case, which is good,
 * because the caller may be PF_MEMALLOC.
 *
 * By accident, mockfs can be reentered when a transaction is open via
 * quota file writes.  If we were to commit the transaction while thus
 * reentered, there can be a deadlock - we would be holding a quota
 * lock, and the commit would never complete if another thread had a
 * transaction open and was blocking on the quota lock - a ranking
 * violation.
 *
 * So what we do is to rely on the fact that jbd2_journal_stop/journal_start
 * will _not_ run commit under these circumstances because handle->h_ref
 * is elevated.  We'll still have enough credits for the tiny quotafile
 * write.
 */
int do_journal_get_write_access(handle_t *handle,
				struct buffer_head *bh)
{
	int dirty = buffer_dirty(bh);
	int ret;

	if (!buffer_mapped(bh) || buffer_freed(bh))
		return 0;
	/*
	 * __block_write_begin() could have dirtied some buffers. Clean
	 * the dirty bit as jbd2_journal_get_write_access() could complain
	 * otherwise about fs integrity issues. Setting of the dirty bit
	 * by __block_write_begin() isn't a real problem here as we clear
	 * the bit before releasing a page lock and thus writeback cannot
	 * ever write the buffer.
	 */
	if (dirty)
		clear_buffer_dirty(bh);
	BUFFER_TRACE(bh, "get write access");
	ret = mockfs_journal_get_write_access(handle, bh);
	if (!ret && dirty)
		ret = mockfs_handle_dirty_metadata(handle, NULL, bh);
	return ret;
}

#ifdef CONFIG_MOCKFS_FS_ENCRYPTION
static int mockfs_block_write_begin(struct page *page, loff_t pos, unsigned len,
				  get_block_t *get_block)
{
	unsigned from = pos & (PAGE_SIZE - 1);
	unsigned to = from + len;
	struct inode *inode = page->mapping->host;
	unsigned block_start, block_end;
	sector_t block;
	int err = 0;
	unsigned blocksize = inode->i_sb->s_blocksize;
	unsigned bbits;
	struct buffer_head *bh, *head, *wait[2], **wait_bh = wait;
	bool decrypt = false;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_SIZE);
	BUG_ON(to > PAGE_SIZE);
	BUG_ON(from > to);

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);
	head = page_buffers(page);
	bbits = ilog2(blocksize);
	block = (sector_t)page->index << (PAGE_SHIFT - bbits);

	for (bh = head, block_start = 0; bh != head || !block_start;
	    block++, block_start = block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
			}
			continue;
		}
		if (buffer_new(bh))
			clear_buffer_new(bh);
		if (!buffer_mapped(bh)) {
			WARN_ON(bh->b_size != blocksize);
			err = get_block(inode, block, bh, 1);
			if (err)
				break;
			if (buffer_new(bh)) {
				unmap_underlying_metadata(bh->b_bdev,
							  bh->b_blocknr);
				if (PageUptodate(page)) {
					clear_buffer_new(bh);
					set_buffer_uptodate(bh);
					mark_buffer_dirty(bh);
					continue;
				}
				if (block_end > to || block_start < from)
					zero_user_segments(page, to, block_end,
							   block_start, from);
				continue;
			}
		}
		if (PageUptodate(page)) {
			if (!buffer_uptodate(bh))
				set_buffer_uptodate(bh);
			continue;
		}
		if (!buffer_uptodate(bh) && !buffer_delay(bh) &&
		    !buffer_unwritten(bh) &&
		    (block_start < from || block_end > to)) {
			ll_rw_block(READ, 1, &bh);
			*wait_bh++ = bh;
			decrypt = mockfs_encrypted_inode(inode) &&
				S_ISREG(inode->i_mode);
		}
	}
	/*
	 * If we issued read requests, let them complete.
	 */
	while (wait_bh > wait) {
		wait_on_buffer(*--wait_bh);
		if (!buffer_uptodate(*wait_bh))
			err = -EIO;
	}
	if (unlikely(err))
		page_zero_new_buffers(page, from, to);
	else if (decrypt)
		err = mockfs_decrypt(page);
	return err;
}
#endif

static int mockfs_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	int ret, needed_blocks;
	handle_t *handle;
	int retries = 0;
	struct page *page;
	pgoff_t index;
	unsigned from, to;

	/*
	 * Reserve one block more for addition to orphan list in case
	 * we allocate blocks but write fails for some reason
	 */
	needed_blocks = mockfs_writepage_trans_blocks(inode) + 1;
	index = pos >> PAGE_SHIFT;
	from = pos & (PAGE_SIZE - 1);
	to = from + len;

	if (mockfs_test_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA)) {
		ret = mockfs_try_to_write_inline_data(mapping, inode, pos, len,
						    flags, pagep);
		if (ret < 0)
			return ret;
		if (ret == 1)
			return 0;
	}

	/*
	 * grab_cache_page_write_begin() can take a long time if the
	 * system is thrashing due to memory pressure, or if the page
	 * is being written back.  So grab it first before we start
	 * the transaction handle.  This also allows us to allocate
	 * the page (if needed) without using GFP_NOFS.
	 */
retry_grab:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	unlock_page(page);

retry_journal:
	handle = mockfs_journal_start(inode, MOCKFS_HT_WRITE_PAGE, needed_blocks);
	if (IS_ERR(handle)) {
		put_page(page);
		return PTR_ERR(handle);
	}

	lock_page(page);
	if (page->mapping != mapping) {
		/* The page got truncated from under us */
		unlock_page(page);
		put_page(page);
		mockfs_journal_stop(handle);
		goto retry_grab;
	}
	/* In case writeback began while the page was unlocked */
	wait_for_stable_page(page);

#ifdef CONFIG_MOCKFS_FS_ENCRYPTION
	if (mockfs_should_dioread_nolock(inode))
		ret = mockfs_block_write_begin(page, pos, len,
					     mockfs_get_block_unwritten);
	else
		ret = mockfs_block_write_begin(page, pos, len,
					     mockfs_get_block);
#else
	if (mockfs_should_dioread_nolock(inode))
		ret = __block_write_begin(page, pos, len,
					  mockfs_get_block_unwritten);
	else
		ret = __block_write_begin(page, pos, len, mockfs_get_block);
#endif
	if (!ret && mockfs_should_journal_data(inode)) {
		ret = mockfs_walk_page_buffers(handle, page_buffers(page),
					     from, to, NULL,
					     do_journal_get_write_access);
	}

	if (ret) {
		unlock_page(page);
		/*
		 * __block_write_begin may have instantiated a few blocks
		 * outside i_size.  Trim these off again. Don't need
		 * i_size_read because we hold i_mutex.
		 *
		 * Add inode to orphan list in case we crash before
		 * truncate finishes
		 */
		if (pos + len > inode->i_size && mockfs_can_truncate(inode))
			mockfs_orphan_add(handle, inode);

		mockfs_journal_stop(handle);
		if (pos + len > inode->i_size) {
			mockfs_truncate_failed_write(inode);
			/*
			 * If truncate failed early the inode might
			 * still be on the orphan list; we need to
			 * make sure the inode is removed from the
			 * orphan list in that case.
			 */
			if (inode->i_nlink)
				mockfs_orphan_del(NULL, inode);
		}

		if (ret == -ENOSPC &&
		    mockfs_should_retry_alloc(inode->i_sb, &retries))
			goto retry_journal;
		put_page(page);
		return ret;
	}
	*pagep = page;
	return ret;
}

/* For write_end() in data=journal mode */
static int write_end_fn(handle_t *handle, struct buffer_head *bh)
{
	int ret;
	if (!buffer_mapped(bh) || buffer_freed(bh))
		return 0;
	set_buffer_uptodate(bh);
	ret = mockfs_handle_dirty_metadata(handle, NULL, bh);
	clear_buffer_meta(bh);
	clear_buffer_prio(bh);
	return ret;
}

/*
 * We need to pick up the new inode size which generic_commit_write gave us
 * `file' can be NULL - eg, when called from page_symlink().
 *
 * mockfs never places buffers on inode->i_mapping->private_list.  metadata
 * buffers are managed internally.
 */
static int mockfs_write_end(struct file *file,
			  struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{
	handle_t *handle = mockfs_journal_current_handle();
	struct inode *inode = mapping->host;
	loff_t old_size = inode->i_size;
	int ret = 0, ret2;
	int i_size_changed = 0;

	if (mockfs_test_inode_state(inode, MOCKFS_STATE_ORDERED_MODE)) {
		ret = mockfs_jbd2_file_inode(handle, inode);
		if (ret) {
			unlock_page(page);
			put_page(page);
			goto errout;
		}
	}

	if (mockfs_has_inline_data(inode)) {
		ret = mockfs_write_inline_data_end(inode, pos, len,
						 copied, page);
		if (ret < 0)
			goto errout;
		copied = ret;
	} else
		copied = block_write_end(file, mapping, pos,
					 len, copied, page, fsdata);
	/*
	 * it's important to update i_size while still holding page lock:
	 * page writeout could otherwise come in and zero beyond i_size.
	 */
	i_size_changed = mockfs_update_inode_size(inode, pos + copied);
	unlock_page(page);
	put_page(page);

	if (old_size < pos)
		pagecache_isize_extended(inode, old_size, pos);
	/*
	 * Don't mark the inode dirty under page lock. First, it unnecessarily
	 * makes the holding time of page lock longer. Second, it forces lock
	 * ordering of page lock and transaction start for journaling
	 * filesystems.
	 */
	if (i_size_changed)
		mockfs_mark_inode_dirty(handle, inode);

	if (pos + len > inode->i_size && mockfs_can_truncate(inode))
		/* if we have allocated more blocks and copied
		 * less. We will have blocks allocated outside
		 * inode->i_size. So truncate them
		 */
		mockfs_orphan_add(handle, inode);
errout:
	ret2 = mockfs_journal_stop(handle);
	if (!ret)
		ret = ret2;

	if (pos + len > inode->i_size) {
		mockfs_truncate_failed_write(inode);
		/*
		 * If truncate failed early the inode might still be
		 * on the orphan list; we need to make sure the inode
		 * is removed from the orphan list in that case.
		 */
		if (inode->i_nlink)
			mockfs_orphan_del(NULL, inode);
	}

	return ret ? ret : copied;
}

/*
 * This is a private version of page_zero_new_buffers() which doesn't
 * set the buffer to be dirty, since in data=journalled mode we need
 * to call mockfs_handle_dirty_metadata() instead.
 */
static void zero_new_buffers(struct page *page, unsigned from, unsigned to)
{
	unsigned int block_start = 0, block_end;
	struct buffer_head *head, *bh;

	bh = head = page_buffers(page);
	do {
		block_end = block_start + bh->b_size;
		if (buffer_new(bh)) {
			if (block_end > from && block_start < to) {
				if (!PageUptodate(page)) {
					unsigned start, size;

					start = max(from, block_start);
					size = min(to, block_end) - start;

					zero_user(page, start, size);
					set_buffer_uptodate(bh);
				}
				clear_buffer_new(bh);
			}
		}
		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);
}

static int mockfs_journalled_write_end(struct file *file,
				     struct address_space *mapping,
				     loff_t pos, unsigned len, unsigned copied,
				     struct page *page, void *fsdata)
{
	handle_t *handle = mockfs_journal_current_handle();
	struct inode *inode = mapping->host;
	loff_t old_size = inode->i_size;
	int ret = 0, ret2;
	int partial = 0;
	unsigned from, to;
	int size_changed = 0;

	from = pos & (PAGE_SIZE - 1);
	to = from + len;

	BUG_ON(!mockfs_handle_valid(handle));

	if (mockfs_has_inline_data(inode))
		copied = mockfs_write_inline_data_end(inode, pos, len,
						    copied, page);
	else {
		if (copied < len) {
			if (!PageUptodate(page))
				copied = 0;
			zero_new_buffers(page, from+copied, to);
		}

		ret = mockfs_walk_page_buffers(handle, page_buffers(page), from,
					     to, &partial, write_end_fn);
		if (!partial)
			SetPageUptodate(page);
	}
	size_changed = mockfs_update_inode_size(inode, pos + copied);
	mockfs_set_inode_state(inode, MOCKFS_STATE_JDATA);
	MOCKFS_I(inode)->i_datasync_tid = handle->h_transaction->t_tid;
	unlock_page(page);
	put_page(page);

	if (old_size < pos)
		pagecache_isize_extended(inode, old_size, pos);

	if (size_changed) {
		ret2 = mockfs_mark_inode_dirty(handle, inode);
		if (!ret)
			ret = ret2;
	}

	if (pos + len > inode->i_size && mockfs_can_truncate(inode))
		/* if we have allocated more blocks and copied
		 * less. We will have blocks allocated outside
		 * inode->i_size. So truncate them
		 */
		mockfs_orphan_add(handle, inode);

	ret2 = mockfs_journal_stop(handle);
	if (!ret)
		ret = ret2;
	if (pos + len > inode->i_size) {
		mockfs_truncate_failed_write(inode);
		/*
		 * If truncate failed early the inode might still be
		 * on the orphan list; we need to make sure the inode
		 * is removed from the orphan list in that case.
		 */
		if (inode->i_nlink)
			mockfs_orphan_del(NULL, inode);
	}

	return ret ? ret : copied;
}

/*
 * Reserve space for a single cluster
 */
static int mockfs_da_reserve_space(struct inode *inode)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	int ret;

	/*
	 * We will charge metadata quota at writeout time; this saves
	 * us from metadata over-estimation, though we may go over by
	 * a small amount in the end.  Here we just reserve for data.
	 */
	ret = dquot_reserve_block(inode, MOCKFS_C2B(sbi, 1));
	if (ret)
		return ret;

	spin_lock(&ei->i_block_reservation_lock);
	if (mockfs_claim_free_clusters(sbi, 1, 0)) {
		spin_unlock(&ei->i_block_reservation_lock);
		dquot_release_reservation_block(inode, MOCKFS_C2B(sbi, 1));
		return -ENOSPC;
	}
	ei->i_reserved_data_blocks++;
	spin_unlock(&ei->i_block_reservation_lock);

	return 0;       /* success */
}

static void mockfs_da_release_space(struct inode *inode, int to_free)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);
	struct mockfs_inode_info *ei = MOCKFS_I(inode);

	if (!to_free)
		return;		/* Nothing to release, exit */

	spin_lock(&MOCKFS_I(inode)->i_block_reservation_lock);

	if (unlikely(to_free > ei->i_reserved_data_blocks)) {
		/*
		 * if there aren't enough reserved blocks, then the
		 * counter is messed up somewhere.  Since this
		 * function is called from invalidate page, it's
		 * harmless to return without any action.
		 */
		mockfs_warning(inode->i_sb, "mockfs_da_release_space: "
			 "ino %lu, to_free %d with only %d reserved "
			 "data blocks", inode->i_ino, to_free,
			 ei->i_reserved_data_blocks);
		WARN_ON(1);
		to_free = ei->i_reserved_data_blocks;
	}
	ei->i_reserved_data_blocks -= to_free;

	/* update fs dirty data blocks counter */
	percpu_counter_sub(&sbi->s_dirtyclusters_counter, to_free);

	spin_unlock(&MOCKFS_I(inode)->i_block_reservation_lock);

	dquot_release_reservation_block(inode, MOCKFS_C2B(sbi, to_free));
}

static void mockfs_da_page_release_reservation(struct page *page,
					     unsigned int offset,
					     unsigned int length)
{
	int to_release = 0, contiguous_blks = 0;
	struct buffer_head *head, *bh;
	unsigned int curr_off = 0;
	struct inode *inode = page->mapping->host;
	struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);
	unsigned int stop = offset + length;
	int num_clusters;
	mockfs_fsblk_t lblk;

	BUG_ON(stop > PAGE_SIZE || stop < length);

	head = page_buffers(page);
	bh = head;
	do {
		unsigned int next_off = curr_off + bh->b_size;

		if (next_off > stop)
			break;

		if ((offset <= curr_off) && (buffer_delay(bh))) {
			to_release++;
			contiguous_blks++;
			clear_buffer_delay(bh);
		} else if (contiguous_blks) {
			lblk = page->index <<
			       (PAGE_SHIFT - inode->i_blkbits);
			lblk += (curr_off >> inode->i_blkbits) -
				contiguous_blks;
			mockfs_es_remove_extent(inode, lblk, contiguous_blks);
			contiguous_blks = 0;
		}
		curr_off = next_off;
	} while ((bh = bh->b_this_page) != head);

	if (contiguous_blks) {
		lblk = page->index << (PAGE_SHIFT - inode->i_blkbits);
		lblk += (curr_off >> inode->i_blkbits) - contiguous_blks;
		mockfs_es_remove_extent(inode, lblk, contiguous_blks);
	}

	/* If we have released all the blocks belonging to a cluster, then we
	 * need to release the reserved space for that cluster. */
	num_clusters = MOCKFS_NUM_B2C(sbi, to_release);
	while (num_clusters > 0) {
		lblk = (page->index << (PAGE_SHIFT - inode->i_blkbits)) +
			((num_clusters - 1) << sbi->s_cluster_bits);
		if (sbi->s_cluster_ratio == 1 ||
		    !mockfs_find_delalloc_cluster(inode, lblk))
			mockfs_da_release_space(inode, 1);

		num_clusters--;
	}
}

/*
 * Delayed allocation stuff
 */

struct mpage_da_data {
	struct inode *inode;
	struct writeback_control *wbc;

	pgoff_t first_page;	/* The first page to write */
	pgoff_t next_page;	/* Current page to examine */
	pgoff_t last_page;	/* Last page to examine */
	/*
	 * Extent to map - this can be after first_page because that can be
	 * fully mapped. We somewhat abuse m_flags to store whether the extent
	 * is delalloc or unwritten.
	 */
	struct mockfs_map_blocks map;
	struct mockfs_io_submit io_submit;	/* IO submission data */
};

static void mpage_release_unused_pages(struct mpage_da_data *mpd,
				       bool invalidate)
{
	int nr_pages, i;
	pgoff_t index, end;
	struct pagevec pvec;
	struct inode *inode = mpd->inode;
	struct address_space *mapping = inode->i_mapping;

	/* This is necessary when next_page == 0. */
	if (mpd->first_page >= mpd->next_page)
		return;

	index = mpd->first_page;
	end   = mpd->next_page - 1;
	if (invalidate) {
		mockfs_lblk_t start, last;
		start = index << (PAGE_SHIFT - inode->i_blkbits);
		last = end << (PAGE_SHIFT - inode->i_blkbits);
		mockfs_es_remove_extent(inode, start, last - start + 1);
	}

	pagevec_init(&pvec, 0);
	while (index <= end) {
		nr_pages = pagevec_lookup(&pvec, mapping, index, PAGEVEC_SIZE);
		if (nr_pages == 0)
			break;
		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];
			if (page->index > end)
				break;
			BUG_ON(!PageLocked(page));
			BUG_ON(PageWriteback(page));
			if (invalidate) {
				block_invalidatepage(page, 0, PAGE_SIZE);
				ClearPageUptodate(page);
			}
			unlock_page(page);
		}
		index = pvec.pages[nr_pages - 1]->index + 1;
		pagevec_release(&pvec);
	}
}

static void mockfs_print_free_blocks(struct inode *inode)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);
	struct super_block *sb = inode->i_sb;
	struct mockfs_inode_info *ei = MOCKFS_I(inode);

	mockfs_msg(sb, KERN_CRIT, "Total free blocks count %lld",
	       MOCKFS_C2B(MOCKFS_SB(inode->i_sb),
			mockfs_count_free_clusters(sb)));
	mockfs_msg(sb, KERN_CRIT, "Free/Dirty block details");
	mockfs_msg(sb, KERN_CRIT, "free_blocks=%lld",
	       (long long) MOCKFS_C2B(MOCKFS_SB(sb),
		percpu_counter_sum(&sbi->s_freeclusters_counter)));
	mockfs_msg(sb, KERN_CRIT, "dirty_blocks=%lld",
	       (long long) MOCKFS_C2B(MOCKFS_SB(sb),
		percpu_counter_sum(&sbi->s_dirtyclusters_counter)));
	mockfs_msg(sb, KERN_CRIT, "Block reservation details");
	mockfs_msg(sb, KERN_CRIT, "i_reserved_data_blocks=%u",
		 ei->i_reserved_data_blocks);
	return;
}

static int mockfs_bh_delay_or_unwritten(handle_t *handle, struct buffer_head *bh)
{
	return (buffer_delay(bh) || buffer_unwritten(bh)) && buffer_dirty(bh);
}

/*
 * This function is grabs code from the very beginning of
 * mockfs_map_blocks, but assumes that the caller is from delayed write
 * time. This function looks up the requested blocks and sets the
 * buffer delay bit under the protection of i_data_sem.
 */
static int mockfs_da_map_blocks(struct inode *inode, sector_t iblock,
			      struct mockfs_map_blocks *map,
			      struct buffer_head *bh)
{
	struct extent_status es;
	int retval;
	sector_t invalid_block = ~((sector_t) 0xffff);
#ifdef ES_AGGRESSIVE_TEST
	struct mockfs_map_blocks orig_map;

	memcpy(&orig_map, map, sizeof(*map));
#endif

	if (invalid_block < mockfs_blocks_count(MOCKFS_SB(inode->i_sb)->s_es))
		invalid_block = ~0;

	map->m_flags = 0;
	ext_debug("mockfs_da_map_blocks(): inode %lu, max_blocks %u,"
		  "logical block %lu\n", inode->i_ino, map->m_len,
		  (unsigned long) map->m_lblk);

	/* Lookup extent status tree firstly */
	if (mockfs_es_lookup_extent(inode, iblock, &es)) {
		if (mockfs_es_is_hole(&es)) {
			retval = 0;
			down_read(&MOCKFS_I(inode)->i_data_sem);
			goto add_delayed;
		}

		/*
		 * Delayed extent could be allocated by fallocate.
		 * So we need to check it.
		 */
		if (mockfs_es_is_delayed(&es) && !mockfs_es_is_unwritten(&es)) {
			map_bh(bh, inode->i_sb, invalid_block);
			set_buffer_new(bh);
			set_buffer_delay(bh);
			return 0;
		}

		map->m_pblk = mockfs_es_pblock(&es) + iblock - es.es_lblk;
		retval = es.es_len - (iblock - es.es_lblk);
		if (retval > map->m_len)
			retval = map->m_len;
		map->m_len = retval;
		if (mockfs_es_is_written(&es))
			map->m_flags |= MOCKFS_MAP_MAPPED;
		else if (mockfs_es_is_unwritten(&es))
			map->m_flags |= MOCKFS_MAP_UNWRITTEN;
		else
			BUG_ON(1);

#ifdef ES_AGGRESSIVE_TEST
		mockfs_map_blocks_es_recheck(NULL, inode, map, &orig_map, 0);
#endif
		return retval;
	}

	/*
	 * Try to see if we can get the block without requesting a new
	 * file system block.
	 */
	down_read(&MOCKFS_I(inode)->i_data_sem);
	if (mockfs_has_inline_data(inode))
		retval = 0;
	else if (mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS))
		retval = mockfs_ext_map_blocks(NULL, inode, map, 0);
	else
		retval = mockfs_ind_map_blocks(NULL, inode, map, 0);

add_delayed:
	if (retval == 0) {
		int ret;
		/*
		 * XXX: __block_prepare_write() unmaps passed block,
		 * is it OK?
		 */
		/*
		 * If the block was allocated from previously allocated cluster,
		 * then we don't need to reserve it again. However we still need
		 * to reserve metadata for every block we're going to write.
		 */
		if (MOCKFS_SB(inode->i_sb)->s_cluster_ratio == 1 ||
		    !mockfs_find_delalloc_cluster(inode, map->m_lblk)) {
			ret = mockfs_da_reserve_space(inode);
			if (ret) {
				/* not enough space to reserve */
				retval = ret;
				goto out_unlock;
			}
		}

		ret = mockfs_es_insert_extent(inode, map->m_lblk, map->m_len,
					    ~0, EXTENT_STATUS_DELAYED);
		if (ret) {
			retval = ret;
			goto out_unlock;
		}

		map_bh(bh, inode->i_sb, invalid_block);
		set_buffer_new(bh);
		set_buffer_delay(bh);
	} else if (retval > 0) {
		int ret;
		unsigned int status;

		if (unlikely(retval != map->m_len)) {
			mockfs_warning(inode->i_sb,
				     "ES len assertion failed for inode "
				     "%lu: retval %d != map->m_len %d",
				     inode->i_ino, retval, map->m_len);
			WARN_ON(1);
		}

		status = map->m_flags & MOCKFS_MAP_UNWRITTEN ?
				EXTENT_STATUS_UNWRITTEN : EXTENT_STATUS_WRITTEN;
		ret = mockfs_es_insert_extent(inode, map->m_lblk, map->m_len,
					    map->m_pblk, status);
		if (ret != 0)
			retval = ret;
	}

out_unlock:
	up_read((&MOCKFS_I(inode)->i_data_sem));

	return retval;
}

/*
 * This is a special get_block_t callback which is used by
 * mockfs_da_write_begin().  It will either return mapped block or
 * reserve space for a single block.
 *
 * For delayed buffer_head we have BH_Mapped, BH_New, BH_Delay set.
 * We also have b_blocknr = -1 and b_bdev initialized properly
 *
 * For unwritten buffer_head we have BH_Mapped, BH_New, BH_Unwritten set.
 * We also have b_blocknr = physicalblock mapping unwritten extent and b_bdev
 * initialized properly.
 */
int mockfs_da_get_block_prep(struct inode *inode, sector_t iblock,
			   struct buffer_head *bh, int create)
{
	struct mockfs_map_blocks map;
	int ret = 0;

	BUG_ON(create == 0);
	BUG_ON(bh->b_size != inode->i_sb->s_blocksize);

	map.m_lblk = iblock;
	map.m_len = 1;

	/*
	 * first, we need to know whether the block is allocated already
	 * preallocated blocks are unmapped but should treated
	 * the same as allocated blocks.
	 */
	ret = mockfs_da_map_blocks(inode, iblock, &map, bh);
	if (ret <= 0)
		return ret;

	map_bh(bh, inode->i_sb, map.m_pblk);
	mockfs_update_bh_state(bh, map.m_flags);

	if (buffer_unwritten(bh)) {
		/* A delayed write to unwritten bh should be marked
		 * new and mapped.  Mapped ensures that we don't do
		 * get_block multiple times when we write to the same
		 * offset and new ensures that we do proper zero out
		 * for partial write.
		 */
		set_buffer_new(bh);
		set_buffer_mapped(bh);
	}
	return 0;
}

static int bget_one(handle_t *handle, struct buffer_head *bh)
{
	get_bh(bh);
	return 0;
}

static int bput_one(handle_t *handle, struct buffer_head *bh)
{
	put_bh(bh);
	return 0;
}

static int __mockfs_journalled_writepage(struct page *page,
				       unsigned int len)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct buffer_head *page_bufs = NULL;
	handle_t *handle = NULL;
	int ret = 0, err = 0;
	int inline_data = mockfs_has_inline_data(inode);
	struct buffer_head *inode_bh = NULL;

	ClearPageChecked(page);

	if (inline_data) {
		BUG_ON(page->index != 0);
		BUG_ON(len > mockfs_get_max_inline_size(inode));
		inode_bh = mockfs_journalled_write_inline_data(inode, len, page);
		if (inode_bh == NULL)
			goto out;
	} else {
		page_bufs = page_buffers(page);
		if (!page_bufs) {
			BUG();
			goto out;
		}
		mockfs_walk_page_buffers(handle, page_bufs, 0, len,
				       NULL, bget_one);
	}
	/*
	 * We need to release the page lock before we start the
	 * journal, so grab a reference so the page won't disappear
	 * out from under us.
	 */
	get_page(page);
	unlock_page(page);

	handle = mockfs_journal_start(inode, MOCKFS_HT_WRITE_PAGE,
				    mockfs_writepage_trans_blocks(inode));
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		put_page(page);
		goto out_no_pagelock;
	}
	BUG_ON(!mockfs_handle_valid(handle));

	lock_page(page);
	put_page(page);
	if (page->mapping != mapping) {
		/* The page got truncated from under us */
		mockfs_journal_stop(handle);
		ret = 0;
		goto out;
	}

	if (inline_data) {
		BUFFER_TRACE(inode_bh, "get write access");
		ret = mockfs_journal_get_write_access(handle, inode_bh);

		err = mockfs_handle_dirty_metadata(handle, inode, inode_bh);

	} else {
		ret = mockfs_walk_page_buffers(handle, page_bufs, 0, len, NULL,
					     do_journal_get_write_access);

		err = mockfs_walk_page_buffers(handle, page_bufs, 0, len, NULL,
					     write_end_fn);
	}
	if (ret == 0)
		ret = err;
	MOCKFS_I(inode)->i_datasync_tid = handle->h_transaction->t_tid;
	err = mockfs_journal_stop(handle);
	if (!ret)
		ret = err;

	if (!mockfs_has_inline_data(inode))
		mockfs_walk_page_buffers(NULL, page_bufs, 0, len,
				       NULL, bput_one);
	mockfs_set_inode_state(inode, MOCKFS_STATE_JDATA);
out:
	unlock_page(page);
out_no_pagelock:
	brelse(inode_bh);
	return ret;
}

/*
 * Note that we don't need to start a transaction unless we're journaling data
 * because we should have holes filled from mockfs_page_mkwrite(). We even don't
 * need to file the inode to the transaction's list in ordered mode because if
 * we are writing back data added by write(), the inode is already there and if
 * we are writing back data modified via mmap(), no one guarantees in which
 * transaction the data will hit the disk. In case we are journaling data, we
 * cannot start transaction directly because transaction start ranks above page
 * lock so we have to do some magic.
 *
 * This function can get called via...
 *   - mockfs_writepages after taking page lock (have journal handle)
 *   - journal_submit_inode_data_buffers (no journal handle)
 *   - shrink_page_list via the kswapd/direct reclaim (no journal handle)
 *   - grab_page_cache when doing write_begin (have journal handle)
 *
 * We don't do any block allocation in this function. If we have page with
 * multiple blocks we need to write those buffer_heads that are mapped. This
 * is important for mmaped based write. So if we do with blocksize 1K
 * truncate(f, 1024);
 * a = mmap(f, 0, 4096);
 * a[0] = 'a';
 * truncate(f, 4096);
 * we have in the page first buffer_head mapped via page_mkwrite call back
 * but other buffer_heads would be unmapped but dirty (dirty done via the
 * do_wp_page). So writepage should write the first block. If we modify
 * the mmap area beyond 1024 we will again get a page_fault and the
 * page_mkwrite callback will do the block allocation and mark the
 * buffer_heads mapped.
 *
 * We redirty the page if we have any buffer_heads that is either delay or
 * unwritten in the page.
 *
 * We can get recursively called as show below.
 *
 *	mockfs_writepage() -> kmalloc() -> __alloc_pages() -> page_launder() ->
 *		mockfs_writepage()
 *
 * But since we don't do any block allocation we should not deadlock.
 * Page also have the dirty flag cleared so we don't get recurive page_lock.
 */
static int mockfs_writepage(struct page *page,
			  struct writeback_control *wbc)
{
	int ret = 0;
	loff_t size;
	unsigned int len;
	struct buffer_head *page_bufs = NULL;
	struct inode *inode = page->mapping->host;
	struct mockfs_io_submit io_submit;
	bool keep_towrite = false;

	size = i_size_read(inode);
	if (page->index == size >> PAGE_SHIFT)
		len = size & ~PAGE_MASK;
	else
		len = PAGE_SIZE;

	page_bufs = page_buffers(page);
	/*
	 * We cannot do block allocation or other extent handling in this
	 * function. If there are buffers needing that, we have to redirty
	 * the page. But we may reach here when we do a journal commit via
	 * journal_submit_inode_data_buffers() and in that case we must write
	 * allocated buffers to achieve data=ordered mode guarantees.
	 *
	 * Also, if there is only one buffer per page (the fs block
	 * size == the page size), if one buffer needs block
	 * allocation or needs to modify the extent tree to clear the
	 * unwritten flag, we know that the page can't be written at
	 * all, so we might as well refuse the write immediately.
	 * Unfortunately if the block size != page size, we can't as
	 * easily detect this case using mockfs_walk_page_buffers(), but
	 * for the extremely common case, this is an optimization that
	 * skips a useless round trip through mockfs_bio_write_page().
	 */
	if (mockfs_walk_page_buffers(NULL, page_bufs, 0, len, NULL,
				   mockfs_bh_delay_or_unwritten)) {
		redirty_page_for_writepage(wbc, page);
		if ((current->flags & PF_MEMALLOC) ||
		    (inode->i_sb->s_blocksize == PAGE_SIZE)) {
			/*
			 * For memory cleaning there's no point in writing only
			 * some buffers. So just bail out. Warn if we came here
			 * from direct reclaim.
			 */
			WARN_ON_ONCE((current->flags & (PF_MEMALLOC|PF_KSWAPD))
							== PF_MEMALLOC);
			unlock_page(page);
			return 0;
		}
		keep_towrite = true;
	}

	if (PageChecked(page) && mockfs_should_journal_data(inode))
		/*
		 * It's mmapped pagecache.  Add buffers and journal it.  There
		 * doesn't seem much point in redirtying the page here.
		 */
		return __mockfs_journalled_writepage(page, len);

	mockfs_io_submit_init(&io_submit, wbc);
	io_submit.io_end = mockfs_init_io_end(inode, GFP_NOFS);
	if (!io_submit.io_end) {
		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
		return -ENOMEM;
	}
	ret = mockfs_bio_write_page(&io_submit, page, len, wbc, keep_towrite);
	mockfs_io_submit(&io_submit);
	/* Drop io_end reference we got from init */
	mockfs_put_io_end_defer(io_submit.io_end);
	return ret;
}

static int mpage_submit_page(struct mpage_da_data *mpd, struct page *page)
{
	int len;
	loff_t size = i_size_read(mpd->inode);
	int err;

	BUG_ON(page->index != mpd->first_page);
	if (page->index == size >> PAGE_SHIFT)
		len = size & ~PAGE_MASK;
	else
		len = PAGE_SIZE;
	clear_page_dirty_for_io(page);
	err = mockfs_bio_write_page(&mpd->io_submit, page, len, mpd->wbc, false);
	if (!err)
		mpd->wbc->nr_to_write--;
	mpd->first_page++;

	return err;
}

#define BH_FLAGS ((1 << BH_Unwritten) | (1 << BH_Delay))

/*
 * mballoc gives us at most this number of blocks...
 * XXX: That seems to be only a limitation of mockfs_mb_normalize_request().
 * The rest of mballoc seems to handle chunks up to full group size.
 */
#define MAX_WRITEPAGES_EXTENT_LEN 2048

/*
 * mpage_add_bh_to_extent - try to add bh to extent of blocks to map
 *
 * @mpd - extent of blocks
 * @lblk - logical number of the block in the file
 * @bh - buffer head we want to add to the extent
 *
 * The function is used to collect contig. blocks in the same state. If the
 * buffer doesn't require mapping for writeback and we haven't started the
 * extent of buffers to map yet, the function returns 'true' immediately - the
 * caller can write the buffer right away. Otherwise the function returns true
 * if the block has been added to the extent, false if the block couldn't be
 * added.
 */
static bool mpage_add_bh_to_extent(struct mpage_da_data *mpd, mockfs_lblk_t lblk,
				   struct buffer_head *bh)
{
	struct mockfs_map_blocks *map = &mpd->map;

	/* Buffer that doesn't need mapping for writeback? */
	if (!buffer_dirty(bh) || !buffer_mapped(bh) ||
	    (!buffer_delay(bh) && !buffer_unwritten(bh))) {
		/* So far no extent to map => we write the buffer right away */
		if (map->m_len == 0)
			return true;
		return false;
	}

	/* First block in the extent? */
	if (map->m_len == 0) {
		map->m_lblk = lblk;
		map->m_len = 1;
		map->m_flags = bh->b_state & BH_FLAGS;
		return true;
	}

	/* Don't go larger than mballoc is willing to allocate */
	if (map->m_len >= MAX_WRITEPAGES_EXTENT_LEN)
		return false;

	/* Can we merge the block to our big extent? */
	if (lblk == map->m_lblk + map->m_len &&
	    (bh->b_state & BH_FLAGS) == map->m_flags) {
		map->m_len++;
		return true;
	}
	return false;
}

/*
 * mpage_process_page_bufs - submit page buffers for IO or add them to extent
 *
 * @mpd - extent of blocks for mapping
 * @head - the first buffer in the page
 * @bh - buffer we should start processing from
 * @lblk - logical number of the block in the file corresponding to @bh
 *
 * Walk through page buffers from @bh upto @head (exclusive) and either submit
 * the page for IO if all buffers in this page were mapped and there's no
 * accumulated extent of buffers to map or add buffers in the page to the
 * extent of buffers to map. The function returns 1 if the caller can continue
 * by processing the next page, 0 if it should stop adding buffers to the
 * extent to map because we cannot extend it anymore. It can also return value
 * < 0 in case of error during IO submission.
 */
static int mpage_process_page_bufs(struct mpage_da_data *mpd,
				   struct buffer_head *head,
				   struct buffer_head *bh,
				   mockfs_lblk_t lblk)
{
	struct inode *inode = mpd->inode;
	int err;
	mockfs_lblk_t blocks = (i_size_read(inode) + (1 << inode->i_blkbits) - 1)
							>> inode->i_blkbits;

	do {
		BUG_ON(buffer_locked(bh));

		if (lblk >= blocks || !mpage_add_bh_to_extent(mpd, lblk, bh)) {
			/* Found extent to map? */
			if (mpd->map.m_len)
				return 0;
			/* Everything mapped so far and we hit EOF */
			break;
		}
	} while (lblk++, (bh = bh->b_this_page) != head);
	/* So far everything mapped? Submit the page for IO. */
	if (mpd->map.m_len == 0) {
		err = mpage_submit_page(mpd, head->b_page);
		if (err < 0)
			return err;
	}
	return lblk < blocks;
}

/*
 * mpage_map_buffers - update buffers corresponding to changed extent and
 *		       submit fully mapped pages for IO
 *
 * @mpd - description of extent to map, on return next extent to map
 *
 * Scan buffers corresponding to changed extent (we expect corresponding pages
 * to be already locked) and update buffer state according to new extent state.
 * We map delalloc buffers to their physical location, clear unwritten bits,
 * and mark buffers as uninit when we perform writes to unwritten extents
 * and do extent conversion after IO is finished. If the last page is not fully
 * mapped, we update @map to the next extent in the last page that needs
 * mapping. Otherwise we submit the page for IO.
 */
static int mpage_map_and_submit_buffers(struct mpage_da_data *mpd)
{
	struct pagevec pvec;
	int nr_pages, i;
	struct inode *inode = mpd->inode;
	struct buffer_head *head, *bh;
	int bpp_bits = PAGE_SHIFT - inode->i_blkbits;
	pgoff_t start, end;
	mockfs_lblk_t lblk;
	sector_t pblock;
	int err;

	start = mpd->map.m_lblk >> bpp_bits;
	end = (mpd->map.m_lblk + mpd->map.m_len - 1) >> bpp_bits;
	lblk = start << bpp_bits;
	pblock = mpd->map.m_pblk;

	pagevec_init(&pvec, 0);
	while (start <= end) {
		nr_pages = pagevec_lookup(&pvec, inode->i_mapping, start,
					  PAGEVEC_SIZE);
		if (nr_pages == 0)
			break;
		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			if (page->index > end)
				break;
			/* Up to 'end' pages must be contiguous */
			BUG_ON(page->index != start);
			bh = head = page_buffers(page);
			do {
				if (lblk < mpd->map.m_lblk)
					continue;
				if (lblk >= mpd->map.m_lblk + mpd->map.m_len) {
					/*
					 * Buffer after end of mapped extent.
					 * Find next buffer in the page to map.
					 */
					mpd->map.m_len = 0;
					mpd->map.m_flags = 0;
					/*
					 * FIXME: If dioread_nolock supports
					 * blocksize < pagesize, we need to make
					 * sure we add size mapped so far to
					 * io_end->size as the following call
					 * can submit the page for IO.
					 */
					err = mpage_process_page_bufs(mpd, head,
								      bh, lblk);
					pagevec_release(&pvec);
					if (err > 0)
						err = 0;
					return err;
				}
				if (buffer_delay(bh)) {
					clear_buffer_delay(bh);
					bh->b_blocknr = pblock++;
				}
				clear_buffer_unwritten(bh);
			} while (lblk++, (bh = bh->b_this_page) != head);

			/*
			 * FIXME: This is going to break if dioread_nolock
			 * supports blocksize < pagesize as we will try to
			 * convert potentially unmapped parts of inode.
			 */
			mpd->io_submit.io_end->size += PAGE_SIZE;
			/* Page fully mapped - let IO run! */
			err = mpage_submit_page(mpd, page);
			if (err < 0) {
				pagevec_release(&pvec);
				return err;
			}
			start++;
		}
		pagevec_release(&pvec);
	}
	/* Extent fully mapped and matches with page boundary. We are done. */
	mpd->map.m_len = 0;
	mpd->map.m_flags = 0;
	return 0;
}

static int mpage_map_one_extent(handle_t *handle, struct mpage_da_data *mpd)
{
	struct inode *inode = mpd->inode;
	struct mockfs_map_blocks *map = &mpd->map;
	int get_blocks_flags;
	int err, dioread_nolock;

	/*
	 * Call mockfs_map_blocks() to allocate any delayed allocation blocks, or
	 * to convert an unwritten extent to be initialized (in the case
	 * where we have written into one or more preallocated blocks).  It is
	 * possible that we're going to need more metadata blocks than
	 * previously reserved. However we must not fail because we're in
	 * writeback and there is nothing we can do about it so it might result
	 * in data loss.  So use reserved blocks to allocate metadata if
	 * possible.
	 *
	 * We pass in the magic MOCKFS_GET_BLOCKS_DELALLOC_RESERVE if
	 * the blocks in question are delalloc blocks.  This indicates
	 * that the blocks and quotas has already been checked when
	 * the data was copied into the page cache.
	 */
	get_blocks_flags = MOCKFS_GET_BLOCKS_CREATE |
			   MOCKFS_GET_BLOCKS_METADATA_NOFAIL;
	dioread_nolock = mockfs_should_dioread_nolock(inode);
	if (dioread_nolock)
		get_blocks_flags |= MOCKFS_GET_BLOCKS_IO_CREATE_EXT;
	if (map->m_flags & (1 << BH_Delay))
		get_blocks_flags |= MOCKFS_GET_BLOCKS_DELALLOC_RESERVE;

	err = mockfs_map_blocks(handle, inode, map, get_blocks_flags);
	if (err < 0)
		return err;
	if (dioread_nolock && (map->m_flags & MOCKFS_MAP_UNWRITTEN)) {
		if (!mpd->io_submit.io_end->handle &&
		    mockfs_handle_valid(handle)) {
			mpd->io_submit.io_end->handle = handle->h_rsv_handle;
			handle->h_rsv_handle = NULL;
		}
		mockfs_set_io_unwritten_flag(inode, mpd->io_submit.io_end);
	}

	BUG_ON(map->m_len == 0);
	if (map->m_flags & MOCKFS_MAP_NEW) {
		struct block_device *bdev = inode->i_sb->s_bdev;
		int i;

		for (i = 0; i < map->m_len; i++)
			unmap_underlying_metadata(bdev, map->m_pblk + i);
	}
	return 0;
}

/*
 * mpage_map_and_submit_extent - map extent starting at mpd->lblk of length
 *				 mpd->len and submit pages underlying it for IO
 *
 * @handle - handle for journal operations
 * @mpd - extent to map
 * @give_up_on_write - we set this to true iff there is a fatal error and there
 *                     is no hope of writing the data. The caller should discard
 *                     dirty pages to avoid infinite loops.
 *
 * The function maps extent starting at mpd->lblk of length mpd->len. If it is
 * delayed, blocks are allocated, if it is unwritten, we may need to convert
 * them to initialized or split the described range from larger unwritten
 * extent. Note that we need not map all the described range since allocation
 * can return less blocks or the range is covered by more unwritten extents. We
 * cannot map more because we are limited by reserved transaction credits. On
 * the other hand we always make sure that the last touched page is fully
 * mapped so that it can be written out (and thus forward progress is
 * guaranteed). After mapping we submit all mapped pages for IO.
 */
static int mpage_map_and_submit_extent(handle_t *handle,
				       struct mpage_da_data *mpd,
				       bool *give_up_on_write)
{
	struct inode *inode = mpd->inode;
	struct mockfs_map_blocks *map = &mpd->map;
	int err;
	loff_t disksize;
	int progress = 0;

	mpd->io_submit.io_end->offset =
				((loff_t)map->m_lblk) << inode->i_blkbits;
	do {
		err = mpage_map_one_extent(handle, mpd);
		if (err < 0) {
			struct super_block *sb = inode->i_sb;

			if (MOCKFS_SB(sb)->s_mount_flags & MOCKFS_MF_FS_ABORTED)
				goto invalidate_dirty_pages;
			/*
			 * Let the uper layers retry transient errors.
			 * In the case of ENOSPC, if mockfs_count_free_blocks()
			 * is non-zero, a commit should free up blocks.
			 */
			if ((err == -ENOMEM) ||
			    (err == -ENOSPC && mockfs_count_free_clusters(sb))) {
				if (progress)
					goto update_disksize;
				return err;
			}
			mockfs_msg(sb, KERN_CRIT,
				 "Delayed block allocation failed for "
				 "inode %lu at logical offset %llu with"
				 " max blocks %u with error %d",
				 inode->i_ino,
				 (unsigned long long)map->m_lblk,
				 (unsigned)map->m_len, -err);
			mockfs_msg(sb, KERN_CRIT,
				 "This should not happen!! Data will "
				 "be lost\n");
			if (err == -ENOSPC)
				mockfs_print_free_blocks(inode);
		invalidate_dirty_pages:
			*give_up_on_write = true;
			return err;
		}
		progress = 1;
		/*
		 * Update buffer state, submit mapped pages, and get us new
		 * extent to map
		 */
		err = mpage_map_and_submit_buffers(mpd);
		if (err < 0)
			goto update_disksize;
	} while (map->m_len);

update_disksize:
	/*
	 * Update on-disk size after IO is submitted.  Races with
	 * truncate are avoided by checking i_size under i_data_sem.
	 */
	disksize = ((loff_t)mpd->first_page) << PAGE_SHIFT;
	if (disksize > MOCKFS_I(inode)->i_disksize) {
		int err2;
		loff_t i_size;

		down_write(&MOCKFS_I(inode)->i_data_sem);
		i_size = i_size_read(inode);
		if (disksize > i_size)
			disksize = i_size;
		if (disksize > MOCKFS_I(inode)->i_disksize)
			MOCKFS_I(inode)->i_disksize = disksize;
		err2 = mockfs_mark_inode_dirty(handle, inode);
		up_write(&MOCKFS_I(inode)->i_data_sem);
		if (err2)
			mockfs_error(inode->i_sb,
				   "Failed to mark inode %lu dirty",
				   inode->i_ino);
		if (!err)
			err = err2;
	}
	return err;
}

/*
 * Calculate the total number of credits to reserve for one writepages
 * iteration. This is called from mockfs_writepages(). We map an extent of
 * up to MAX_WRITEPAGES_EXTENT_LEN blocks and then we go on and finish mapping
 * the last partial page. So in total we can map MAX_WRITEPAGES_EXTENT_LEN +
 * bpp - 1 blocks in bpp different extents.
 */
static int mockfs_da_writepages_trans_blocks(struct inode *inode)
{
	int bpp = mockfs_journal_blocks_per_page(inode);

	return mockfs_meta_trans_blocks(inode,
				MAX_WRITEPAGES_EXTENT_LEN + bpp - 1, bpp);
}

/*
 * mpage_prepare_extent_to_map - find & lock contiguous range of dirty pages
 * 				 and underlying extent to map
 *
 * @mpd - where to look for pages
 *
 * Walk dirty pages in the mapping. If they are fully mapped, submit them for
 * IO immediately. When we find a page which isn't mapped we start accumulating
 * extent of buffers underlying these pages that needs mapping (formed by
 * either delayed or unwritten buffers). We also lock the pages containing
 * these buffers. The extent found is returned in @mpd structure (starting at
 * mpd->lblk with length mpd->len blocks).
 *
 * Note that this function can attach bios to one io_end structure which are
 * neither logically nor physically contiguous. Although it may seem as an
 * unnecessary complication, it is actually inevitable in blocksize < pagesize
 * case as we need to track IO to all buffers underlying a page in one io_end.
 */
static int mpage_prepare_extent_to_map(struct mpage_da_data *mpd)
{
	struct address_space *mapping = mpd->inode->i_mapping;
	struct pagevec pvec;
	unsigned int nr_pages;
	long left = mpd->wbc->nr_to_write;
	pgoff_t index = mpd->first_page;
	pgoff_t end = mpd->last_page;
	int tag;
	int i, err = 0;
	int blkbits = mpd->inode->i_blkbits;
	mockfs_lblk_t lblk;
	struct buffer_head *head;

	if (mpd->wbc->sync_mode == WB_SYNC_ALL || mpd->wbc->tagged_writepages)
		tag = PAGECACHE_TAG_TOWRITE;
	else
		tag = PAGECACHE_TAG_DIRTY;

	pagevec_init(&pvec, 0);
	mpd->map.m_len = 0;
	mpd->next_page = index;
	while (index <= end) {
		nr_pages = pagevec_lookup_tag(&pvec, mapping, &index, tag,
			      min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1);
		if (nr_pages == 0)
			goto out;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/*
			 * At this point, the page may be truncated or
			 * invalidated (changing page->mapping to NULL), or
			 * even swizzled back from swapper_space to tmpfs file
			 * mapping. However, page->index will not change
			 * because we have a reference on the page.
			 */
			if (page->index > end)
				goto out;

			/*
			 * Accumulated enough dirty pages? This doesn't apply
			 * to WB_SYNC_ALL mode. For integrity sync we have to
			 * keep going because someone may be concurrently
			 * dirtying pages, and we might have synced a lot of
			 * newly appeared dirty pages, but have not synced all
			 * of the old dirty pages.
			 */
			if (mpd->wbc->sync_mode == WB_SYNC_NONE && left <= 0)
				goto out;

			/* If we can't merge this page, we are done. */
			if (mpd->map.m_len > 0 && mpd->next_page != page->index)
				goto out;

			lock_page(page);
			/*
			 * If the page is no longer dirty, or its mapping no
			 * longer corresponds to inode we are writing (which
			 * means it has been truncated or invalidated), or the
			 * page is already under writeback and we are not doing
			 * a data integrity writeback, skip the page
			 */
			if (!PageDirty(page) ||
			    (PageWriteback(page) &&
			     (mpd->wbc->sync_mode == WB_SYNC_NONE)) ||
			    unlikely(page->mapping != mapping)) {
				unlock_page(page);
				continue;
			}

			wait_on_page_writeback(page);
			BUG_ON(PageWriteback(page));

			if (mpd->map.m_len == 0)
				mpd->first_page = page->index;
			mpd->next_page = page->index + 1;
			/* Add all dirty buffers to mpd */
			lblk = ((mockfs_lblk_t)page->index) <<
				(PAGE_SHIFT - blkbits);
			head = page_buffers(page);
			err = mpage_process_page_bufs(mpd, head, head, lblk);
			if (err <= 0)
				goto out;
			err = 0;
			left--;
		}
		pagevec_release(&pvec);
		cond_resched();
	}
	return 0;
out:
	pagevec_release(&pvec);
	return err;
}

static int __writepage(struct page *page, struct writeback_control *wbc,
		       void *data)
{
	struct address_space *mapping = data;
	int ret = mockfs_writepage(page, wbc);
	mapping_set_error(mapping, ret);
	return ret;
}

static int mockfs_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	pgoff_t	writeback_index = 0;
	long nr_to_write = wbc->nr_to_write;
	int range_whole = 0;
	int cycled = 1;
	handle_t *handle = NULL;
	struct mpage_da_data mpd;
	struct inode *inode = mapping->host;
	int needed_blocks, rsv_blocks = 0, ret = 0;
	struct mockfs_sb_info *sbi = MOCKFS_SB(mapping->host->i_sb);
	bool done;
	struct blk_plug plug;
	bool give_up_on_write = false;


	if (dax_mapping(mapping))
		return dax_writeback_mapping_range(mapping, inode->i_sb->s_bdev,
						   wbc);

	/*
	 * No pages to write? This is mainly a kludge to avoid starting
	 * a transaction for special inodes like journal inode on last iput()
	 * because that could violate lock ordering on umount
	 */
	if (!mapping->nrpages || !mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
		goto out_writepages;

	if (mockfs_should_journal_data(inode)) {
		struct blk_plug plug;

		blk_start_plug(&plug);
		ret = write_cache_pages(mapping, wbc, __writepage, mapping);
		blk_finish_plug(&plug);
		goto out_writepages;
	}

	/*
	 * If the filesystem has aborted, it is read-only, so return
	 * right away instead of dumping stack traces later on that
	 * will obscure the real source of the problem.  We test
	 * MOCKFS_MF_FS_ABORTED instead of sb->s_flag's MS_RDONLY because
	 * the latter could be true if the filesystem is mounted
	 * read-only, and in that case, mockfs_writepages should
	 * *never* be called, so if that ever happens, we would want
	 * the stack trace.
	 */
	if (unlikely(sbi->s_mount_flags & MOCKFS_MF_FS_ABORTED)) {
		ret = -EROFS;
		goto out_writepages;
	}

	if (mockfs_should_dioread_nolock(inode)) {
		/*
		 * We may need to convert up to one extent per block in
		 * the page and we may dirty the inode.
		 */
		rsv_blocks = 1 + (PAGE_SIZE >> inode->i_blkbits);
	}

	/*
	 * If we have inline data and arrive here, it means that
	 * we will soon create the block for the 1st page, so
	 * we'd better clear the inline data here.
	 */
	if (mockfs_has_inline_data(inode)) {
		/* Just inode will be modified... */
		handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, 1);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto out_writepages;
		}
		BUG_ON(mockfs_test_inode_state(inode,
				MOCKFS_STATE_MAY_INLINE_DATA));
		mockfs_destroy_inline_data(handle, inode);
		mockfs_journal_stop(handle);
	}

	if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
		range_whole = 1;

	if (wbc->range_cyclic) {
		writeback_index = mapping->writeback_index;
		if (writeback_index)
			cycled = 0;
		mpd.first_page = writeback_index;
		mpd.last_page = -1;
	} else {
		mpd.first_page = wbc->range_start >> PAGE_SHIFT;
		mpd.last_page = wbc->range_end >> PAGE_SHIFT;
	}

	mpd.inode = inode;
	mpd.wbc = wbc;
	mockfs_io_submit_init(&mpd.io_submit, wbc);
retry:
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag_pages_for_writeback(mapping, mpd.first_page, mpd.last_page);
	done = false;
	blk_start_plug(&plug);
	while (!done && mpd.first_page <= mpd.last_page) {
		/* For each extent of pages we use new io_end */
		mpd.io_submit.io_end = mockfs_init_io_end(inode, GFP_KERNEL);
		if (!mpd.io_submit.io_end) {
			ret = -ENOMEM;
			break;
		}

		/*
		 * We have two constraints: We find one extent to map and we
		 * must always write out whole page (makes a difference when
		 * blocksize < pagesize) so that we don't block on IO when we
		 * try to write out the rest of the page. Journalled mode is
		 * not supported by delalloc.
		 */
		BUG_ON(mockfs_should_journal_data(inode));
		needed_blocks = mockfs_da_writepages_trans_blocks(inode);

		/* start a new transaction */
		handle = mockfs_journal_start_with_reserve(inode,
				MOCKFS_HT_WRITE_PAGE, needed_blocks, rsv_blocks);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			mockfs_msg(inode->i_sb, KERN_CRIT, "%s: jbd2_start: "
			       "%ld pages, ino %lu; err %d", __func__,
				wbc->nr_to_write, inode->i_ino, ret);
			/* Release allocated io_end */
			mockfs_put_io_end(mpd.io_submit.io_end);
			break;
		}

		ret = mpage_prepare_extent_to_map(&mpd);
		if (!ret) {
			if (mpd.map.m_len)
				ret = mpage_map_and_submit_extent(handle, &mpd,
					&give_up_on_write);
			else {
				/*
				 * We scanned the whole range (or exhausted
				 * nr_to_write), submitted what was mapped and
				 * didn't find anything needing mapping. We are
				 * done.
				 */
				done = true;
			}
		}
		mockfs_journal_stop(handle);
		/* Submit prepared bio */
		mockfs_io_submit(&mpd.io_submit);
		/* Unlock pages we didn't use */
		mpage_release_unused_pages(&mpd, give_up_on_write);
		/* Drop our io_end reference we got from init */
		mockfs_put_io_end(mpd.io_submit.io_end);

		if (ret == -ENOSPC && sbi->s_journal) {
			/*
			 * Commit the transaction which would
			 * free blocks released in the transaction
			 * and try again
			 */
			jbd2_journal_force_commit_nested(sbi->s_journal);
			ret = 0;
			continue;
		}
		/* Fatal error - ENOMEM, EIO... */
		if (ret)
			break;
	}
	blk_finish_plug(&plug);
	if (!ret && !cycled && wbc->nr_to_write > 0) {
		cycled = 1;
		mpd.last_page = writeback_index - 1;
		mpd.first_page = 0;
		goto retry;
	}

	/* Update index */
	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		/*
		 * Set the writeback_index so that range_cyclic
		 * mode will write it back later
		 */
		mapping->writeback_index = mpd.first_page;

out_writepages:
	return ret;
}

static int mockfs_nonda_switch(struct super_block *sb)
{
	s64 free_clusters, dirty_clusters;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);

	/*
	 * switch to non delalloc mode if we are running low
	 * on free block. The free block accounting via percpu
	 * counters can get slightly wrong with percpu_counter_batch getting
	 * accumulated on each CPU without updating global counters
	 * Delalloc need an accurate free block accounting. So switch
	 * to non delalloc when we are near to error range.
	 */
	free_clusters =
		percpu_counter_read_positive(&sbi->s_freeclusters_counter);
	dirty_clusters =
		percpu_counter_read_positive(&sbi->s_dirtyclusters_counter);
	/*
	 * Start pushing delalloc when 1/2 of free blocks are dirty.
	 */
	if (dirty_clusters && (free_clusters < 2 * dirty_clusters))
		try_to_writeback_inodes_sb(sb, WB_REASON_FS_FREE_SPACE);

	if (2 * free_clusters < 3 * dirty_clusters ||
	    free_clusters < (dirty_clusters + MOCKFS_FREECLUSTERS_WATERMARK)) {
		/*
		 * free block count is less than 150% of dirty blocks
		 * or free blocks is less than watermark
		 */
		return 1;
	}
	return 0;
}

/* We always reserve for an inode update; the superblock could be there too */
static int mockfs_da_write_credits(struct inode *inode, loff_t pos, unsigned len)
{
	if (likely(mockfs_has_feature_large_file(inode->i_sb)))
		return 1;

	if (pos + len <= 0x7fffffffULL)
		return 1;

	/* We might need to update the superblock to set LARGE_FILE */
	return 2;
}

static int mockfs_da_write_begin(struct file *file, struct address_space *mapping,
			       loff_t pos, unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	int ret, retries = 0;
	struct page *page;
	pgoff_t index;
	struct inode *inode = mapping->host;
	handle_t *handle;

	index = pos >> PAGE_SHIFT;

	if (mockfs_nonda_switch(inode->i_sb)) {
		*fsdata = (void *)FALL_BACK_TO_NONDELALLOC;
		return mockfs_write_begin(file, mapping, pos,
					len, flags, pagep, fsdata);
	}
	*fsdata = (void *)0;

	if (mockfs_test_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA)) {
		ret = mockfs_da_write_inline_data_begin(mapping, inode,
						      pos, len, flags,
						      pagep, fsdata);
		if (ret < 0)
			return ret;
		if (ret == 1)
			return 0;
	}

	/*
	 * grab_cache_page_write_begin() can take a long time if the
	 * system is thrashing due to memory pressure, or if the page
	 * is being written back.  So grab it first before we start
	 * the transaction handle.  This also allows us to allocate
	 * the page (if needed) without using GFP_NOFS.
	 */
retry_grab:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	unlock_page(page);

	/*
	 * With delayed allocation, we don't log the i_disksize update
	 * if there is delayed block allocation. But we still need
	 * to journalling the i_disksize update if writes to the end
	 * of file which has an already mapped buffer.
	 */
retry_journal:
	handle = mockfs_journal_start(inode, MOCKFS_HT_WRITE_PAGE,
				mockfs_da_write_credits(inode, pos, len));
	if (IS_ERR(handle)) {
		put_page(page);
		return PTR_ERR(handle);
	}

	lock_page(page);
	if (page->mapping != mapping) {
		/* The page got truncated from under us */
		unlock_page(page);
		put_page(page);
		mockfs_journal_stop(handle);
		goto retry_grab;
	}
	/* In case writeback began while the page was unlocked */
	wait_for_stable_page(page);

#ifdef CONFIG_MOCKFS_FS_ENCRYPTION
	ret = mockfs_block_write_begin(page, pos, len,
				     mockfs_da_get_block_prep);
#else
	ret = __block_write_begin(page, pos, len, mockfs_da_get_block_prep);
#endif
	if (ret < 0) {
		unlock_page(page);
		mockfs_journal_stop(handle);
		/*
		 * block_write_begin may have instantiated a few blocks
		 * outside i_size.  Trim these off again. Don't need
		 * i_size_read because we hold i_mutex.
		 */
		if (pos + len > inode->i_size)
			mockfs_truncate_failed_write(inode);

		if (ret == -ENOSPC &&
		    mockfs_should_retry_alloc(inode->i_sb, &retries))
			goto retry_journal;

		put_page(page);
		return ret;
	}

	*pagep = page;
	return ret;
}

/*
 * Check if we should update i_disksize
 * when write to the end of file but not require block allocation
 */
static int mockfs_da_should_update_i_disksize(struct page *page,
					    unsigned long offset)
{
	struct buffer_head *bh;
	struct inode *inode = page->mapping->host;
	unsigned int idx;
	int i;

	bh = page_buffers(page);
	idx = offset >> inode->i_blkbits;

	for (i = 0; i < idx; i++)
		bh = bh->b_this_page;

	if (!buffer_mapped(bh) || (buffer_delay(bh)) || buffer_unwritten(bh))
		return 0;
	return 1;
}

static int mockfs_da_write_end(struct file *file,
			     struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	int ret = 0, ret2;
	handle_t *handle = mockfs_journal_current_handle();
	loff_t new_i_size;
	unsigned long start, end;
	int write_mode = (int)(unsigned long)fsdata;

	if (write_mode == FALL_BACK_TO_NONDELALLOC)
		return mockfs_write_end(file, mapping, pos,
				      len, copied, page, fsdata);

	start = pos & (PAGE_SIZE - 1);
	end = start + copied - 1;

	/*
	 * generic_write_end() will run mark_inode_dirty() if i_size
	 * changes.  So let's piggyback the i_disksize mark_inode_dirty
	 * into that.
	 */
	new_i_size = pos + copied;
	if (copied && new_i_size > MOCKFS_I(inode)->i_disksize) {
		if (mockfs_has_inline_data(inode) ||
		    mockfs_da_should_update_i_disksize(page, end)) {
			mockfs_update_i_disksize(inode, new_i_size);
			/* We need to mark inode dirty even if
			 * new_i_size is less that inode->i_size
			 * bu greater than i_disksize.(hint delalloc)
			 */
			mockfs_mark_inode_dirty(handle, inode);
		}
	}

	if (write_mode != CONVERT_INLINE_DATA &&
	    mockfs_test_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA) &&
	    mockfs_has_inline_data(inode))
		ret2 = mockfs_da_write_inline_data_end(inode, pos, len, copied,
						     page);
	else
		ret2 = generic_write_end(file, mapping, pos, len, copied,
							page, fsdata);

	copied = ret2;
	if (ret2 < 0)
		ret = ret2;
	ret2 = mockfs_journal_stop(handle);
	if (!ret)
		ret = ret2;

	return ret ? ret : copied;
}

static void mockfs_da_invalidatepage(struct page *page, unsigned int offset,
				   unsigned int length)
{
	/*
	 * Drop reserved blocks
	 */
	BUG_ON(!PageLocked(page));
	if (!page_has_buffers(page))
		goto out;

	mockfs_da_page_release_reservation(page, offset, length);

out:
	mockfs_invalidatepage(page, offset, length);

	return;
}

/*
 * Force all delayed allocation blocks to be allocated for a given inode.
 */
int mockfs_alloc_da_blocks(struct inode *inode)
{

	if (!MOCKFS_I(inode)->i_reserved_data_blocks)
		return 0;

	/*
	 * We do something simple for now.  The filemap_flush() will
	 * also start triggering a write of the data blocks, which is
	 * not strictly speaking necessary (and for users of
	 * laptop_mode, not even desirable).  However, to do otherwise
	 * would require replicating code paths in:
	 *
	 * mockfs_writepages() ->
	 *    write_cache_pages() ---> (via passed in callback function)
	 *        __mpage_da_writepage() -->
	 *           mpage_add_bh_to_extent()
	 *           mpage_da_map_blocks()
	 *
	 * The problem is that write_cache_pages(), located in
	 * mm/page-writeback.c, marks pages clean in preparation for
	 * doing I/O, which is not desirable if we're not planning on
	 * doing I/O at all.
	 *
	 * We could call write_cache_pages(), and then redirty all of
	 * the pages by calling redirty_page_for_writepage() but that
	 * would be ugly in the extreme.  So instead we would need to
	 * replicate parts of the code in the above functions,
	 * simplifying them because we wouldn't actually intend to
	 * write out the pages, but rather only collect contiguous
	 * logical block extents, call the multi-block allocator, and
	 * then update the buffer heads with the block allocations.
	 *
	 * For now, though, we'll cheat by calling filemap_flush(),
	 * which will map the blocks, and start the I/O, but not
	 * actually wait for the I/O to complete.
	 */
	return filemap_flush(inode->i_mapping);
}

/*
 * bmap() is special.  It gets used by applications such as lilo and by
 * the swapper to find the on-disk block of a specific piece of data.
 *
 * Naturally, this is dangerous if the block concerned is still in the
 * journal.  If somebody makes a swapfile on an mockfs data-journaling
 * filesystem and enables swap, then they may get a nasty shock when the
 * data getting swapped to that swapfile suddenly gets overwritten by
 * the original zero's written out previously to the journal and
 * awaiting writeback in the kernel's buffer cache.
 *
 * So, if we see any bmap calls here on a modified, data-journaled file,
 * take extra steps to flush any blocks which might be in the cache.
 */
static sector_t mockfs_bmap(struct address_space *mapping, sector_t block)
{
	struct inode *inode = mapping->host;
	journal_t *journal;
	int err;

	/*
	 * We can get here for an inline file via the FIBMAP ioctl
	 */
	if (mockfs_has_inline_data(inode))
		return 0;

	if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY) &&
			test_opt(inode->i_sb, DELALLOC)) {
		/*
		 * With delalloc we want to sync the file
		 * so that we can make sure we allocate
		 * blocks for file
		 */
		filemap_write_and_wait(mapping);
	}

	if (MOCKFS_JOURNAL(inode) &&
	    mockfs_test_inode_state(inode, MOCKFS_STATE_JDATA)) {
		/*
		 * This is a REALLY heavyweight approach, but the use of
		 * bmap on dirty files is expected to be extremely rare:
		 * only if we run lilo or swapon on a freshly made file
		 * do we expect this to happen.
		 *
		 * (bmap requires CAP_SYS_RAWIO so this does not
		 * represent an unprivileged user DOS attack --- we'd be
		 * in trouble if mortal users could trigger this path at
		 * will.)
		 *
		 * NB. MOCKFS_STATE_JDATA is not set on files other than
		 * regular files.  If somebody wants to bmap a directory
		 * or symlink and gets confused because the buffer
		 * hasn't yet been flushed to disk, they deserve
		 * everything they get.
		 */

		mockfs_clear_inode_state(inode, MOCKFS_STATE_JDATA);
		journal = MOCKFS_JOURNAL(inode);
		jbd2_journal_lock_updates(journal);
		err = jbd2_journal_flush(journal);
		jbd2_journal_unlock_updates(journal);

		if (err)
			return 0;
	}

	return generic_block_bmap(mapping, block, mockfs_get_block);
}

static int mockfs_readpage(struct file *file, struct page *page)
{
	int ret = -EAGAIN;
	struct inode *inode = page->mapping->host;


	if (mockfs_has_inline_data(inode))
		ret = mockfs_readpage_inline(inode, page);

	if (ret == -EAGAIN)
		return mockfs_mpage_readpages(page->mapping, NULL, page, 1);

	return ret;
}

static int
mockfs_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;

	/* If the file has inline data, no need to do readpages. */
	if (mockfs_has_inline_data(inode))
		return 0;

	return mockfs_mpage_readpages(mapping, pages, NULL, nr_pages);
}

static void mockfs_invalidatepage(struct page *page, unsigned int offset,
				unsigned int length)
{

	/* No journalling happens on data buffers when this function is used */
	WARN_ON(page_has_buffers(page) && buffer_jbd(page_buffers(page)));

	block_invalidatepage(page, offset, length);
}

static int __mockfs_journalled_invalidatepage(struct page *page,
					    unsigned int offset,
					    unsigned int length)
{
	journal_t *journal = MOCKFS_JOURNAL(page->mapping->host);


	/*
	 * If it's a full truncate we just forget about the pending dirtying
	 */
	if (offset == 0 && length == PAGE_SIZE)
		ClearPageChecked(page);

	return jbd2_journal_invalidatepage(journal, page, offset, length);
}

/* Wrapper for aops... */
static void mockfs_journalled_invalidatepage(struct page *page,
					   unsigned int offset,
					   unsigned int length)
{
	WARN_ON(__mockfs_journalled_invalidatepage(page, offset, length) < 0);
}

static int mockfs_releasepage(struct page *page, gfp_t wait)
{
	journal_t *journal = MOCKFS_JOURNAL(page->mapping->host);


	/* Page has dirty journalled data -> cannot release */
	if (PageChecked(page))
		return 0;
	if (journal)
		return jbd2_journal_try_to_free_buffers(journal, page, wait);
	else
		return try_to_free_buffers(page);
}

#ifdef CONFIG_FS_DAX
int mockfs_dax_mmap_get_block(struct inode *inode, sector_t iblock,
			    struct buffer_head *bh_result, int create)
{
	int ret, err;
	int credits;
	struct mockfs_map_blocks map;
	handle_t *handle = NULL;
	int flags = 0;

	mockfs_debug("mockfs_dax_mmap_get_block: inode %lu, create flag %d\n",
		   inode->i_ino, create);
	map.m_lblk = iblock;
	map.m_len = bh_result->b_size >> inode->i_blkbits;
	credits = mockfs_chunk_trans_blocks(inode, map.m_len);
	if (create) {
		flags |= MOCKFS_GET_BLOCKS_PRE_IO | MOCKFS_GET_BLOCKS_CREATE_ZERO;
		handle = mockfs_journal_start(inode, MOCKFS_HT_MAP_BLOCKS, credits);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			return ret;
		}
	}

	ret = mockfs_map_blocks(handle, inode, &map, flags);
	if (create) {
		err = mockfs_journal_stop(handle);
		if (ret >= 0 && err < 0)
			ret = err;
	}
	if (ret <= 0)
		goto out;
	if (map.m_flags & MOCKFS_MAP_UNWRITTEN) {
		int err2;

		/*
		 * We are protected by i_mmap_sem so we know block cannot go
		 * away from under us even though we dropped i_data_sem.
		 * Convert extent to written and write zeros there.
		 *
		 * Note: We may get here even when create == 0.
		 */
		handle = mockfs_journal_start(inode, MOCKFS_HT_MAP_BLOCKS, credits);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto out;
		}

		err = mockfs_map_blocks(handle, inode, &map,
		      MOCKFS_GET_BLOCKS_CONVERT | MOCKFS_GET_BLOCKS_CREATE_ZERO);
		if (err < 0)
			ret = err;
		err2 = mockfs_journal_stop(handle);
		if (err2 < 0 && ret > 0)
			ret = err2;
	}
out:
	WARN_ON_ONCE(ret == 0 && create);
	if (ret > 0) {
		map_bh(bh_result, inode->i_sb, map.m_pblk);
		/*
		 * At least for now we have to clear BH_New so that DAX code
		 * doesn't attempt to zero blocks again in a racy way.
		 */
		map.m_flags &= ~MOCKFS_MAP_NEW;
		mockfs_update_bh_state(bh_result, map.m_flags);
		bh_result->b_size = map.m_len << inode->i_blkbits;
		ret = 0;
	}
	return ret;
}
#endif

static int mockfs_end_io_dio(struct kiocb *iocb, loff_t offset,
			    ssize_t size, void *private)
{
        mockfs_io_end_t *io_end = private;

	/* if not async direct IO just return */
	if (!io_end)
		return 0;

	ext_debug("mockfs_end_io_dio(): io_end 0x%p "
		  "for inode %lu, iocb 0x%p, offset %llu, size %zd\n",
		  io_end, io_end->inode->i_ino, iocb, offset, size);

	/*
	 * Error during AIO DIO. We cannot convert unwritten extents as the
	 * data was not written. Just clear the unwritten flag and drop io_end.
	 */
	if (size <= 0) {
		mockfs_clear_io_unwritten_flag(io_end);
		size = 0;
	}
	io_end->offset = offset;
	io_end->size = size;
	mockfs_put_io_end(io_end);

	return 0;
}

/*
 * For mockfs extent files, mockfs will do direct-io write to holes,
 * preallocated extents, and those write extend the file, no need to
 * fall back to buffered IO.
 *
 * For holes, we fallocate those blocks, mark them as unwritten
 * If those blocks were preallocated, we mark sure they are split, but
 * still keep the range to write as unwritten.
 *
 * The unwritten extents will be converted to written when DIO is completed.
 * For async direct IO, since the IO may still pending when return, we
 * set up an end_io call back function, which will do the conversion
 * when async direct IO completed.
 *
 * If the O_DIRECT write will extend the file then add this inode to the
 * orphan list.  So recovery will truncate it back to the original size
 * if the machine crashes during the write.
 *
 */
static ssize_t mockfs_ext_direct_IO(struct kiocb *iocb, struct iov_iter *iter,
				  loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;
	size_t count = iov_iter_count(iter);
	int overwrite = 0;
	get_block_t *get_block_func = NULL;
	int dio_flags = 0;
	loff_t final_size = offset + count;

	/* Use the old path for reads and writes beyond i_size. */
	if (iov_iter_rw(iter) != WRITE || final_size > inode->i_size)
		return mockfs_ind_direct_IO(iocb, iter, offset);

	BUG_ON(iocb->private == NULL);

	/*
	 * Make all waiters for direct IO properly wait also for extent
	 * conversion. This also disallows race between truncate() and
	 * overwrite DIO as i_dio_count needs to be incremented under i_mutex.
	 */
	if (iov_iter_rw(iter) == WRITE)
		inode_dio_begin(inode);

	/* If we do a overwrite dio, i_mutex locking can be released */
	overwrite = *((int *)iocb->private);

	if (overwrite)
		inode_unlock(inode);

	/*
	 * We could direct write to holes and fallocate.
	 *
	 * Allocated blocks to fill the hole are marked as unwritten to prevent
	 * parallel buffered read to expose the stale data before DIO complete
	 * the data IO.
	 *
	 * As to previously fallocated extents, mockfs get_block will just simply
	 * mark the buffer mapped but still keep the extents unwritten.
	 *
	 * For non AIO case, we will convert those unwritten extents to written
	 * after return back from blockdev_direct_IO. That way we save us from
	 * allocating io_end structure and also the overhead of offloading
	 * the extent convertion to a workqueue.
	 *
	 * For async DIO, the conversion needs to be deferred when the
	 * IO is completed. The mockfs end_io callback function will be
	 * called to take care of the conversion work.  Here for async
	 * case, we allocate an io_end structure to hook to the iocb.
	 */
	iocb->private = NULL;
	if (overwrite)
		get_block_func = mockfs_dio_get_block_overwrite;
	else if (is_sync_kiocb(iocb)) {
		get_block_func = mockfs_dio_get_block_unwritten_sync;
		dio_flags = DIO_LOCKING;
	} else {
		get_block_func = mockfs_dio_get_block_unwritten_async;
		dio_flags = DIO_LOCKING;
	}
#ifdef CONFIG_MOCKFS_FS_ENCRYPTION
	BUG_ON(mockfs_encrypted_inode(inode) && S_ISREG(inode->i_mode));
#endif
	if (IS_DAX(inode))
		ret = dax_do_io(iocb, inode, iter, offset, get_block_func,
				mockfs_end_io_dio, dio_flags);
	else
		ret = __blockdev_direct_IO(iocb, inode,
					   inode->i_sb->s_bdev, iter, offset,
					   get_block_func,
					   mockfs_end_io_dio, NULL, dio_flags);

	if (ret > 0 && !overwrite && mockfs_test_inode_state(inode,
						MOCKFS_STATE_DIO_UNWRITTEN)) {
		int err;
		/*
		 * for non AIO case, since the IO is already
		 * completed, we could do the conversion right here
		 */
		err = mockfs_convert_unwritten_extents(NULL, inode,
						     offset, ret);
		if (err < 0)
			ret = err;
		mockfs_clear_inode_state(inode, MOCKFS_STATE_DIO_UNWRITTEN);
	}

	if (iov_iter_rw(iter) == WRITE)
		inode_dio_end(inode);
	/* take i_mutex locking again if we do a ovewrite dio */
	if (overwrite)
		inode_lock(inode);

	return ret;
}

static ssize_t mockfs_direct_IO(struct kiocb *iocb, struct iov_iter *iter,
			      loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	size_t count = iov_iter_count(iter);
	ssize_t ret;

#ifdef CONFIG_MOCKFS_FS_ENCRYPTION
	if (mockfs_encrypted_inode(inode) && S_ISREG(inode->i_mode))
		return 0;
#endif

	/*
	 * If we are doing data journalling we don't support O_DIRECT
	 */
	if (mockfs_should_journal_data(inode))
		return 0;

	/* Let buffer I/O handle the inline data case. */
	if (mockfs_has_inline_data(inode))
		return 0;

	if (mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS))
		ret = mockfs_ext_direct_IO(iocb, iter, offset);
	else
		ret = mockfs_ind_direct_IO(iocb, iter, offset);
	return ret;
}

/*
 * Pages can be marked dirty completely asynchronously from mockfs's journalling
 * activity.  By filemap_sync_pte(), try_to_unmap_one(), etc.  We cannot do
 * much here because ->set_page_dirty is called under VFS locks.  The page is
 * not necessarily locked.
 *
 * We cannot just dirty the page and leave attached buffers clean, because the
 * buffers' dirty state is "definitive".  We cannot just set the buffers dirty
 * or jbddirty because all the journalling code will explode.
 *
 * So what we do is to mark the page "pending dirty" and next time writepage
 * is called, propagate that into the buffers appropriately.
 */
static int mockfs_journalled_set_page_dirty(struct page *page)
{
	SetPageChecked(page);
	return __set_page_dirty_nobuffers(page);
}

static const struct address_space_operations mockfs_aops = {
	.readpage		= mockfs_readpage,
	.readpages		= mockfs_readpages,
	.writepage		= mockfs_writepage,
	.writepages		= mockfs_writepages,
	.write_begin		= mockfs_write_begin,
	.write_end		= mockfs_write_end,
	.bmap			= mockfs_bmap,
	.invalidatepage		= mockfs_invalidatepage,
	.releasepage		= mockfs_releasepage,
	.direct_IO		= mockfs_direct_IO,
	.migratepage		= buffer_migrate_page,
	.is_partially_uptodate  = block_is_partially_uptodate,
	.error_remove_page	= generic_error_remove_page,
};

static const struct address_space_operations mockfs_journalled_aops = {
	.readpage		= mockfs_readpage,
	.readpages		= mockfs_readpages,
	.writepage		= mockfs_writepage,
	.writepages		= mockfs_writepages,
	.write_begin		= mockfs_write_begin,
	.write_end		= mockfs_journalled_write_end,
	.set_page_dirty		= mockfs_journalled_set_page_dirty,
	.bmap			= mockfs_bmap,
	.invalidatepage		= mockfs_journalled_invalidatepage,
	.releasepage		= mockfs_releasepage,
	.direct_IO		= mockfs_direct_IO,
	.is_partially_uptodate  = block_is_partially_uptodate,
	.error_remove_page	= generic_error_remove_page,
};

static const struct address_space_operations mockfs_da_aops = {
	.readpage		= mockfs_readpage,
	.readpages		= mockfs_readpages,
	.writepage		= mockfs_writepage,
	.writepages		= mockfs_writepages,
	.write_begin		= mockfs_da_write_begin,
	.write_end		= mockfs_da_write_end,
	.bmap			= mockfs_bmap,
	.invalidatepage		= mockfs_da_invalidatepage,
	.releasepage		= mockfs_releasepage,
	.direct_IO		= mockfs_direct_IO,
	.migratepage		= buffer_migrate_page,
	.is_partially_uptodate  = block_is_partially_uptodate,
	.error_remove_page	= generic_error_remove_page,
};

void mockfs_set_aops(struct inode *inode)
{
	switch (mockfs_inode_journal_mode(inode)) {
	case MOCKFS_INODE_ORDERED_DATA_MODE:
		mockfs_set_inode_state(inode, MOCKFS_STATE_ORDERED_MODE);
		break;
	case MOCKFS_INODE_WRITEBACK_DATA_MODE:
		mockfs_clear_inode_state(inode, MOCKFS_STATE_ORDERED_MODE);
		break;
	case MOCKFS_INODE_JOURNAL_DATA_MODE:
		inode->i_mapping->a_ops = &mockfs_journalled_aops;
		return;
	default:
		BUG();
	}
	if (test_opt(inode->i_sb, DELALLOC))
		inode->i_mapping->a_ops = &mockfs_da_aops;
	else
		inode->i_mapping->a_ops = &mockfs_aops;
}

static int __mockfs_block_zero_page_range(handle_t *handle,
		struct address_space *mapping, loff_t from, loff_t length)
{
	mockfs_fsblk_t index = from >> PAGE_SHIFT;
	unsigned offset = from & (PAGE_SIZE-1);
	unsigned blocksize, pos;
	mockfs_lblk_t iblock;
	struct inode *inode = mapping->host;
	struct buffer_head *bh;
	struct page *page;
	int err = 0;

	page = find_or_create_page(mapping, from >> PAGE_SHIFT,
				   mapping_gfp_constraint(mapping, ~__GFP_FS));
	if (!page)
		return -ENOMEM;

	blocksize = inode->i_sb->s_blocksize;

	iblock = index << (PAGE_SHIFT - inode->i_sb->s_blocksize_bits);

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	/* Find the buffer that contains "offset" */
	bh = page_buffers(page);
	pos = blocksize;
	while (offset >= pos) {
		bh = bh->b_this_page;
		iblock++;
		pos += blocksize;
	}
	if (buffer_freed(bh)) {
		BUFFER_TRACE(bh, "freed: skip");
		goto unlock;
	}
	if (!buffer_mapped(bh)) {
		BUFFER_TRACE(bh, "unmapped");
		mockfs_get_block(inode, iblock, bh, 0);
		/* unmapped? It's a hole - nothing to do */
		if (!buffer_mapped(bh)) {
			BUFFER_TRACE(bh, "still unmapped");
			goto unlock;
		}
	}

	/* Ok, it's mapped. Make sure it's up-to-date */
	if (PageUptodate(page))
		set_buffer_uptodate(bh);

	if (!buffer_uptodate(bh)) {
		err = -EIO;
		ll_rw_block(READ, 1, &bh);
		wait_on_buffer(bh);
		/* Uhhuh. Read error. Complain and punt. */
		if (!buffer_uptodate(bh))
			goto unlock;
		if (S_ISREG(inode->i_mode) &&
		    mockfs_encrypted_inode(inode)) {
			/* We expect the key to be set. */
			BUG_ON(!mockfs_has_encryption_key(inode));
			BUG_ON(blocksize != PAGE_SIZE);
			WARN_ON_ONCE(mockfs_decrypt(page));
		}
	}
	if (mockfs_should_journal_data(inode)) {
		BUFFER_TRACE(bh, "get write access");
		err = mockfs_journal_get_write_access(handle, bh);
		if (err)
			goto unlock;
	}
	zero_user(page, offset, length);
	BUFFER_TRACE(bh, "zeroed end of block");

	if (mockfs_should_journal_data(inode)) {
		err = mockfs_handle_dirty_metadata(handle, inode, bh);
	} else {
		err = 0;
		mark_buffer_dirty(bh);
		if (mockfs_test_inode_state(inode, MOCKFS_STATE_ORDERED_MODE))
			err = mockfs_jbd2_file_inode(handle, inode);
	}

unlock:
	unlock_page(page);
	put_page(page);
	return err;
}

/*
 * mockfs_block_zero_page_range() zeros out a mapping of length 'length'
 * starting from file offset 'from'.  The range to be zero'd must
 * be contained with in one block.  If the specified range exceeds
 * the end of the block it will be shortened to end of the block
 * that cooresponds to 'from'
 */
static int mockfs_block_zero_page_range(handle_t *handle,
		struct address_space *mapping, loff_t from, loff_t length)
{
	struct inode *inode = mapping->host;
	unsigned offset = from & (PAGE_SIZE-1);
	unsigned blocksize = inode->i_sb->s_blocksize;
	unsigned max = blocksize - (offset & (blocksize - 1));

	/*
	 * correct length if it does not fall between
	 * 'from' and the end of the block
	 */
	if (length > max || length < 0)
		length = max;

	if (IS_DAX(inode))
		return dax_zero_page_range(inode, from, length, mockfs_get_block);
	return __mockfs_block_zero_page_range(handle, mapping, from, length);
}

/*
 * mockfs_block_truncate_page() zeroes out a mapping from file offset `from'
 * up to the end of the block which corresponds to `from'.
 * This required during truncate. We need to physically zero the tail end
 * of that block so it doesn't yield old data if the file is later grown.
 */
static int mockfs_block_truncate_page(handle_t *handle,
		struct address_space *mapping, loff_t from)
{
	unsigned offset = from & (PAGE_SIZE-1);
	unsigned length;
	unsigned blocksize;
	struct inode *inode = mapping->host;

	blocksize = inode->i_sb->s_blocksize;
	length = blocksize - (offset & (blocksize - 1));

	return mockfs_block_zero_page_range(handle, mapping, from, length);
}

int mockfs_zero_partial_blocks(handle_t *handle, struct inode *inode,
			     loff_t lstart, loff_t length)
{
	struct super_block *sb = inode->i_sb;
	struct address_space *mapping = inode->i_mapping;
	unsigned partial_start, partial_end;
	mockfs_fsblk_t start, end;
	loff_t byte_end = (lstart + length - 1);
	int err = 0;

	partial_start = lstart & (sb->s_blocksize - 1);
	partial_end = byte_end & (sb->s_blocksize - 1);

	start = lstart >> sb->s_blocksize_bits;
	end = byte_end >> sb->s_blocksize_bits;

	/* Handle partial zero within the single block */
	if (start == end &&
	    (partial_start || (partial_end != sb->s_blocksize - 1))) {
		err = mockfs_block_zero_page_range(handle, mapping,
						 lstart, length);
		return err;
	}
	/* Handle partial zero out on the start of the range */
	if (partial_start) {
		err = mockfs_block_zero_page_range(handle, mapping,
						 lstart, sb->s_blocksize);
		if (err)
			return err;
	}
	/* Handle partial zero out on the end of the range */
	if (partial_end != sb->s_blocksize - 1)
		err = mockfs_block_zero_page_range(handle, mapping,
						 byte_end - partial_end,
						 partial_end + 1);
	return err;
}

int mockfs_can_truncate(struct inode *inode)
{
	if (S_ISREG(inode->i_mode))
		return 1;
	if (S_ISDIR(inode->i_mode))
		return 1;
	if (S_ISLNK(inode->i_mode))
		return !mockfs_inode_is_fast_symlink(inode);
	return 0;
}

/*
 * We have to make sure i_disksize gets properly updated before we truncate
 * page cache due to hole punching or zero range. Otherwise i_disksize update
 * can get lost as it may have been postponed to submission of writeback but
 * that will never happen after we truncate page cache.
 */
int mockfs_update_disksize_before_punch(struct inode *inode, loff_t offset,
				      loff_t len)
{
	handle_t *handle;
	loff_t size = i_size_read(inode);

	WARN_ON(!inode_is_locked(inode));
	if (offset > size || offset + len < size)
		return 0;

	if (MOCKFS_I(inode)->i_disksize >= size)
		return 0;

	handle = mockfs_journal_start(inode, MOCKFS_HT_MISC, 1);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	mockfs_update_i_disksize(inode, size);
	mockfs_mark_inode_dirty(handle, inode);
	mockfs_journal_stop(handle);

	return 0;
}

/*
 * mockfs_punch_hole: punches a hole in a file by releaseing the blocks
 * associated with the given offset and length
 *
 * @inode:  File inode
 * @offset: The offset where the hole will begin
 * @len:    The length of the hole
 *
 * Returns: 0 on success or negative on failure
 */

int mockfs_punch_hole(struct inode *inode, loff_t offset, loff_t length)
{
	struct super_block *sb = inode->i_sb;
	mockfs_lblk_t first_block, stop_block;
	struct address_space *mapping = inode->i_mapping;
	loff_t first_block_offset, last_block_offset;
	handle_t *handle;
	unsigned int credits;
	int ret = 0;

	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;


	/*
	 * Write out all dirty pages to avoid race conditions
	 * Then release them.
	 */
	if (mapping->nrpages && mapping_tagged(mapping, PAGECACHE_TAG_DIRTY)) {
		ret = filemap_write_and_wait_range(mapping, offset,
						   offset + length - 1);
		if (ret)
			return ret;
	}

	inode_lock(inode);

	/* No need to punch hole beyond i_size */
	if (offset >= inode->i_size)
		goto out_mutex;

	/*
	 * If the hole extends beyond i_size, set the hole
	 * to end after the page that contains i_size
	 */
	if (offset + length > inode->i_size) {
		length = inode->i_size +
		   PAGE_SIZE - (inode->i_size & (PAGE_SIZE - 1)) -
		   offset;
	}

	if (offset & (sb->s_blocksize - 1) ||
	    (offset + length) & (sb->s_blocksize - 1)) {
		/*
		 * Attach jinode to inode for jbd2 if we do any zeroing of
		 * partial block
		 */
		ret = mockfs_inode_attach_jinode(inode);
		if (ret < 0)
			goto out_mutex;

	}

	/* Wait all existing dio workers, newcomers will block on i_mutex */
	mockfs_inode_block_unlocked_dio(inode);
	inode_dio_wait(inode);

	/*
	 * Prevent page faults from reinstantiating pages we have released from
	 * page cache.
	 */
	down_write(&MOCKFS_I(inode)->i_mmap_sem);
	first_block_offset = round_up(offset, sb->s_blocksize);
	last_block_offset = round_down((offset + length), sb->s_blocksize) - 1;

	/* Now release the pages and zero block aligned part of pages*/
	if (last_block_offset > first_block_offset) {
		ret = mockfs_update_disksize_before_punch(inode, offset, length);
		if (ret)
			goto out_dio;
		truncate_pagecache_range(inode, first_block_offset,
					 last_block_offset);
	}

	if (mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS))
		credits = mockfs_writepage_trans_blocks(inode);
	else
		credits = mockfs_blocks_for_truncate(inode);
	handle = mockfs_journal_start(inode, MOCKFS_HT_TRUNCATE, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		mockfs_std_error(sb, ret);
		goto out_dio;
	}

	ret = mockfs_zero_partial_blocks(handle, inode, offset,
				       length);
	if (ret)
		goto out_stop;

	first_block = (offset + sb->s_blocksize - 1) >>
		MOCKFS_BLOCK_SIZE_BITS(sb);
	stop_block = (offset + length) >> MOCKFS_BLOCK_SIZE_BITS(sb);

	/* If there are no blocks to remove, return now */
	if (first_block >= stop_block)
		goto out_stop;

	down_write(&MOCKFS_I(inode)->i_data_sem);
	mockfs_discard_preallocations(inode);

	ret = mockfs_es_remove_extent(inode, first_block,
				    stop_block - first_block);
	if (ret) {
		up_write(&MOCKFS_I(inode)->i_data_sem);
		goto out_stop;
	}

	if (mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS))
		ret = mockfs_ext_remove_space(inode, first_block,
					    stop_block - 1);
	else
		ret = mockfs_ind_remove_space(handle, inode, first_block,
					    stop_block);

	up_write(&MOCKFS_I(inode)->i_data_sem);
	if (IS_SYNC(inode))
		mockfs_handle_sync(handle);

	inode->i_mtime = inode->i_ctime = mockfs_current_time(inode);
	mockfs_mark_inode_dirty(handle, inode);
out_stop:
	mockfs_journal_stop(handle);
out_dio:
	up_write(&MOCKFS_I(inode)->i_mmap_sem);
	mockfs_inode_resume_unlocked_dio(inode);
out_mutex:
	inode_unlock(inode);
	return ret;
}

int mockfs_inode_attach_jinode(struct inode *inode)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	struct jbd2_inode *jinode;

	if (ei->jinode || !MOCKFS_SB(inode->i_sb)->s_journal)
		return 0;

	jinode = jbd2_alloc_inode(GFP_KERNEL);
	spin_lock(&inode->i_lock);
	if (!ei->jinode) {
		if (!jinode) {
			spin_unlock(&inode->i_lock);
			return -ENOMEM;
		}
		ei->jinode = jinode;
		jbd2_journal_init_jbd_inode(ei->jinode, inode);
		jinode = NULL;
	}
	spin_unlock(&inode->i_lock);
	if (unlikely(jinode != NULL))
		jbd2_free_inode(jinode);
	return 0;
}

/*
 * mockfs_truncate()
 *
 * We block out mockfs_get_block() block instantiations across the entire
 * transaction, and VFS/VM ensures that mockfs_truncate() cannot run
 * simultaneously on behalf of the same inode.
 *
 * As we work through the truncate and commit bits of it to the journal there
 * is one core, guiding principle: the file's tree must always be consistent on
 * disk.  We must be able to restart the truncate after a crash.
 *
 * The file's tree may be transiently inconsistent in memory (although it
 * probably isn't), but whenever we close off and commit a journal transaction,
 * the contents of (the filesystem + the journal) must be consistent and
 * restartable.  It's pretty simple, really: bottom up, right to left (although
 * left-to-right works OK too).
 *
 * Note that at recovery time, journal replay occurs *before* the restart of
 * truncate against the orphan inode list.
 *
 * The committed inode has the new, desired i_size (which is the same as
 * i_disksize in this case).  After a crash, mockfs_orphan_cleanup() will see
 * that this inode's truncate did not complete and it will again call
 * mockfs_truncate() to have another go.  So there will be instantiated blocks
 * to the right of the truncation point in a crashed mockfs filesystem.  But
 * that's fine - as long as they are linked from the inode, the post-crash
 * mockfs_truncate() run will find them and release them.
 */
void mockfs_truncate(struct inode *inode)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	unsigned int credits;
	handle_t *handle;
	struct address_space *mapping = inode->i_mapping;

	/*
	 * There is a possibility that we're either freeing the inode
	 * or it's a completely new inode. In those cases we might not
	 * have i_mutex locked because it's not necessary.
	 */
	if (!(inode->i_state & (I_NEW|I_FREEING)))
		WARN_ON(!inode_is_locked(inode));

	if (!mockfs_can_truncate(inode))
		return;

	mockfs_clear_inode_flag(inode, MOCKFS_INODE_EOFBLOCKS);

	if (inode->i_size == 0 && !test_opt(inode->i_sb, NO_AUTO_DA_ALLOC))
		mockfs_set_inode_state(inode, MOCKFS_STATE_DA_ALLOC_CLOSE);

	if (mockfs_has_inline_data(inode)) {
		int has_inline = 1;

		mockfs_inline_data_truncate(inode, &has_inline);
		if (has_inline)
			return;
	}

	/* If we zero-out tail of the page, we have to create jinode for jbd2 */
	if (inode->i_size & (inode->i_sb->s_blocksize - 1)) {
		if (mockfs_inode_attach_jinode(inode) < 0)
			return;
	}

	if (mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS))
		credits = mockfs_writepage_trans_blocks(inode);
	else
		credits = mockfs_blocks_for_truncate(inode);

	handle = mockfs_journal_start(inode, MOCKFS_HT_TRUNCATE, credits);
	if (IS_ERR(handle)) {
		mockfs_std_error(inode->i_sb, PTR_ERR(handle));
		return;
	}

	if (inode->i_size & (inode->i_sb->s_blocksize - 1))
		mockfs_block_truncate_page(handle, mapping, inode->i_size);

	/*
	 * We add the inode to the orphan list, so that if this
	 * truncate spans multiple transactions, and we crash, we will
	 * resume the truncate when the filesystem recovers.  It also
	 * marks the inode dirty, to catch the new size.
	 *
	 * Implication: the file must always be in a sane, consistent
	 * truncatable state while each transaction commits.
	 */
	if (mockfs_orphan_add(handle, inode))
		goto out_stop;

	down_write(&MOCKFS_I(inode)->i_data_sem);

	mockfs_discard_preallocations(inode);

	if (mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS))
		mockfs_ext_truncate(handle, inode);
	else
		mockfs_ind_truncate(handle, inode);

	up_write(&ei->i_data_sem);

	if (IS_SYNC(inode))
		mockfs_handle_sync(handle);

out_stop:
	/*
	 * If this was a simple ftruncate() and the file will remain alive,
	 * then we need to clear up the orphan record which we created above.
	 * However, if this was a real unlink then we were called by
	 * mockfs_evict_inode(), and we allow that function to clean up the
	 * orphan info for us.
	 */
	if (inode->i_nlink)
		mockfs_orphan_del(handle, inode);

	inode->i_mtime = inode->i_ctime = mockfs_current_time(inode);
	mockfs_mark_inode_dirty(handle, inode);
	mockfs_journal_stop(handle);

}

/*
 * mockfs_get_inode_loc returns with an extra refcount against the inode's
 * underlying buffer_head on success. If 'in_mem' is true, we have all
 * data in memory that is needed to recreate the on-disk version of this
 * inode.
 */
static int __mockfs_get_inode_loc(struct inode *inode,
				struct mockfs_iloc *iloc, int in_mem)
{
	struct mockfs_group_desc	*gdp;
	struct buffer_head	*bh;
	struct super_block	*sb = inode->i_sb;
	mockfs_fsblk_t		block;
	int			inodes_per_block, inode_offset;

	iloc->bh = NULL;
	if (!mockfs_valid_inum(sb, inode->i_ino))
		return -EFSCORRUPTED;

	iloc->block_group = (inode->i_ino - 1) / MOCKFS_INODES_PER_GROUP(sb);
	gdp = mockfs_get_group_desc(sb, iloc->block_group, NULL);
	if (!gdp)
		return -EIO;

	/*
	 * Figure out the offset within the block group inode table
	 */
	inodes_per_block = MOCKFS_SB(sb)->s_inodes_per_block;
	inode_offset = ((inode->i_ino - 1) %
			MOCKFS_INODES_PER_GROUP(sb));
	block = mockfs_inode_table(sb, gdp) + (inode_offset / inodes_per_block);
	iloc->offset = (inode_offset % inodes_per_block) * MOCKFS_INODE_SIZE(sb);

	bh = sb_getblk(sb, block);
	if (unlikely(!bh))
		return -ENOMEM;
	if (!buffer_uptodate(bh)) {
		lock_buffer(bh);

		/*
		 * If the buffer has the write error flag, we have failed
		 * to write out another inode in the same block.  In this
		 * case, we don't have to read the block because we may
		 * read the old inode data successfully.
		 */
		if (buffer_write_io_error(bh) && !buffer_uptodate(bh))
			set_buffer_uptodate(bh);

		if (buffer_uptodate(bh)) {
			/* someone brought it uptodate while we waited */
			unlock_buffer(bh);
			goto has_buffer;
		}

		/*
		 * If we have all information of the inode in memory and this
		 * is the only valid inode in the block, we need not read the
		 * block.
		 */
		if (in_mem) {
			struct buffer_head *bitmap_bh;
			int i, start;

			start = inode_offset & ~(inodes_per_block - 1);

			/* Is the inode bitmap in cache? */
			bitmap_bh = sb_getblk(sb, mockfs_inode_bitmap(sb, gdp));
			if (unlikely(!bitmap_bh))
				goto make_io;

			/*
			 * If the inode bitmap isn't in cache then the
			 * optimisation may end up performing two reads instead
			 * of one, so skip it.
			 */
			if (!buffer_uptodate(bitmap_bh)) {
				brelse(bitmap_bh);
				goto make_io;
			}
			for (i = start; i < start + inodes_per_block; i++) {
				if (i == inode_offset)
					continue;
				if (mockfs_test_bit(i, bitmap_bh->b_data))
					break;
			}
			brelse(bitmap_bh);
			if (i == start + inodes_per_block) {
				/* all other inodes are free, so skip I/O */
				memset(bh->b_data, 0, bh->b_size);
				set_buffer_uptodate(bh);
				unlock_buffer(bh);
				goto has_buffer;
			}
		}

make_io:
		/*
		 * If we need to do any I/O, try to pre-readahead extra
		 * blocks from the inode table.
		 */
		if (MOCKFS_SB(sb)->s_inode_readahead_blks) {
			mockfs_fsblk_t b, end, table;
			unsigned num;
			__u32 ra_blks = MOCKFS_SB(sb)->s_inode_readahead_blks;

			table = mockfs_inode_table(sb, gdp);
			/* s_inode_readahead_blks is always a power of 2 */
			b = block & ~((mockfs_fsblk_t) ra_blks - 1);
			if (table > b)
				b = table;
			end = b + ra_blks;
			num = MOCKFS_INODES_PER_GROUP(sb);
			if (mockfs_has_group_desc_csum(sb))
				num -= mockfs_itable_unused_count(sb, gdp);
			table += num / inodes_per_block;
			if (end > table)
				end = table;
			while (b <= end)
				sb_breadahead(sb, b++);
		}

		/*
		 * There are other valid inodes in the buffer, this inode
		 * has in-inode xattrs, or we don't have this inode in memory.
		 * Read the block from disk.
		 */
		get_bh(bh);
		bh->b_end_io = end_buffer_read_sync;
		submit_bh(READ | REQ_META | REQ_PRIO, bh);
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh)) {
			MOCKFS_ERROR_INODE_BLOCK(inode, block,
					       "unable to read itable block");
			brelse(bh);
			return -EIO;
		}
	}
has_buffer:
	iloc->bh = bh;
	return 0;
}

int mockfs_get_inode_loc(struct inode *inode, struct mockfs_iloc *iloc)
{
	/* We have all inode data except xattrs in memory here. */
	return __mockfs_get_inode_loc(inode, iloc,
		!mockfs_test_inode_state(inode, MOCKFS_STATE_XATTR));
}

void mockfs_set_inode_flags(struct inode *inode)
{
	unsigned int flags = MOCKFS_I(inode)->i_flags;
	unsigned int new_fl = 0;

	if (flags & MOCKFS_SYNC_FL)
		new_fl |= S_SYNC;
	if (flags & MOCKFS_APPEND_FL)
		new_fl |= S_APPEND;
	if (flags & MOCKFS_IMMUTABLE_FL)
		new_fl |= S_IMMUTABLE;
	if (flags & MOCKFS_NOATIME_FL)
		new_fl |= S_NOATIME;
	if (flags & MOCKFS_DIRSYNC_FL)
		new_fl |= S_DIRSYNC;
	if (test_opt(inode->i_sb, DAX) && S_ISREG(inode->i_mode))
		new_fl |= S_DAX;
	inode_set_flags(inode, new_fl,
			S_SYNC|S_APPEND|S_IMMUTABLE|S_NOATIME|S_DIRSYNC|S_DAX);
}

/* Propagate flags from i_flags to MOCKFS_I(inode)->i_flags */
void mockfs_get_inode_flags(struct mockfs_inode_info *ei)
{
	unsigned int vfs_fl;
	unsigned long old_fl, new_fl;

	do {
		vfs_fl = ei->vfs_inode.i_flags;
		old_fl = ei->i_flags;
		new_fl = old_fl & ~(MOCKFS_SYNC_FL|MOCKFS_APPEND_FL|
				MOCKFS_IMMUTABLE_FL|MOCKFS_NOATIME_FL|
				MOCKFS_DIRSYNC_FL);
		if (vfs_fl & S_SYNC)
			new_fl |= MOCKFS_SYNC_FL;
		if (vfs_fl & S_APPEND)
			new_fl |= MOCKFS_APPEND_FL;
		if (vfs_fl & S_IMMUTABLE)
			new_fl |= MOCKFS_IMMUTABLE_FL;
		if (vfs_fl & S_NOATIME)
			new_fl |= MOCKFS_NOATIME_FL;
		if (vfs_fl & S_DIRSYNC)
			new_fl |= MOCKFS_DIRSYNC_FL;
	} while (cmpxchg(&ei->i_flags, old_fl, new_fl) != old_fl);
}

static blkcnt_t mockfs_inode_blocks(struct mockfs_inode *raw_inode,
				  struct mockfs_inode_info *ei)
{
	blkcnt_t i_blocks ;
	struct inode *inode = &(ei->vfs_inode);
	struct super_block *sb = inode->i_sb;

	if (mockfs_has_feature_huge_file(sb)) {
		/* we are using combined 48 bit field */
		i_blocks = ((u64)le16_to_cpu(raw_inode->i_blocks_high)) << 32 |
					le32_to_cpu(raw_inode->i_blocks_lo);
		if (mockfs_test_inode_flag(inode, MOCKFS_INODE_HUGE_FILE)) {
			/* i_blocks represent file system block size */
			return i_blocks  << (inode->i_blkbits - 9);
		} else {
			return i_blocks;
		}
	} else {
		return le32_to_cpu(raw_inode->i_blocks_lo);
	}
}

static inline void mockfs_iget_extra_inode(struct inode *inode,
					 struct mockfs_inode *raw_inode,
					 struct mockfs_inode_info *ei)
{
	__le32 *magic = (void *)raw_inode +
			MOCKFS_GOOD_OLD_INODE_SIZE + ei->i_extra_isize;
	if (*magic == cpu_to_le32(MOCKFS_XATTR_MAGIC)) {
		mockfs_set_inode_state(inode, MOCKFS_STATE_XATTR);
		mockfs_find_inline_data_nolock(inode);
	} else
		MOCKFS_I(inode)->i_inline_off = 0;
}

int mockfs_get_projid(struct inode *inode, kprojid_t *projid)
{
	if (!MOCKFS_HAS_RO_COMPAT_FEATURE(inode->i_sb, MOCKFS_FEATURE_RO_COMPAT_PROJECT))
		return -EOPNOTSUPP;
	*projid = MOCKFS_I(inode)->i_projid;
	return 0;
}

struct inode *mockfs_iget(struct super_block *sb, unsigned long ino)
{
	struct mockfs_iloc iloc;
	struct mockfs_inode *raw_inode;
	struct mockfs_inode_info *ei;
	struct inode *inode;
	journal_t *journal = MOCKFS_SB(sb)->s_journal;
	long ret;
	int block;
	uid_t i_uid;
	gid_t i_gid;
	projid_t i_projid;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ei = MOCKFS_I(inode);
	iloc.bh = NULL;

	ret = __mockfs_get_inode_loc(inode, &iloc, 0);
	if (ret < 0)
		goto bad_inode;
	raw_inode = mockfs_raw_inode(&iloc);

	if (MOCKFS_INODE_SIZE(inode->i_sb) > MOCKFS_GOOD_OLD_INODE_SIZE) {
		ei->i_extra_isize = le16_to_cpu(raw_inode->i_extra_isize);
		if (MOCKFS_GOOD_OLD_INODE_SIZE + ei->i_extra_isize >
		    MOCKFS_INODE_SIZE(inode->i_sb)) {
			MOCKFS_ERROR_INODE(inode, "bad extra_isize (%u != %u)",
				MOCKFS_GOOD_OLD_INODE_SIZE + ei->i_extra_isize,
				MOCKFS_INODE_SIZE(inode->i_sb));
			ret = -EFSCORRUPTED;
			goto bad_inode;
		}
	} else
		ei->i_extra_isize = 0;

	/* Precompute checksum seed for inode metadata */
	if (mockfs_has_metadata_csum(sb)) {
		struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);
		__u32 csum;
		__le32 inum = cpu_to_le32(inode->i_ino);
		__le32 gen = raw_inode->i_generation;
		csum = mockfs_chksum(sbi, sbi->s_csum_seed, (__u8 *)&inum,
				   sizeof(inum));
		ei->i_csum_seed = mockfs_chksum(sbi, csum, (__u8 *)&gen,
					      sizeof(gen));
	}

	if (!mockfs_inode_csum_verify(inode, raw_inode, ei)) {
		MOCKFS_ERROR_INODE(inode, "checksum invalid");
		ret = -EFSBADCRC;
		goto bad_inode;
	}

	inode->i_mode = le16_to_cpu(raw_inode->i_mode);
	i_uid = (uid_t)le16_to_cpu(raw_inode->i_uid_low);
	i_gid = (gid_t)le16_to_cpu(raw_inode->i_gid_low);
	if (MOCKFS_HAS_RO_COMPAT_FEATURE(sb, MOCKFS_FEATURE_RO_COMPAT_PROJECT) &&
	    MOCKFS_INODE_SIZE(sb) > MOCKFS_GOOD_OLD_INODE_SIZE &&
	    MOCKFS_FITS_IN_INODE(raw_inode, ei, i_projid))
		i_projid = (projid_t)le32_to_cpu(raw_inode->i_projid);
	else
		i_projid = MOCKFS_DEF_PROJID;

	if (!(test_opt(inode->i_sb, NO_UID32))) {
		i_uid |= le16_to_cpu(raw_inode->i_uid_high) << 16;
		i_gid |= le16_to_cpu(raw_inode->i_gid_high) << 16;
	}
	i_uid_write(inode, i_uid);
	i_gid_write(inode, i_gid);
	ei->i_projid = make_kprojid(&init_user_ns, i_projid);
	set_nlink(inode, le16_to_cpu(raw_inode->i_links_count));

	mockfs_clear_state_flags(ei);	/* Only relevant on 32-bit archs */
	ei->i_inline_off = 0;
	ei->i_dir_start_lookup = 0;
	ei->i_dtime = le32_to_cpu(raw_inode->i_dtime);
	/* We now have enough fields to check if the inode was active or not.
	 * This is needed because nfsd might try to access dead inodes
	 * the test is that same one that e2fsck uses
	 * NeilBrown 1999oct15
	 */
	if (inode->i_nlink == 0) {
		if ((inode->i_mode == 0 ||
		     !(MOCKFS_SB(inode->i_sb)->s_mount_state & MOCKFS_ORPHAN_FS)) &&
		    ino != MOCKFS_BOOT_LOADER_INO) {
			/* this inode is deleted */
			ret = -ESTALE;
			goto bad_inode;
		}
		/* The only unlinked inodes we let through here have
		 * valid i_mode and are being read by the orphan
		 * recovery code: that's fine, we're about to complete
		 * the process of deleting those.
		 * OR it is the MOCKFS_BOOT_LOADER_INO which is
		 * not initialized on a new filesystem. */
	}
	ei->i_flags = le32_to_cpu(raw_inode->i_flags);
	inode->i_blocks = mockfs_inode_blocks(raw_inode, ei);
	ei->i_file_acl = le32_to_cpu(raw_inode->i_file_acl_lo);
	if (mockfs_has_feature_64bit(sb))
		ei->i_file_acl |=
			((__u64)le16_to_cpu(raw_inode->i_file_acl_high)) << 32;
	inode->i_size = mockfs_isize(raw_inode);
	ei->i_disksize = inode->i_size;
#ifdef CONFIG_QUOTA
	ei->i_reserved_quota = 0;
#endif
	inode->i_generation = le32_to_cpu(raw_inode->i_generation);
	ei->i_block_group = iloc.block_group;
	ei->i_last_alloc_group = ~0;
	/*
	 * NOTE! The in-memory inode i_data array is in little-endian order
	 * even on big-endian machines: we do NOT byteswap the block numbers!
	 */
	for (block = 0; block < MOCKFS_N_BLOCKS; block++)
		ei->i_data[block] = raw_inode->i_block[block];
	INIT_LIST_HEAD(&ei->i_orphan);

	/*
	 * Set transaction id's of transactions that have to be committed
	 * to finish f[data]sync. We set them to currently running transaction
	 * as we cannot be sure that the inode or some of its metadata isn't
	 * part of the transaction - the inode could have been reclaimed and
	 * now it is reread from disk.
	 */
	if (journal) {
		transaction_t *transaction;
		tid_t tid;

		read_lock(&journal->j_state_lock);
		if (journal->j_running_transaction)
			transaction = journal->j_running_transaction;
		else
			transaction = journal->j_committing_transaction;
		if (transaction)
			tid = transaction->t_tid;
		else
			tid = journal->j_commit_sequence;
		read_unlock(&journal->j_state_lock);
		ei->i_sync_tid = tid;
		ei->i_datasync_tid = tid;
	}

	if (MOCKFS_INODE_SIZE(inode->i_sb) > MOCKFS_GOOD_OLD_INODE_SIZE) {
		if (ei->i_extra_isize == 0) {
			/* The extra space is currently unused. Use it. */
			ei->i_extra_isize = sizeof(struct mockfs_inode) -
					    MOCKFS_GOOD_OLD_INODE_SIZE;
		} else {
			mockfs_iget_extra_inode(inode, raw_inode, ei);
		}
	}

	MOCKFS_INODE_GET_XTIME(i_ctime, inode, raw_inode);
	MOCKFS_INODE_GET_XTIME(i_mtime, inode, raw_inode);
	MOCKFS_INODE_GET_XTIME(i_atime, inode, raw_inode);
	MOCKFS_EINODE_GET_XTIME(i_crtime, ei, raw_inode);

	if (likely(!test_opt2(inode->i_sb, HURD_COMPAT))) {
		inode->i_version = le32_to_cpu(raw_inode->i_disk_version);
		if (MOCKFS_INODE_SIZE(inode->i_sb) > MOCKFS_GOOD_OLD_INODE_SIZE) {
			if (MOCKFS_FITS_IN_INODE(raw_inode, ei, i_version_hi))
				inode->i_version |=
		    (__u64)(le32_to_cpu(raw_inode->i_version_hi)) << 32;
		}
	}

	ret = 0;
	if (ei->i_file_acl &&
	    !mockfs_data_block_valid(MOCKFS_SB(sb), ei->i_file_acl, 1)) {
		MOCKFS_ERROR_INODE(inode, "bad extended attribute block %llu",
				 ei->i_file_acl);
		ret = -EFSCORRUPTED;
		goto bad_inode;
	} else if (!mockfs_has_inline_data(inode)) {
		if (mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS)) {
			if ((S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
			    (S_ISLNK(inode->i_mode) &&
			     !mockfs_inode_is_fast_symlink(inode))))
				/* Validate extent which is part of inode */
				ret = mockfs_ext_check_inode(inode);
		} else if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
			   (S_ISLNK(inode->i_mode) &&
			    !mockfs_inode_is_fast_symlink(inode))) {
			/* Validate block references which are part of inode */
			ret = mockfs_ind_check_inode(inode);
		}
	}
	if (ret)
		goto bad_inode;

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &mockfs_file_inode_operations;
		inode->i_fop = &mockfs_file_operations;
		mockfs_set_aops(inode);
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &mockfs_dir_inode_operations;
		inode->i_fop = &mockfs_dir_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		if (mockfs_encrypted_inode(inode)) {
			inode->i_op = &mockfs_encrypted_symlink_inode_operations;
			mockfs_set_aops(inode);
		} else if (mockfs_inode_is_fast_symlink(inode)) {
			inode->i_link = (char *)ei->i_data;
			inode->i_op = &mockfs_fast_symlink_inode_operations;
			nd_terminate_link(ei->i_data, inode->i_size,
				sizeof(ei->i_data) - 1);
		} else {
			inode->i_op = &mockfs_symlink_inode_operations;
			mockfs_set_aops(inode);
		}
		inode_nohighmem(inode);
	} else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
	      S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		inode->i_op = &mockfs_special_inode_operations;
		if (raw_inode->i_block[0])
			init_special_inode(inode, inode->i_mode,
			   old_decode_dev(le32_to_cpu(raw_inode->i_block[0])));
		else
			init_special_inode(inode, inode->i_mode,
			   new_decode_dev(le32_to_cpu(raw_inode->i_block[1])));
	} else if (ino == MOCKFS_BOOT_LOADER_INO) {
		make_bad_inode(inode);
	} else {
		ret = -EFSCORRUPTED;
		MOCKFS_ERROR_INODE(inode, "bogus i_mode (%o)", inode->i_mode);
		goto bad_inode;
	}
	brelse(iloc.bh);
	mockfs_set_inode_flags(inode);
	unlock_new_inode(inode);
	return inode;

bad_inode:
	brelse(iloc.bh);
	iget_failed(inode);
	return ERR_PTR(ret);
}

struct inode *mockfs_iget_normal(struct super_block *sb, unsigned long ino)
{
	if (ino < MOCKFS_FIRST_INO(sb) && ino != MOCKFS_ROOT_INO)
		return ERR_PTR(-EFSCORRUPTED);
	return mockfs_iget(sb, ino);
}

static int mockfs_inode_blocks_set(handle_t *handle,
				struct mockfs_inode *raw_inode,
				struct mockfs_inode_info *ei)
{
	struct inode *inode = &(ei->vfs_inode);
	u64 i_blocks = inode->i_blocks;
	struct super_block *sb = inode->i_sb;

	if (i_blocks <= ~0U) {
		/*
		 * i_blocks can be represented in a 32 bit variable
		 * as multiple of 512 bytes
		 */
		raw_inode->i_blocks_lo   = cpu_to_le32(i_blocks);
		raw_inode->i_blocks_high = 0;
		mockfs_clear_inode_flag(inode, MOCKFS_INODE_HUGE_FILE);
		return 0;
	}
	if (!mockfs_has_feature_huge_file(sb))
		return -EFBIG;

	if (i_blocks <= 0xffffffffffffULL) {
		/*
		 * i_blocks can be represented in a 48 bit variable
		 * as multiple of 512 bytes
		 */
		raw_inode->i_blocks_lo   = cpu_to_le32(i_blocks);
		raw_inode->i_blocks_high = cpu_to_le16(i_blocks >> 32);
		mockfs_clear_inode_flag(inode, MOCKFS_INODE_HUGE_FILE);
	} else {
		mockfs_set_inode_flag(inode, MOCKFS_INODE_HUGE_FILE);
		/* i_block is stored in file system block size */
		i_blocks = i_blocks >> (inode->i_blkbits - 9);
		raw_inode->i_blocks_lo   = cpu_to_le32(i_blocks);
		raw_inode->i_blocks_high = cpu_to_le16(i_blocks >> 32);
	}
	return 0;
}

struct other_inode {
	unsigned long		orig_ino;
	struct mockfs_inode	*raw_inode;
};

static int other_inode_match(struct inode * inode, unsigned long ino,
			     void *data)
{
	struct other_inode *oi = (struct other_inode *) data;

	if ((inode->i_ino != ino) ||
	    (inode->i_state & (I_FREEING | I_WILL_FREE | I_NEW |
			       I_DIRTY_SYNC | I_DIRTY_DATASYNC)) ||
	    ((inode->i_state & I_DIRTY_TIME) == 0))
		return 0;
	spin_lock(&inode->i_lock);
	if (((inode->i_state & (I_FREEING | I_WILL_FREE | I_NEW |
				I_DIRTY_SYNC | I_DIRTY_DATASYNC)) == 0) &&
	    (inode->i_state & I_DIRTY_TIME)) {
		struct mockfs_inode_info	*ei = MOCKFS_I(inode);

		inode->i_state &= ~(I_DIRTY_TIME | I_DIRTY_TIME_EXPIRED);
		spin_unlock(&inode->i_lock);

		spin_lock(&ei->i_raw_lock);
		MOCKFS_INODE_SET_XTIME(i_ctime, inode, oi->raw_inode);
		MOCKFS_INODE_SET_XTIME(i_mtime, inode, oi->raw_inode);
		MOCKFS_INODE_SET_XTIME(i_atime, inode, oi->raw_inode);
		mockfs_inode_csum_set(inode, oi->raw_inode, ei);
		spin_unlock(&ei->i_raw_lock);
		return -1;
	}
	spin_unlock(&inode->i_lock);
	return -1;
}

/*
 * Opportunistically update the other time fields for other inodes in
 * the same inode table block.
 */
static void mockfs_update_other_inodes_time(struct super_block *sb,
					  unsigned long orig_ino, char *buf)
{
	struct other_inode oi;
	unsigned long ino;
	int i, inodes_per_block = MOCKFS_SB(sb)->s_inodes_per_block;
	int inode_size = MOCKFS_INODE_SIZE(sb);

	oi.orig_ino = orig_ino;
	/*
	 * Calculate the first inode in the inode table block.  Inode
	 * numbers are one-based.  That is, the first inode in a block
	 * (assuming 4k blocks and 256 byte inodes) is (n*16 + 1).
	 */
	ino = ((orig_ino - 1) & ~(inodes_per_block - 1)) + 1;
	for (i = 0; i < inodes_per_block; i++, ino++, buf += inode_size) {
		if (ino == orig_ino)
			continue;
		oi.raw_inode = (struct mockfs_inode *) buf;
		(void) find_inode_nowait(sb, ino, other_inode_match, &oi);
	}
}

/*
 * Post the struct inode info into an on-disk inode location in the
 * buffer-cache.  This gobbles the caller's reference to the
 * buffer_head in the inode location struct.
 *
 * The caller must have write access to iloc->bh.
 */
static int mockfs_do_update_inode(handle_t *handle,
				struct inode *inode,
				struct mockfs_iloc *iloc)
{
	struct mockfs_inode *raw_inode = mockfs_raw_inode(iloc);
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	struct buffer_head *bh = iloc->bh;
	struct super_block *sb = inode->i_sb;
	int err = 0, rc, block;
	int need_datasync = 0, set_large_file = 0;
	uid_t i_uid;
	gid_t i_gid;
	projid_t i_projid;

	spin_lock(&ei->i_raw_lock);

	/* For fields not tracked in the in-memory inode,
	 * initialise them to zero for new inodes. */
	if (mockfs_test_inode_state(inode, MOCKFS_STATE_NEW))
		memset(raw_inode, 0, MOCKFS_SB(inode->i_sb)->s_inode_size);

	mockfs_get_inode_flags(ei);
	raw_inode->i_mode = cpu_to_le16(inode->i_mode);
	i_uid = i_uid_read(inode);
	i_gid = i_gid_read(inode);
	i_projid = from_kprojid(&init_user_ns, ei->i_projid);
	if (!(test_opt(inode->i_sb, NO_UID32))) {
		raw_inode->i_uid_low = cpu_to_le16(low_16_bits(i_uid));
		raw_inode->i_gid_low = cpu_to_le16(low_16_bits(i_gid));
/*
 * Fix up interoperability with old kernels. Otherwise, old inodes get
 * re-used with the upper 16 bits of the uid/gid intact
 */
		if (!ei->i_dtime) {
			raw_inode->i_uid_high =
				cpu_to_le16(high_16_bits(i_uid));
			raw_inode->i_gid_high =
				cpu_to_le16(high_16_bits(i_gid));
		} else {
			raw_inode->i_uid_high = 0;
			raw_inode->i_gid_high = 0;
		}
	} else {
		raw_inode->i_uid_low = cpu_to_le16(fs_high2lowuid(i_uid));
		raw_inode->i_gid_low = cpu_to_le16(fs_high2lowgid(i_gid));
		raw_inode->i_uid_high = 0;
		raw_inode->i_gid_high = 0;
	}
	raw_inode->i_links_count = cpu_to_le16(inode->i_nlink);

	MOCKFS_INODE_SET_XTIME(i_ctime, inode, raw_inode);
	MOCKFS_INODE_SET_XTIME(i_mtime, inode, raw_inode);
	MOCKFS_INODE_SET_XTIME(i_atime, inode, raw_inode);
	MOCKFS_EINODE_SET_XTIME(i_crtime, ei, raw_inode);

	err = mockfs_inode_blocks_set(handle, raw_inode, ei);
	if (err) {
		spin_unlock(&ei->i_raw_lock);
		goto out_brelse;
	}
	raw_inode->i_dtime = cpu_to_le32(ei->i_dtime);
	raw_inode->i_flags = cpu_to_le32(ei->i_flags & 0xFFFFFFFF);
	if (likely(!test_opt2(inode->i_sb, HURD_COMPAT)))
		raw_inode->i_file_acl_high =
			cpu_to_le16(ei->i_file_acl >> 32);
	raw_inode->i_file_acl_lo = cpu_to_le32(ei->i_file_acl);
	if (ei->i_disksize != mockfs_isize(raw_inode)) {
		mockfs_isize_set(raw_inode, ei->i_disksize);
		need_datasync = 1;
	}
	if (ei->i_disksize > 0x7fffffffULL) {
		if (!mockfs_has_feature_large_file(sb) ||
				MOCKFS_SB(sb)->s_es->s_rev_level ==
		    cpu_to_le32(MOCKFS_GOOD_OLD_REV))
			set_large_file = 1;
	}
	raw_inode->i_generation = cpu_to_le32(inode->i_generation);
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		if (old_valid_dev(inode->i_rdev)) {
			raw_inode->i_block[0] =
				cpu_to_le32(old_encode_dev(inode->i_rdev));
			raw_inode->i_block[1] = 0;
		} else {
			raw_inode->i_block[0] = 0;
			raw_inode->i_block[1] =
				cpu_to_le32(new_encode_dev(inode->i_rdev));
			raw_inode->i_block[2] = 0;
		}
	} else if (!mockfs_has_inline_data(inode)) {
		for (block = 0; block < MOCKFS_N_BLOCKS; block++)
			raw_inode->i_block[block] = ei->i_data[block];
	}

	if (likely(!test_opt2(inode->i_sb, HURD_COMPAT))) {
		raw_inode->i_disk_version = cpu_to_le32(inode->i_version);
		if (ei->i_extra_isize) {
			if (MOCKFS_FITS_IN_INODE(raw_inode, ei, i_version_hi))
				raw_inode->i_version_hi =
					cpu_to_le32(inode->i_version >> 32);
			raw_inode->i_extra_isize =
				cpu_to_le16(ei->i_extra_isize);
		}
	}

	BUG_ON(!MOCKFS_HAS_RO_COMPAT_FEATURE(inode->i_sb,
			MOCKFS_FEATURE_RO_COMPAT_PROJECT) &&
	       i_projid != MOCKFS_DEF_PROJID);

	if (MOCKFS_INODE_SIZE(inode->i_sb) > MOCKFS_GOOD_OLD_INODE_SIZE &&
	    MOCKFS_FITS_IN_INODE(raw_inode, ei, i_projid))
		raw_inode->i_projid = cpu_to_le32(i_projid);

	mockfs_inode_csum_set(inode, raw_inode, ei);
	spin_unlock(&ei->i_raw_lock);
	if (inode->i_sb->s_flags & MS_LAZYTIME)
		mockfs_update_other_inodes_time(inode->i_sb, inode->i_ino,
					      bh->b_data);

	BUFFER_TRACE(bh, "call mockfs_handle_dirty_metadata");
	rc = mockfs_handle_dirty_metadata(handle, NULL, bh);
	if (!err)
		err = rc;
	mockfs_clear_inode_state(inode, MOCKFS_STATE_NEW);
	if (set_large_file) {
		BUFFER_TRACE(MOCKFS_SB(sb)->s_sbh, "get write access");
		err = mockfs_journal_get_write_access(handle, MOCKFS_SB(sb)->s_sbh);
		if (err)
			goto out_brelse;
		mockfs_update_dynamic_rev(sb);
		mockfs_set_feature_large_file(sb);
		mockfs_handle_sync(handle);
		err = mockfs_handle_dirty_super(handle, sb);
	}
	mockfs_update_inode_fsync_trans(handle, inode, need_datasync);
out_brelse:
	brelse(bh);
	mockfs_std_error(inode->i_sb, err);
	return err;
}

/*
 * mockfs_write_inode()
 *
 * We are called from a few places:
 *
 * - Within generic_file_aio_write() -> generic_write_sync() for O_SYNC files.
 *   Here, there will be no transaction running. We wait for any running
 *   transaction to commit.
 *
 * - Within flush work (sys_sync(), kupdate and such).
 *   We wait on commit, if told to.
 *
 * - Within iput_final() -> write_inode_now()
 *   We wait on commit, if told to.
 *
 * In all cases it is actually safe for us to return without doing anything,
 * because the inode has been copied into a raw inode buffer in
 * mockfs_mark_inode_dirty().  This is a correctness thing for WB_SYNC_ALL
 * writeback.
 *
 * Note that we are absolutely dependent upon all inode dirtiers doing the
 * right thing: they *must* call mark_inode_dirty() after dirtying info in
 * which we are interested.
 *
 * It would be a bug for them to not do this.  The code:
 *
 *	mark_inode_dirty(inode)
 *	stuff();
 *	inode->i_size = expr;
 *
 * is in error because write_inode() could occur while `stuff()' is running,
 * and the new i_size will be lost.  Plus the inode will no longer be on the
 * superblock's dirty inode list.
 */
int mockfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int err;

	if (WARN_ON_ONCE(current->flags & PF_MEMALLOC))
		return 0;

	if (MOCKFS_SB(inode->i_sb)->s_journal) {
		if (mockfs_journal_current_handle()) {
			jbd_debug(1, "called recursively, non-PF_MEMALLOC!\n");
			dump_stack();
			return -EIO;
		}

		/*
		 * No need to force transaction in WB_SYNC_NONE mode. Also
		 * mockfs_sync_fs() will force the commit after everything is
		 * written.
		 */
		if (wbc->sync_mode != WB_SYNC_ALL || wbc->for_sync)
			return 0;

		err = mockfs_force_commit(inode->i_sb);
	} else {
		struct mockfs_iloc iloc;

		err = __mockfs_get_inode_loc(inode, &iloc, 0);
		if (err)
			return err;
		/*
		 * sync(2) will flush the whole buffer cache. No need to do
		 * it here separately for each inode.
		 */
		if (wbc->sync_mode == WB_SYNC_ALL && !wbc->for_sync)
			sync_dirty_buffer(iloc.bh);
		if (buffer_req(iloc.bh) && !buffer_uptodate(iloc.bh)) {
			MOCKFS_ERROR_INODE_BLOCK(inode, iloc.bh->b_blocknr,
					 "IO error syncing inode");
			err = -EIO;
		}
		brelse(iloc.bh);
	}
	return err;
}

/*
 * In data=journal mode mockfs_journalled_invalidatepage() may fail to invalidate
 * buffers that are attached to a page stradding i_size and are undergoing
 * commit. In that case we have to wait for commit to finish and try again.
 */
static void mockfs_wait_for_tail_page_commit(struct inode *inode)
{
	struct page *page;
	unsigned offset;
	journal_t *journal = MOCKFS_SB(inode->i_sb)->s_journal;
	tid_t commit_tid = 0;
	int ret;

	offset = inode->i_size & (PAGE_SIZE - 1);
	/*
	 * All buffers in the last page remain valid? Then there's nothing to
	 * do. We do the check mainly to optimize the common PAGE_SIZE ==
	 * blocksize case
	 */
	if (offset > PAGE_SIZE - (1 << inode->i_blkbits))
		return;
	while (1) {
		page = find_lock_page(inode->i_mapping,
				      inode->i_size >> PAGE_SHIFT);
		if (!page)
			return;
		ret = __mockfs_journalled_invalidatepage(page, offset,
						PAGE_SIZE - offset);
		unlock_page(page);
		put_page(page);
		if (ret != -EBUSY)
			return;
		commit_tid = 0;
		read_lock(&journal->j_state_lock);
		if (journal->j_committing_transaction)
			commit_tid = journal->j_committing_transaction->t_tid;
		read_unlock(&journal->j_state_lock);
		if (commit_tid)
			jbd2_log_wait_commit(journal, commit_tid);
	}
}

/*
 * mockfs_setattr()
 *
 * Called from notify_change.
 *
 * We want to trap VFS attempts to truncate the file as soon as
 * possible.  In particular, we want to make sure that when the VFS
 * shrinks i_size, we put the inode on the orphan list and modify
 * i_disksize immediately, so that during the subsequent flushing of
 * dirty pages and freeing of disk blocks, we can guarantee that any
 * commit will leave the blocks being flushed in an unused state on
 * disk.  (On recovery, the inode will get truncated and the blocks will
 * be freed, so we have a strong guarantee that no future commit will
 * leave these blocks visible to the user.)
 *
 * Another thing we have to assure is that if we are in ordered mode
 * and inode is still attached to the committing transaction, we must
 * we start writeout of all the dirty pages which are being truncated.
 * This way we are sure that all the data written in the previous
 * transaction are already on disk (truncate waits for pages under
 * writeback).
 *
 * Called with inode->i_mutex down.
 */
int mockfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error, rc = 0;
	int orphan = 0;
	const unsigned int ia_valid = attr->ia_valid;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	if (is_quota_modification(inode, attr)) {
		error = dquot_initialize(inode);
		if (error)
			return error;
	}
	if ((ia_valid & ATTR_UID && !uid_eq(attr->ia_uid, inode->i_uid)) ||
	    (ia_valid & ATTR_GID && !gid_eq(attr->ia_gid, inode->i_gid))) {
		handle_t *handle;

		/* (user+group)*(old+new) structure, inode write (sb,
		 * inode block, ? - but truncate inode update has it) */
		handle = mockfs_journal_start(inode, MOCKFS_HT_QUOTA,
			(MOCKFS_MAXQUOTAS_INIT_BLOCKS(inode->i_sb) +
			 MOCKFS_MAXQUOTAS_DEL_BLOCKS(inode->i_sb)) + 3);
		if (IS_ERR(handle)) {
			error = PTR_ERR(handle);
			goto err_out;
		}
		error = dquot_transfer(inode, attr);
		if (error) {
			mockfs_journal_stop(handle);
			return error;
		}
		/* Update corresponding info in inode so that everything is in
		 * one transaction */
		if (attr->ia_valid & ATTR_UID)
			inode->i_uid = attr->ia_uid;
		if (attr->ia_valid & ATTR_GID)
			inode->i_gid = attr->ia_gid;
		error = mockfs_mark_inode_dirty(handle, inode);
		mockfs_journal_stop(handle);
	}

	if (attr->ia_valid & ATTR_SIZE) {
		handle_t *handle;
		loff_t oldsize = inode->i_size;
		int shrink = (attr->ia_size <= inode->i_size);

		if (!(mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS))) {
			struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);

			if (attr->ia_size > sbi->s_bitmap_maxbytes)
				return -EFBIG;
		}
		if (!S_ISREG(inode->i_mode))
			return -EINVAL;

		if (IS_I_VERSION(inode) && attr->ia_size != inode->i_size)
			inode_inc_iversion(inode);

		if (mockfs_should_order_data(inode) &&
		    (attr->ia_size < inode->i_size)) {
			error = mockfs_begin_ordered_truncate(inode,
							    attr->ia_size);
			if (error)
				goto err_out;
		}
		if (attr->ia_size != inode->i_size) {
			handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, 3);
			if (IS_ERR(handle)) {
				error = PTR_ERR(handle);
				goto err_out;
			}
			if (mockfs_handle_valid(handle) && shrink) {
				error = mockfs_orphan_add(handle, inode);
				orphan = 1;
			}
			/*
			 * Update c/mtime on truncate up, mockfs_truncate() will
			 * update c/mtime in shrink case below
			 */
			if (!shrink) {
				inode->i_mtime = mockfs_current_time(inode);
				inode->i_ctime = inode->i_mtime;
			}
			down_write(&MOCKFS_I(inode)->i_data_sem);
			MOCKFS_I(inode)->i_disksize = attr->ia_size;
			rc = mockfs_mark_inode_dirty(handle, inode);
			if (!error)
				error = rc;
			/*
			 * We have to update i_size under i_data_sem together
			 * with i_disksize to avoid races with writeback code
			 * running mockfs_wb_update_i_disksize().
			 */
			if (!error)
				i_size_write(inode, attr->ia_size);
			up_write(&MOCKFS_I(inode)->i_data_sem);
			mockfs_journal_stop(handle);
			if (error) {
				if (orphan)
					mockfs_orphan_del(NULL, inode);
				goto err_out;
			}
		}
		if (!shrink)
			pagecache_isize_extended(inode, oldsize, inode->i_size);

		/*
		 * Blocks are going to be removed from the inode. Wait
		 * for dio in flight.  Temporarily disable
		 * dioread_nolock to prevent livelock.
		 */
		if (orphan) {
			if (!mockfs_should_journal_data(inode)) {
				mockfs_inode_block_unlocked_dio(inode);
				inode_dio_wait(inode);
				mockfs_inode_resume_unlocked_dio(inode);
			} else
				mockfs_wait_for_tail_page_commit(inode);
		}
		down_write(&MOCKFS_I(inode)->i_mmap_sem);
		/*
		 * Truncate pagecache after we've waited for commit
		 * in data=journal mode to make pages freeable.
		 */
		truncate_pagecache(inode, inode->i_size);
		if (shrink)
			mockfs_truncate(inode);
		up_write(&MOCKFS_I(inode)->i_mmap_sem);
	}

	if (!rc) {
		setattr_copy(inode, attr);
		mark_inode_dirty(inode);
	}

	/*
	 * If the call to mockfs_truncate failed to get a transaction handle at
	 * all, we need to clean up the in-core orphan list manually.
	 */
	if (orphan && inode->i_nlink)
		mockfs_orphan_del(NULL, inode);

	if (!rc && (ia_valid & ATTR_MODE))
		rc = posix_acl_chmod(inode, inode->i_mode);

err_out:
	mockfs_std_error(inode->i_sb, error);
	if (!error)
		error = rc;
	return error;
}

int mockfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		 struct kstat *stat)
{
	struct inode *inode;
	unsigned long long delalloc_blocks;

	inode = d_inode(dentry);
	generic_fillattr(inode, stat);

	/*
	 * If there is inline data in the inode, the inode will normally not
	 * have data blocks allocated (it may have an external xattr block).
	 * Report at least one sector for such files, so tools like tar, rsync,
	 * others doen't incorrectly think the file is completely sparse.
	 */
	if (unlikely(mockfs_has_inline_data(inode)))
		stat->blocks += (stat->size + 511) >> 9;

	/*
	 * We can't update i_blocks if the block allocation is delayed
	 * otherwise in the case of system crash before the real block
	 * allocation is done, we will have i_blocks inconsistent with
	 * on-disk file blocks.
	 * We always keep i_blocks updated together with real
	 * allocation. But to not confuse with user, stat
	 * will return the blocks that include the delayed allocation
	 * blocks for this file.
	 */
	delalloc_blocks = MOCKFS_C2B(MOCKFS_SB(inode->i_sb),
				   MOCKFS_I(inode)->i_reserved_data_blocks);
	stat->blocks += delalloc_blocks << (inode->i_sb->s_blocksize_bits - 9);
	return 0;
}

static int mockfs_index_trans_blocks(struct inode *inode, int lblocks,
				   int pextents)
{
	if (!(mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS)))
		return mockfs_ind_trans_blocks(inode, lblocks);
	return mockfs_ext_index_trans_blocks(inode, pextents);
}

/*
 * Account for index blocks, block groups bitmaps and block group
 * descriptor blocks if modify datablocks and index blocks
 * worse case, the indexs blocks spread over different block groups
 *
 * If datablocks are discontiguous, they are possible to spread over
 * different block groups too. If they are contiguous, with flexbg,
 * they could still across block group boundary.
 *
 * Also account for superblock, inode, quota and xattr blocks
 */
static int mockfs_meta_trans_blocks(struct inode *inode, int lblocks,
				  int pextents)
{
	mockfs_group_t groups, ngroups = mockfs_get_groups_count(inode->i_sb);
	int gdpblocks;
	int idxblocks;
	int ret = 0;

	/*
	 * How many index blocks need to touch to map @lblocks logical blocks
	 * to @pextents physical extents?
	 */
	idxblocks = mockfs_index_trans_blocks(inode, lblocks, pextents);

	ret = idxblocks;

	/*
	 * Now let's see how many group bitmaps and group descriptors need
	 * to account
	 */
	groups = idxblocks + pextents;
	gdpblocks = groups;
	if (groups > ngroups)
		groups = ngroups;
	if (groups > MOCKFS_SB(inode->i_sb)->s_gdb_count)
		gdpblocks = MOCKFS_SB(inode->i_sb)->s_gdb_count;

	/* bitmaps and block group descriptor blocks */
	ret += groups + gdpblocks;

	/* Blocks for super block, inode, quota and xattr blocks */
	ret += MOCKFS_META_TRANS_BLOCKS(inode->i_sb);

	return ret;
}

/*
 * Calculate the total number of credits to reserve to fit
 * the modification of a single pages into a single transaction,
 * which may include multiple chunks of block allocations.
 *
 * This could be called via mockfs_write_begin()
 *
 * We need to consider the worse case, when
 * one new block per extent.
 */
int mockfs_writepage_trans_blocks(struct inode *inode)
{
	int bpp = mockfs_journal_blocks_per_page(inode);
	int ret;

	ret = mockfs_meta_trans_blocks(inode, bpp, bpp);

	/* Account for data blocks for journalled mode */
	if (mockfs_should_journal_data(inode))
		ret += bpp;
	return ret;
}

/*
 * Calculate the journal credits for a chunk of data modification.
 *
 * This is called from DIO, fallocate or whoever calling
 * mockfs_map_blocks() to map/allocate a chunk of contiguous disk blocks.
 *
 * journal buffers for data blocks are not included here, as DIO
 * and fallocate do no need to journal data buffers.
 */
int mockfs_chunk_trans_blocks(struct inode *inode, int nrblocks)
{
	return mockfs_meta_trans_blocks(inode, nrblocks, 1);
}

/*
 * The caller must have previously called mockfs_reserve_inode_write().
 * Give this, we know that the caller already has write access to iloc->bh.
 */
int mockfs_mark_iloc_dirty(handle_t *handle,
			 struct inode *inode, struct mockfs_iloc *iloc)
{
	int err = 0;

	if (IS_I_VERSION(inode))
		inode_inc_iversion(inode);

	/* the do_update_inode consumes one bh->b_count */
	get_bh(iloc->bh);

	/* mockfs_do_update_inode() does jbd2_journal_dirty_metadata */
	err = mockfs_do_update_inode(handle, inode, iloc);
	put_bh(iloc->bh);
	return err;
}

/*
 * On success, We end up with an outstanding reference count against
 * iloc->bh.  This _must_ be cleaned up later.
 */

int
mockfs_reserve_inode_write(handle_t *handle, struct inode *inode,
			 struct mockfs_iloc *iloc)
{
	int err;

	err = mockfs_get_inode_loc(inode, iloc);
	if (!err) {
		BUFFER_TRACE(iloc->bh, "get_write_access");
		err = mockfs_journal_get_write_access(handle, iloc->bh);
		if (err) {
			brelse(iloc->bh);
			iloc->bh = NULL;
		}
	}
	mockfs_std_error(inode->i_sb, err);
	return err;
}

/*
 * Expand an inode by new_extra_isize bytes.
 * Returns 0 on success or negative error number on failure.
 */
static int mockfs_expand_extra_isize(struct inode *inode,
				   unsigned int new_extra_isize,
				   struct mockfs_iloc iloc,
				   handle_t *handle)
{
	struct mockfs_inode *raw_inode;
	struct mockfs_xattr_ibody_header *header;

	if (MOCKFS_I(inode)->i_extra_isize >= new_extra_isize)
		return 0;

	raw_inode = mockfs_raw_inode(&iloc);

	header = IHDR(inode, raw_inode);

	/* No extended attributes present */
	if (!mockfs_test_inode_state(inode, MOCKFS_STATE_XATTR) ||
	    header->h_magic != cpu_to_le32(MOCKFS_XATTR_MAGIC)) {
		memset((void *)raw_inode + MOCKFS_GOOD_OLD_INODE_SIZE, 0,
			new_extra_isize);
		MOCKFS_I(inode)->i_extra_isize = new_extra_isize;
		return 0;
	}

	/* try to expand with EAs present */
	return mockfs_expand_extra_isize_ea(inode, new_extra_isize,
					  raw_inode, handle);
}

/*
 * What we do here is to mark the in-core inode as clean with respect to inode
 * dirtiness (it may still be data-dirty).
 * This means that the in-core inode may be reaped by prune_icache
 * without having to perform any I/O.  This is a very good thing,
 * because *any* task may call prune_icache - even ones which
 * have a transaction open against a different journal.
 *
 * Is this cheating?  Not really.  Sure, we haven't written the
 * inode out, but prune_icache isn't a user-visible syncing function.
 * Whenever the user wants stuff synced (sys_sync, sys_msync, sys_fsync)
 * we start and wait on commits.
 */
int mockfs_mark_inode_dirty(handle_t *handle, struct inode *inode)
{
	struct mockfs_iloc iloc;
	struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);
	static unsigned int mnt_count;
	int err, ret;

	might_sleep();
	err = mockfs_reserve_inode_write(handle, inode, &iloc);
	if (err)
		return err;
	if (mockfs_handle_valid(handle) &&
	    MOCKFS_I(inode)->i_extra_isize < sbi->s_want_extra_isize &&
	    !mockfs_test_inode_state(inode, MOCKFS_STATE_NO_EXPAND)) {
		/*
		 * We need extra buffer credits since we may write into EA block
		 * with this same handle. If journal_extend fails, then it will
		 * only result in a minor loss of functionality for that inode.
		 * If this is felt to be critical, then e2fsck should be run to
		 * force a large enough s_min_extra_isize.
		 */
		if ((jbd2_journal_extend(handle,
			     MOCKFS_DATA_TRANS_BLOCKS(inode->i_sb))) == 0) {
			ret = mockfs_expand_extra_isize(inode,
						      sbi->s_want_extra_isize,
						      iloc, handle);
			if (ret) {
				mockfs_set_inode_state(inode,
						     MOCKFS_STATE_NO_EXPAND);
				if (mnt_count !=
					le16_to_cpu(sbi->s_es->s_mnt_count)) {
					mockfs_warning(inode->i_sb,
					"Unable to expand inode %lu. Delete"
					" some EAs or run e2fsck.",
					inode->i_ino);
					mnt_count =
					  le16_to_cpu(sbi->s_es->s_mnt_count);
				}
			}
		}
	}
	return mockfs_mark_iloc_dirty(handle, inode, &iloc);
}

/*
 * mockfs_dirty_inode() is called from __mark_inode_dirty()
 *
 * We're really interested in the case where a file is being extended.
 * i_size has been changed by generic_commit_write() and we thus need
 * to include the updated inode in the current transaction.
 *
 * Also, dquot_alloc_block() will always dirty the inode when blocks
 * are allocated to the file.
 *
 * If the inode is marked synchronous, we don't honour that here - doing
 * so would cause a commit on atime updates, which we don't bother doing.
 * We handle synchronous inodes at the highest possible level.
 *
 * If only the I_DIRTY_TIME flag is set, we can skip everything.  If
 * I_DIRTY_TIME and I_DIRTY_SYNC is set, the only inode fields we need
 * to copy into the on-disk inode structure are the timestamp files.
 */
void mockfs_dirty_inode(struct inode *inode, int flags)
{
	handle_t *handle;

	if (flags == I_DIRTY_TIME)
		return;
	handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, 2);
	if (IS_ERR(handle))
		goto out;

	mockfs_mark_inode_dirty(handle, inode);

	mockfs_journal_stop(handle);
out:
	return;
}

#if 0
/*
 * Bind an inode's backing buffer_head into this transaction, to prevent
 * it from being flushed to disk early.  Unlike
 * mockfs_reserve_inode_write, this leaves behind no bh reference and
 * returns no iloc structure, so the caller needs to repeat the iloc
 * lookup to mark the inode dirty later.
 */
static int mockfs_pin_inode(handle_t *handle, struct inode *inode)
{
	struct mockfs_iloc iloc;

	int err = 0;
	if (handle) {
		err = mockfs_get_inode_loc(inode, &iloc);
		if (!err) {
			BUFFER_TRACE(iloc.bh, "get_write_access");
			err = jbd2_journal_get_write_access(handle, iloc.bh);
			if (!err)
				err = mockfs_handle_dirty_metadata(handle,
								 NULL,
								 iloc.bh);
			brelse(iloc.bh);
		}
	}
	mockfs_std_error(inode->i_sb, err);
	return err;
}
#endif

int mockfs_change_inode_journal_flag(struct inode *inode, int val)
{
	journal_t *journal;
	handle_t *handle;
	int err;

	/*
	 * We have to be very careful here: changing a data block's
	 * journaling status dynamically is dangerous.  If we write a
	 * data block to the journal, change the status and then delete
	 * that block, we risk forgetting to revoke the old log record
	 * from the journal and so a subsequent replay can corrupt data.
	 * So, first we make sure that the journal is empty and that
	 * nobody is changing anything.
	 */

	journal = MOCKFS_JOURNAL(inode);
	if (!journal)
		return 0;
	if (is_journal_aborted(journal))
		return -EROFS;
	/* We have to allocate physical blocks for delalloc blocks
	 * before flushing journal. otherwise delalloc blocks can not
	 * be allocated any more. even more truncate on delalloc blocks
	 * could trigger BUG by flushing delalloc blocks in journal.
	 * There is no delalloc block in non-journal data mode.
	 */
	if (val && test_opt(inode->i_sb, DELALLOC)) {
		err = mockfs_alloc_da_blocks(inode);
		if (err < 0)
			return err;
	}

	/* Wait for all existing dio workers */
	mockfs_inode_block_unlocked_dio(inode);
	inode_dio_wait(inode);

	jbd2_journal_lock_updates(journal);

	/*
	 * OK, there are no updates running now, and all cached data is
	 * synced to disk.  We are now in a completely consistent state
	 * which doesn't have anything in the journal, and we know that
	 * no filesystem updates are running, so it is safe to modify
	 * the inode's in-core data-journaling state flag now.
	 */

	if (val)
		mockfs_set_inode_flag(inode, MOCKFS_INODE_JOURNAL_DATA);
	else {
		err = jbd2_journal_flush(journal);
		if (err < 0) {
			jbd2_journal_unlock_updates(journal);
			mockfs_inode_resume_unlocked_dio(inode);
			return err;
		}
		mockfs_clear_inode_flag(inode, MOCKFS_INODE_JOURNAL_DATA);
	}
	mockfs_set_aops(inode);

	jbd2_journal_unlock_updates(journal);
	mockfs_inode_resume_unlocked_dio(inode);

	/* Finally we can mark the inode as dirty. */

	handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, 1);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	err = mockfs_mark_inode_dirty(handle, inode);
	mockfs_handle_sync(handle);
	mockfs_journal_stop(handle);
	mockfs_std_error(inode->i_sb, err);

	return err;
}

static int mockfs_bh_unmapped(handle_t *handle, struct buffer_head *bh)
{
	return !buffer_mapped(bh);
}

int mockfs_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	loff_t size;
	unsigned long len;
	int ret;
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	handle_t *handle;
	get_block_t *get_block;
	int retries = 0;

	sb_start_pagefault(inode->i_sb);
	file_update_time(vma->vm_file);

	down_read(&MOCKFS_I(inode)->i_mmap_sem);
	/* Delalloc case is easy... */
	if (test_opt(inode->i_sb, DELALLOC) &&
	    !mockfs_should_journal_data(inode) &&
	    !mockfs_nonda_switch(inode->i_sb)) {
		do {
			ret = block_page_mkwrite(vma, vmf,
						   mockfs_da_get_block_prep);
		} while (ret == -ENOSPC &&
		       mockfs_should_retry_alloc(inode->i_sb, &retries));
		goto out_ret;
	}

	lock_page(page);
	size = i_size_read(inode);
	/* Page got truncated from under us? */
	if (page->mapping != mapping || page_offset(page) > size) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	if (page->index == size >> PAGE_SHIFT)
		len = size & ~PAGE_MASK;
	else
		len = PAGE_SIZE;
	/*
	 * Return if we have all the buffers mapped. This avoids the need to do
	 * journal_start/journal_stop which can block and take a long time
	 */
	if (page_has_buffers(page)) {
		if (!mockfs_walk_page_buffers(NULL, page_buffers(page),
					    0, len, NULL,
					    mockfs_bh_unmapped)) {
			/* Wait so that we don't change page under IO */
			wait_for_stable_page(page);
			ret = VM_FAULT_LOCKED;
			goto out;
		}
	}
	unlock_page(page);
	/* OK, we need to fill the hole... */
	if (mockfs_should_dioread_nolock(inode))
		get_block = mockfs_get_block_unwritten;
	else
		get_block = mockfs_get_block;
retry_alloc:
	handle = mockfs_journal_start(inode, MOCKFS_HT_WRITE_PAGE,
				    mockfs_writepage_trans_blocks(inode));
	if (IS_ERR(handle)) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	}
	ret = block_page_mkwrite(vma, vmf, get_block);
	if (!ret && mockfs_should_journal_data(inode)) {
		if (mockfs_walk_page_buffers(handle, page_buffers(page), 0,
			  PAGE_SIZE, NULL, do_journal_get_write_access)) {
			unlock_page(page);
			ret = VM_FAULT_SIGBUS;
			mockfs_journal_stop(handle);
			goto out;
		}
		mockfs_set_inode_state(inode, MOCKFS_STATE_JDATA);
	}
	mockfs_journal_stop(handle);
	if (ret == -ENOSPC && mockfs_should_retry_alloc(inode->i_sb, &retries))
		goto retry_alloc;
out_ret:
	ret = block_page_mkwrite_return(ret);
out:
	up_read(&MOCKFS_I(inode)->i_mmap_sem);
	sb_end_pagefault(inode->i_sb);
	return ret;
}

int mockfs_filemap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vma->vm_file);
	int err;

	down_read(&MOCKFS_I(inode)->i_mmap_sem);
	err = filemap_fault(vma, vmf);
	up_read(&MOCKFS_I(inode)->i_mmap_sem);

	return err;
}

/*
 * Find the first extent at or after @lblk in an inode that is not a hole.
 * Search for @map_len blocks at most. The extent is returned in @result.
 *
 * The function returns 1 if we found an extent. The function returns 0 in
 * case there is no extent at or after @lblk and in that case also sets
 * @result->es_len to 0. In case of error, the error code is returned.
 */
int mockfs_get_next_extent(struct inode *inode, mockfs_lblk_t lblk,
			 unsigned int map_len, struct extent_status *result)
{
	struct mockfs_map_blocks map;
	struct extent_status es = {};
	int ret;

	map.m_lblk = lblk;
	map.m_len = map_len;

	/*
	 * For non-extent based files this loop may iterate several times since
	 * we do not determine full hole size.
	 */
	while (map.m_len > 0) {
		ret = mockfs_map_blocks(NULL, inode, &map, 0);
		if (ret < 0)
			return ret;
		/* There's extent covering m_lblk? Just return it. */
		if (ret > 0) {
			int status;

			mockfs_es_store_pblock(result, map.m_pblk);
			result->es_lblk = map.m_lblk;
			result->es_len = map.m_len;
			if (map.m_flags & MOCKFS_MAP_UNWRITTEN)
				status = EXTENT_STATUS_UNWRITTEN;
			else
				status = EXTENT_STATUS_WRITTEN;
			mockfs_es_store_status(result, status);
			return 1;
		}
		mockfs_es_find_delayed_extent_range(inode, map.m_lblk,
						  map.m_lblk + map.m_len - 1,
						  &es);
		/* Is delalloc data before next block in extent tree? */
		if (es.es_len && es.es_lblk < map.m_lblk + map.m_len) {
			mockfs_lblk_t offset = 0;

			if (es.es_lblk < lblk)
				offset = lblk - es.es_lblk;
			result->es_lblk = es.es_lblk + offset;
			mockfs_es_store_pblock(result,
					     mockfs_es_pblock(&es) + offset);
			result->es_len = es.es_len - offset;
			mockfs_es_store_status(result, mockfs_es_status(&es));

			return 1;
		}
		/* There's a hole at m_lblk, advance us after it */
		map.m_lblk += map.m_len;
		map_len -= map.m_len;
		map.m_len = map_len;
		cond_resched();
	}
	result->es_len = 0;
	return 0;
}
