/*
 *  linux/fs/mockfs/resize.c
 *
 * Support for resizing an mockfs filesystem while it is mounted.
 *
 * Copyright (C) 2001, 2002 Andreas Dilger <adilger@clusterfs.com>
 *
 * This could probably be made into a module, because it is not often in use.
 */


#define MOCKFSFS_DEBUG

#include <linux/errno.h>
#include <linux/slab.h>

#include "mockfs_jbd2.h"

int mockfs_resize_begin(struct super_block *sb)
{
	int ret = 0;

	if (!capable(CAP_SYS_RESOURCE))
		return -EPERM;

	/*
	 * If we are not using the primary superblock/GDT copy don't resize,
         * because the user tools have no way of handling this.  Probably a
         * bad time to do it anyways.
         */
	if (MOCKFS_SB(sb)->s_sbh->b_blocknr !=
	    le32_to_cpu(MOCKFS_SB(sb)->s_es->s_first_data_block)) {
		mockfs_warning(sb, "won't resize using backup superblock at %llu",
			(unsigned long long)MOCKFS_SB(sb)->s_sbh->b_blocknr);
		return -EPERM;
	}

	/*
	 * We are not allowed to do online-resizing on a filesystem mounted
	 * with error, because it can destroy the filesystem easily.
	 */
	if (MOCKFS_SB(sb)->s_mount_state & MOCKFS_ERROR_FS) {
		mockfs_warning(sb, "There are errors in the filesystem, "
			     "so online resizing is not allowed\n");
		return -EPERM;
	}

	if (test_and_set_bit_lock(MOCKFS_RESIZING, &MOCKFS_SB(sb)->s_resize_flags))
		ret = -EBUSY;

	return ret;
}

void mockfs_resize_end(struct super_block *sb)
{
	clear_bit_unlock(MOCKFS_RESIZING, &MOCKFS_SB(sb)->s_resize_flags);
	smp_mb__after_atomic();
}

static mockfs_group_t mockfs_meta_bg_first_group(struct super_block *sb,
					     mockfs_group_t group) {
	return (group >> MOCKFS_DESC_PER_BLOCK_BITS(sb)) <<
	       MOCKFS_DESC_PER_BLOCK_BITS(sb);
}

static mockfs_fsblk_t mockfs_meta_bg_first_block_no(struct super_block *sb,
					     mockfs_group_t group) {
	group = mockfs_meta_bg_first_group(sb, group);
	return mockfs_group_first_block_no(sb, group);
}

static mockfs_grpblk_t mockfs_group_overhead_blocks(struct super_block *sb,
						mockfs_group_t group) {
	mockfs_grpblk_t overhead;
	overhead = mockfs_bg_num_gdb(sb, group);
	if (mockfs_bg_has_super(sb, group))
		overhead += 1 +
			  le16_to_cpu(MOCKFS_SB(sb)->s_es->s_reserved_gdt_blocks);
	return overhead;
}

#define outside(b, first, last)	((b) < (first) || (b) >= (last))
#define inside(b, first, last)	((b) >= (first) && (b) < (last))

static int verify_group_input(struct super_block *sb,
			      struct mockfs_new_group_data *input)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_super_block *es = sbi->s_es;
	mockfs_fsblk_t start = mockfs_blocks_count(es);
	mockfs_fsblk_t end = start + input->blocks_count;
	mockfs_group_t group = input->group;
	mockfs_fsblk_t itend = input->inode_table + sbi->s_itb_per_group;
	unsigned overhead;
	mockfs_fsblk_t metaend;
	struct buffer_head *bh = NULL;
	mockfs_grpblk_t free_blocks_count, offset;
	int err = -EINVAL;

	if (group != sbi->s_groups_count) {
		mockfs_warning(sb, "Cannot add at group %u (only %u groups)",
			     input->group, sbi->s_groups_count);
		return -EINVAL;
	}

	overhead = mockfs_group_overhead_blocks(sb, group);
	metaend = start + overhead;
	input->free_blocks_count = free_blocks_count =
		input->blocks_count - 2 - overhead - sbi->s_itb_per_group;

	if (test_opt(sb, DEBUG))
		printk(KERN_DEBUG "MOCKFS-fs: adding %s group %u: %u blocks "
		       "(%d free, %u reserved)\n",
		       mockfs_bg_has_super(sb, input->group) ? "normal" :
		       "no-super", input->group, input->blocks_count,
		       free_blocks_count, input->reserved_blocks);

	mockfs_get_group_no_and_offset(sb, start, NULL, &offset);
	if (offset != 0)
			mockfs_warning(sb, "Last group not full");
	else if (input->reserved_blocks > input->blocks_count / 5)
		mockfs_warning(sb, "Reserved blocks too high (%u)",
			     input->reserved_blocks);
	else if (free_blocks_count < 0)
		mockfs_warning(sb, "Bad blocks count %u",
			     input->blocks_count);
	else if (!(bh = sb_bread(sb, end - 1)))
		mockfs_warning(sb, "Cannot read last block (%llu)",
			     end - 1);
	else if (outside(input->block_bitmap, start, end))
		mockfs_warning(sb, "Block bitmap not in group (block %llu)",
			     (unsigned long long)input->block_bitmap);
	else if (outside(input->inode_bitmap, start, end))
		mockfs_warning(sb, "Inode bitmap not in group (block %llu)",
			     (unsigned long long)input->inode_bitmap);
	else if (outside(input->inode_table, start, end) ||
		 outside(itend - 1, start, end))
		mockfs_warning(sb, "Inode table not in group (blocks %llu-%llu)",
			     (unsigned long long)input->inode_table, itend - 1);
	else if (input->inode_bitmap == input->block_bitmap)
		mockfs_warning(sb, "Block bitmap same as inode bitmap (%llu)",
			     (unsigned long long)input->block_bitmap);
	else if (inside(input->block_bitmap, input->inode_table, itend))
		mockfs_warning(sb, "Block bitmap (%llu) in inode table "
			     "(%llu-%llu)",
			     (unsigned long long)input->block_bitmap,
			     (unsigned long long)input->inode_table, itend - 1);
	else if (inside(input->inode_bitmap, input->inode_table, itend))
		mockfs_warning(sb, "Inode bitmap (%llu) in inode table "
			     "(%llu-%llu)",
			     (unsigned long long)input->inode_bitmap,
			     (unsigned long long)input->inode_table, itend - 1);
	else if (inside(input->block_bitmap, start, metaend))
		mockfs_warning(sb, "Block bitmap (%llu) in GDT table (%llu-%llu)",
			     (unsigned long long)input->block_bitmap,
			     start, metaend - 1);
	else if (inside(input->inode_bitmap, start, metaend))
		mockfs_warning(sb, "Inode bitmap (%llu) in GDT table (%llu-%llu)",
			     (unsigned long long)input->inode_bitmap,
			     start, metaend - 1);
	else if (inside(input->inode_table, start, metaend) ||
		 inside(itend - 1, start, metaend))
		mockfs_warning(sb, "Inode table (%llu-%llu) overlaps GDT table "
			     "(%llu-%llu)",
			     (unsigned long long)input->inode_table,
			     itend - 1, start, metaend - 1);
	else
		err = 0;
	brelse(bh);

	return err;
}

/*
 * mockfs_new_flex_group_data is used by 64bit-resize interface to add a flex
 * group each time.
 */
struct mockfs_new_flex_group_data {
	struct mockfs_new_group_data *groups;	/* new_group_data for groups
						   in the flex group */
	__u16 *bg_flags;			/* block group flags of groups
						   in @groups */
	mockfs_group_t count;			/* number of groups in @groups
						 */
};

/*
 * alloc_flex_gd() allocates a mockfs_new_flex_group_data with size of
 * @flexbg_size.
 *
 * Returns NULL on failure otherwise address of the allocated structure.
 */
static struct mockfs_new_flex_group_data *alloc_flex_gd(unsigned long flexbg_size)
{
	struct mockfs_new_flex_group_data *flex_gd;

	flex_gd = kmalloc(sizeof(*flex_gd), GFP_NOFS);
	if (flex_gd == NULL)
		goto out3;

	if (flexbg_size >= UINT_MAX / sizeof(struct mockfs_new_group_data))
		goto out2;
	flex_gd->count = flexbg_size;

	flex_gd->groups = kmalloc(sizeof(struct mockfs_new_group_data) *
				  flexbg_size, GFP_NOFS);
	if (flex_gd->groups == NULL)
		goto out2;

	flex_gd->bg_flags = kmalloc(flexbg_size * sizeof(__u16), GFP_NOFS);
	if (flex_gd->bg_flags == NULL)
		goto out1;

	return flex_gd;

out1:
	kfree(flex_gd->groups);
out2:
	kfree(flex_gd);
out3:
	return NULL;
}

static void free_flex_gd(struct mockfs_new_flex_group_data *flex_gd)
{
	kfree(flex_gd->bg_flags);
	kfree(flex_gd->groups);
	kfree(flex_gd);
}

/*
 * mockfs_alloc_group_tables() allocates block bitmaps, inode bitmaps
 * and inode tables for a flex group.
 *
 * This function is used by 64bit-resize.  Note that this function allocates
 * group tables from the 1st group of groups contained by @flexgd, which may
 * be a partial of a flex group.
 *
 * @sb: super block of fs to which the groups belongs
 *
 * Returns 0 on a successful allocation of the metadata blocks in the
 * block group.
 */
static int mockfs_alloc_group_tables(struct super_block *sb,
				struct mockfs_new_flex_group_data *flex_gd,
				int flexbg_size)
{
	struct mockfs_new_group_data *group_data = flex_gd->groups;
	mockfs_fsblk_t start_blk;
	mockfs_fsblk_t last_blk;
	mockfs_group_t src_group;
	mockfs_group_t bb_index = 0;
	mockfs_group_t ib_index = 0;
	mockfs_group_t it_index = 0;
	mockfs_group_t group;
	mockfs_group_t last_group;
	unsigned overhead;
	__u16 uninit_mask = (flexbg_size > 1) ? ~MOCKFS_BG_BLOCK_UNINIT : ~0;

	BUG_ON(flex_gd->count == 0 || group_data == NULL);

	src_group = group_data[0].group;
	last_group  = src_group + flex_gd->count - 1;

	BUG_ON((flexbg_size > 1) && ((src_group & ~(flexbg_size - 1)) !=
	       (last_group & ~(flexbg_size - 1))));
next_group:
	group = group_data[0].group;
	if (src_group >= group_data[0].group + flex_gd->count)
		return -ENOSPC;
	start_blk = mockfs_group_first_block_no(sb, src_group);
	last_blk = start_blk + group_data[src_group - group].blocks_count;

	overhead = mockfs_group_overhead_blocks(sb, src_group);

	start_blk += overhead;

	/* We collect contiguous blocks as much as possible. */
	src_group++;
	for (; src_group <= last_group; src_group++) {
		overhead = mockfs_group_overhead_blocks(sb, src_group);
		if (overhead == 0)
			last_blk += group_data[src_group - group].blocks_count;
		else
			break;
	}

	/* Allocate block bitmaps */
	for (; bb_index < flex_gd->count; bb_index++) {
		if (start_blk >= last_blk)
			goto next_group;
		group_data[bb_index].block_bitmap = start_blk++;
		group = mockfs_get_group_number(sb, start_blk - 1);
		group -= group_data[0].group;
		group_data[group].free_blocks_count--;
		flex_gd->bg_flags[group] &= uninit_mask;
	}

	/* Allocate inode bitmaps */
	for (; ib_index < flex_gd->count; ib_index++) {
		if (start_blk >= last_blk)
			goto next_group;
		group_data[ib_index].inode_bitmap = start_blk++;
		group = mockfs_get_group_number(sb, start_blk - 1);
		group -= group_data[0].group;
		group_data[group].free_blocks_count--;
		flex_gd->bg_flags[group] &= uninit_mask;
	}

	/* Allocate inode tables */
	for (; it_index < flex_gd->count; it_index++) {
		unsigned int itb = MOCKFS_SB(sb)->s_itb_per_group;
		mockfs_fsblk_t next_group_start;

		if (start_blk + itb > last_blk)
			goto next_group;
		group_data[it_index].inode_table = start_blk;
		group = mockfs_get_group_number(sb, start_blk);
		next_group_start = mockfs_group_first_block_no(sb, group + 1);
		group -= group_data[0].group;

		if (start_blk + itb > next_group_start) {
			flex_gd->bg_flags[group + 1] &= uninit_mask;
			overhead = start_blk + itb - next_group_start;
			group_data[group + 1].free_blocks_count -= overhead;
			itb -= overhead;
		}

		group_data[group].free_blocks_count -= itb;
		flex_gd->bg_flags[group] &= uninit_mask;
		start_blk += MOCKFS_SB(sb)->s_itb_per_group;
	}

	if (test_opt(sb, DEBUG)) {
		int i;
		group = group_data[0].group;

		printk(KERN_DEBUG "MOCKFS-fs: adding a flex group with "
		       "%d groups, flexbg size is %d:\n", flex_gd->count,
		       flexbg_size);

		for (i = 0; i < flex_gd->count; i++) {
			printk(KERN_DEBUG "adding %s group %u: %u "
			       "blocks (%d free)\n",
			       mockfs_bg_has_super(sb, group + i) ? "normal" :
			       "no-super", group + i,
			       group_data[i].blocks_count,
			       group_data[i].free_blocks_count);
		}
	}
	return 0;
}

static struct buffer_head *bclean(handle_t *handle, struct super_block *sb,
				  mockfs_fsblk_t blk)
{
	struct buffer_head *bh;
	int err;

	bh = sb_getblk(sb, blk);
	if (unlikely(!bh))
		return ERR_PTR(-ENOMEM);
	BUFFER_TRACE(bh, "get_write_access");
	if ((err = mockfs_journal_get_write_access(handle, bh))) {
		brelse(bh);
		bh = ERR_PTR(err);
	} else {
		memset(bh->b_data, 0, sb->s_blocksize);
		set_buffer_uptodate(bh);
	}

	return bh;
}

/*
 * If we have fewer than thresh credits, extend by MOCKFS_MAX_TRANS_DATA.
 * If that fails, restart the transaction & regain write access for the
 * buffer head which is used for block_bitmap modifications.
 */
static int extend_or_restart_transaction(handle_t *handle, int thresh)
{
	int err;

	if (mockfs_handle_has_enough_credits(handle, thresh))
		return 0;

	err = mockfs_journal_extend(handle, MOCKFS_MAX_TRANS_DATA);
	if (err < 0)
		return err;
	if (err) {
		err = mockfs_journal_restart(handle, MOCKFS_MAX_TRANS_DATA);
		if (err)
			return err;
	}

	return 0;
}

/*
 * set_flexbg_block_bitmap() mark @count blocks starting from @block used.
 *
 * Helper function for mockfs_setup_new_group_blocks() which set .
 *
 * @sb: super block
 * @handle: journal handle
 * @flex_gd: flex group data
 */
static int set_flexbg_block_bitmap(struct super_block *sb, handle_t *handle,
			struct mockfs_new_flex_group_data *flex_gd,
			mockfs_fsblk_t block, mockfs_group_t count)
{
	mockfs_group_t count2;

	mockfs_debug("mark blocks [%llu/%u] used\n", block, count);
	for (count2 = count; count > 0; count -= count2, block += count2) {
		mockfs_fsblk_t start;
		struct buffer_head *bh;
		mockfs_group_t group;
		int err;

		group = mockfs_get_group_number(sb, block);
		start = mockfs_group_first_block_no(sb, group);
		group -= flex_gd->groups[0].group;

		count2 = MOCKFS_BLOCKS_PER_GROUP(sb) - (block - start);
		if (count2 > count)
			count2 = count;

		if (flex_gd->bg_flags[group] & MOCKFS_BG_BLOCK_UNINIT) {
			BUG_ON(flex_gd->count > 1);
			continue;
		}

		err = extend_or_restart_transaction(handle, 1);
		if (err)
			return err;

		bh = sb_getblk(sb, flex_gd->groups[group].block_bitmap);
		if (unlikely(!bh))
			return -ENOMEM;

		BUFFER_TRACE(bh, "get_write_access");
		err = mockfs_journal_get_write_access(handle, bh);
		if (err)
			return err;
		mockfs_debug("mark block bitmap %#04llx (+%llu/%u)\n", block,
			   block - start, count2);
		mockfs_set_bits(bh->b_data, block - start, count2);

		err = mockfs_handle_dirty_metadata(handle, NULL, bh);
		if (unlikely(err))
			return err;
		brelse(bh);
	}

	return 0;
}

/*
 * Set up the block and inode bitmaps, and the inode table for the new groups.
 * This doesn't need to be part of the main transaction, since we are only
 * changing blocks outside the actual filesystem.  We still do journaling to
 * ensure the recovery is correct in case of a failure just after resize.
 * If any part of this fails, we simply abort the resize.
 *
 * setup_new_flex_group_blocks handles a flex group as follow:
 *  1. copy super block and GDT, and initialize group tables if necessary.
 *     In this step, we only set bits in blocks bitmaps for blocks taken by
 *     super block and GDT.
 *  2. allocate group tables in block bitmaps, that is, set bits in block
 *     bitmap for blocks taken by group tables.
 */
static int setup_new_flex_group_blocks(struct super_block *sb,
				struct mockfs_new_flex_group_data *flex_gd)
{
	int group_table_count[] = {1, 1, MOCKFS_SB(sb)->s_itb_per_group};
	mockfs_fsblk_t start;
	mockfs_fsblk_t block;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_super_block *es = sbi->s_es;
	struct mockfs_new_group_data *group_data = flex_gd->groups;
	__u16 *bg_flags = flex_gd->bg_flags;
	handle_t *handle;
	mockfs_group_t group, count;
	struct buffer_head *bh = NULL;
	int reserved_gdb, i, j, err = 0, err2;
	int meta_bg;

	BUG_ON(!flex_gd->count || !group_data ||
	       group_data[0].group != sbi->s_groups_count);

	reserved_gdb = le16_to_cpu(es->s_reserved_gdt_blocks);
	meta_bg = mockfs_has_feature_meta_bg(sb);

	/* This transaction may be extended/restarted along the way */
	handle = mockfs_journal_start_sb(sb, MOCKFS_HT_RESIZE, MOCKFS_MAX_TRANS_DATA);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	group = group_data[0].group;
	for (i = 0; i < flex_gd->count; i++, group++) {
		unsigned long gdblocks;
		mockfs_grpblk_t overhead;

		gdblocks = mockfs_bg_num_gdb(sb, group);
		start = mockfs_group_first_block_no(sb, group);

		if (meta_bg == 0 && !mockfs_bg_has_super(sb, group))
			goto handle_itb;

		if (meta_bg == 1) {
			mockfs_group_t first_group;
			first_group = mockfs_meta_bg_first_group(sb, group);
			if (first_group != group + 1 &&
			    first_group != group + MOCKFS_DESC_PER_BLOCK(sb) - 1)
				goto handle_itb;
		}

		block = start + mockfs_bg_has_super(sb, group);
		/* Copy all of the GDT blocks into the backup in this group */
		for (j = 0; j < gdblocks; j++, block++) {
			struct buffer_head *gdb;

			mockfs_debug("update backup group %#04llx\n", block);
			err = extend_or_restart_transaction(handle, 1);
			if (err)
				goto out;

			gdb = sb_getblk(sb, block);
			if (unlikely(!gdb)) {
				err = -ENOMEM;
				goto out;
			}

			BUFFER_TRACE(gdb, "get_write_access");
			err = mockfs_journal_get_write_access(handle, gdb);
			if (err) {
				brelse(gdb);
				goto out;
			}
			memcpy(gdb->b_data, sbi->s_group_desc[j]->b_data,
			       gdb->b_size);
			set_buffer_uptodate(gdb);

			err = mockfs_handle_dirty_metadata(handle, NULL, gdb);
			if (unlikely(err)) {
				brelse(gdb);
				goto out;
			}
			brelse(gdb);
		}

		/* Zero out all of the reserved backup group descriptor
		 * table blocks
		 */
		if (mockfs_bg_has_super(sb, group)) {
			err = sb_issue_zeroout(sb, gdblocks + start + 1,
					reserved_gdb, GFP_NOFS);
			if (err)
				goto out;
		}

handle_itb:
		/* Initialize group tables of the grop @group */
		if (!(bg_flags[i] & MOCKFS_BG_INODE_ZEROED))
			goto handle_bb;

		/* Zero out all of the inode table blocks */
		block = group_data[i].inode_table;
		mockfs_debug("clear inode table blocks %#04llx -> %#04lx\n",
			   block, sbi->s_itb_per_group);
		err = sb_issue_zeroout(sb, block, sbi->s_itb_per_group,
				       GFP_NOFS);
		if (err)
			goto out;

handle_bb:
		if (bg_flags[i] & MOCKFS_BG_BLOCK_UNINIT)
			goto handle_ib;

		/* Initialize block bitmap of the @group */
		block = group_data[i].block_bitmap;
		err = extend_or_restart_transaction(handle, 1);
		if (err)
			goto out;

		bh = bclean(handle, sb, block);
		if (IS_ERR(bh)) {
			err = PTR_ERR(bh);
			bh = NULL;
			goto out;
		}
		overhead = mockfs_group_overhead_blocks(sb, group);
		if (overhead != 0) {
			mockfs_debug("mark backup superblock %#04llx (+0)\n",
				   start);
			mockfs_set_bits(bh->b_data, 0, overhead);
		}
		mockfs_mark_bitmap_end(group_data[i].blocks_count,
				     sb->s_blocksize * 8, bh->b_data);
		err = mockfs_handle_dirty_metadata(handle, NULL, bh);
		if (err)
			goto out;
		brelse(bh);

handle_ib:
		if (bg_flags[i] & MOCKFS_BG_INODE_UNINIT)
			continue;

		/* Initialize inode bitmap of the @group */
		block = group_data[i].inode_bitmap;
		err = extend_or_restart_transaction(handle, 1);
		if (err)
			goto out;
		/* Mark unused entries in inode bitmap used */
		bh = bclean(handle, sb, block);
		if (IS_ERR(bh)) {
			err = PTR_ERR(bh);
			bh = NULL;
			goto out;
		}

		mockfs_mark_bitmap_end(MOCKFS_INODES_PER_GROUP(sb),
				     sb->s_blocksize * 8, bh->b_data);
		err = mockfs_handle_dirty_metadata(handle, NULL, bh);
		if (err)
			goto out;
		brelse(bh);
	}
	bh = NULL;

	/* Mark group tables in block bitmap */
	for (j = 0; j < GROUP_TABLE_COUNT; j++) {
		count = group_table_count[j];
		start = (&group_data[0].block_bitmap)[j];
		block = start;
		for (i = 1; i < flex_gd->count; i++) {
			block += group_table_count[j];
			if (block == (&group_data[i].block_bitmap)[j]) {
				count += group_table_count[j];
				continue;
			}
			err = set_flexbg_block_bitmap(sb, handle,
						flex_gd, start, count);
			if (err)
				goto out;
			count = group_table_count[j];
			start = (&group_data[i].block_bitmap)[j];
			block = start;
		}

		if (count) {
			err = set_flexbg_block_bitmap(sb, handle,
						flex_gd, start, count);
			if (err)
				goto out;
		}
	}

out:
	brelse(bh);
	err2 = mockfs_journal_stop(handle);
	if (err2 && !err)
		err = err2;

	return err;
}

/*
 * Iterate through the groups which hold BACKUP superblock/GDT copies in an
 * mockfs filesystem.  The counters should be initialized to 1, 5, and 7 before
 * calling this for the first time.  In a sparse filesystem it will be the
 * sequence of powers of 3, 5, and 7: 1, 3, 5, 7, 9, 25, 27, 49, 81, ...
 * For a non-sparse filesystem it will be every group: 1, 2, 3, 4, ...
 */
static unsigned mockfs_list_backups(struct super_block *sb, unsigned *three,
				  unsigned *five, unsigned *seven)
{
	unsigned *min = three;
	int mult = 3;
	unsigned ret;

	if (!mockfs_has_feature_sparse_super(sb)) {
		ret = *min;
		*min += 1;
		return ret;
	}

	if (*five < *min) {
		min = five;
		mult = 5;
	}
	if (*seven < *min) {
		min = seven;
		mult = 7;
	}

	ret = *min;
	*min *= mult;

	return ret;
}

/*
 * Check that all of the backup GDT blocks are held in the primary GDT block.
 * It is assumed that they are stored in group order.  Returns the number of
 * groups in current filesystem that have BACKUPS, or -ve error code.
 */
static int verify_reserved_gdb(struct super_block *sb,
			       mockfs_group_t end,
			       struct buffer_head *primary)
{
	const mockfs_fsblk_t blk = primary->b_blocknr;
	unsigned three = 1;
	unsigned five = 5;
	unsigned seven = 7;
	unsigned grp;
	__le32 *p = (__le32 *)primary->b_data;
	int gdbackups = 0;

	while ((grp = mockfs_list_backups(sb, &three, &five, &seven)) < end) {
		if (le32_to_cpu(*p++) !=
		    grp * MOCKFS_BLOCKS_PER_GROUP(sb) + blk){
			mockfs_warning(sb, "reserved GDT %llu"
				     " missing grp %d (%llu)",
				     blk, grp,
				     grp *
				     (mockfs_fsblk_t)MOCKFS_BLOCKS_PER_GROUP(sb) +
				     blk);
			return -EINVAL;
		}
		if (++gdbackups > MOCKFS_ADDR_PER_BLOCK(sb))
			return -EFBIG;
	}

	return gdbackups;
}

/*
 * Called when we need to bring a reserved group descriptor table block into
 * use from the resize inode.  The primary copy of the new GDT block currently
 * is an indirect block (under the double indirect block in the resize inode).
 * The new backup GDT blocks will be stored as leaf blocks in this indirect
 * block, in group order.  Even though we know all the block numbers we need,
 * we check to ensure that the resize inode has actually reserved these blocks.
 *
 * Don't need to update the block bitmaps because the blocks are still in use.
 *
 * We get all of the error cases out of the way, so that we are sure to not
 * fail once we start modifying the data on disk, because JBD has no rollback.
 */
static int add_new_gdb(handle_t *handle, struct inode *inode,
		       mockfs_group_t group)
{
	struct super_block *sb = inode->i_sb;
	struct mockfs_super_block *es = MOCKFS_SB(sb)->s_es;
	unsigned long gdb_num = group / MOCKFS_DESC_PER_BLOCK(sb);
	mockfs_fsblk_t gdblock = MOCKFS_SB(sb)->s_sbh->b_blocknr + 1 + gdb_num;
	struct buffer_head **o_group_desc, **n_group_desc;
	struct buffer_head *dind;
	struct buffer_head *gdb_bh;
	int gdbackups;
	struct mockfs_iloc iloc;
	__le32 *data;
	int err;

	if (test_opt(sb, DEBUG))
		printk(KERN_DEBUG
		       "MOCKFS-fs: mockfs_add_new_gdb: adding group block %lu\n",
		       gdb_num);

	gdb_bh = sb_bread(sb, gdblock);
	if (!gdb_bh)
		return -EIO;

	gdbackups = verify_reserved_gdb(sb, group, gdb_bh);
	if (gdbackups < 0) {
		err = gdbackups;
		goto exit_bh;
	}

	data = MOCKFS_I(inode)->i_data + MOCKFS_DIND_BLOCK;
	dind = sb_bread(sb, le32_to_cpu(*data));
	if (!dind) {
		err = -EIO;
		goto exit_bh;
	}

	data = (__le32 *)dind->b_data;
	if (le32_to_cpu(data[gdb_num % MOCKFS_ADDR_PER_BLOCK(sb)]) != gdblock) {
		mockfs_warning(sb, "new group %u GDT block %llu not reserved",
			     group, gdblock);
		err = -EINVAL;
		goto exit_dind;
	}

	BUFFER_TRACE(MOCKFS_SB(sb)->s_sbh, "get_write_access");
	err = mockfs_journal_get_write_access(handle, MOCKFS_SB(sb)->s_sbh);
	if (unlikely(err))
		goto exit_dind;

	BUFFER_TRACE(gdb_bh, "get_write_access");
	err = mockfs_journal_get_write_access(handle, gdb_bh);
	if (unlikely(err))
		goto exit_dind;

	BUFFER_TRACE(dind, "get_write_access");
	err = mockfs_journal_get_write_access(handle, dind);
	if (unlikely(err))
		mockfs_std_error(sb, err);

	/* mockfs_reserve_inode_write() gets a reference on the iloc */
	err = mockfs_reserve_inode_write(handle, inode, &iloc);
	if (unlikely(err))
		goto exit_dind;

	n_group_desc = mockfs_kvmalloc((gdb_num + 1) *
				     sizeof(struct buffer_head *),
				     GFP_NOFS);
	if (!n_group_desc) {
		err = -ENOMEM;
		mockfs_warning(sb, "not enough memory for %lu groups",
			     gdb_num + 1);
		goto exit_inode;
	}

	/*
	 * Finally, we have all of the possible failures behind us...
	 *
	 * Remove new GDT block from inode double-indirect block and clear out
	 * the new GDT block for use (which also "frees" the backup GDT blocks
	 * from the reserved inode).  We don't need to change the bitmaps for
	 * these blocks, because they are marked as in-use from being in the
	 * reserved inode, and will become GDT blocks (primary and backup).
	 */
	data[gdb_num % MOCKFS_ADDR_PER_BLOCK(sb)] = 0;
	err = mockfs_handle_dirty_metadata(handle, NULL, dind);
	if (unlikely(err)) {
		mockfs_std_error(sb, err);
		goto exit_inode;
	}
	inode->i_blocks -= (gdbackups + 1) * sb->s_blocksize >> 9;
	mockfs_mark_iloc_dirty(handle, inode, &iloc);
	memset(gdb_bh->b_data, 0, sb->s_blocksize);
	err = mockfs_handle_dirty_metadata(handle, NULL, gdb_bh);
	if (unlikely(err)) {
		mockfs_std_error(sb, err);
		goto exit_inode;
	}
	brelse(dind);

	o_group_desc = MOCKFS_SB(sb)->s_group_desc;
	memcpy(n_group_desc, o_group_desc,
	       MOCKFS_SB(sb)->s_gdb_count * sizeof(struct buffer_head *));
	n_group_desc[gdb_num] = gdb_bh;
	MOCKFS_SB(sb)->s_group_desc = n_group_desc;
	MOCKFS_SB(sb)->s_gdb_count++;
	kvfree(o_group_desc);

	le16_add_cpu(&es->s_reserved_gdt_blocks, -1);
	err = mockfs_handle_dirty_super(handle, sb);
	if (err)
		mockfs_std_error(sb, err);

	return err;

exit_inode:
	kvfree(n_group_desc);
	brelse(iloc.bh);
exit_dind:
	brelse(dind);
exit_bh:
	brelse(gdb_bh);

	mockfs_debug("leaving with error %d\n", err);
	return err;
}

/*
 * add_new_gdb_meta_bg is the sister of add_new_gdb.
 */
static int add_new_gdb_meta_bg(struct super_block *sb,
			       handle_t *handle, mockfs_group_t group) {
	mockfs_fsblk_t gdblock;
	struct buffer_head *gdb_bh;
	struct buffer_head **o_group_desc, **n_group_desc;
	unsigned long gdb_num = group / MOCKFS_DESC_PER_BLOCK(sb);
	int err;

	gdblock = mockfs_meta_bg_first_block_no(sb, group) +
		   mockfs_bg_has_super(sb, group);
	gdb_bh = sb_bread(sb, gdblock);
	if (!gdb_bh)
		return -EIO;
	n_group_desc = mockfs_kvmalloc((gdb_num + 1) *
				     sizeof(struct buffer_head *),
				     GFP_NOFS);
	if (!n_group_desc) {
		err = -ENOMEM;
		mockfs_warning(sb, "not enough memory for %lu groups",
			     gdb_num + 1);
		return err;
	}

	o_group_desc = MOCKFS_SB(sb)->s_group_desc;
	memcpy(n_group_desc, o_group_desc,
	       MOCKFS_SB(sb)->s_gdb_count * sizeof(struct buffer_head *));
	n_group_desc[gdb_num] = gdb_bh;
	MOCKFS_SB(sb)->s_group_desc = n_group_desc;
	MOCKFS_SB(sb)->s_gdb_count++;
	kvfree(o_group_desc);
	BUFFER_TRACE(gdb_bh, "get_write_access");
	err = mockfs_journal_get_write_access(handle, gdb_bh);
	if (unlikely(err))
		brelse(gdb_bh);
	return err;
}

/*
 * Called when we are adding a new group which has a backup copy of each of
 * the GDT blocks (i.e. sparse group) and there are reserved GDT blocks.
 * We need to add these reserved backup GDT blocks to the resize inode, so
 * that they are kept for future resizing and not allocated to files.
 *
 * Each reserved backup GDT block will go into a different indirect block.
 * The indirect blocks are actually the primary reserved GDT blocks,
 * so we know in advance what their block numbers are.  We only get the
 * double-indirect block to verify it is pointing to the primary reserved
 * GDT blocks so we don't overwrite a data block by accident.  The reserved
 * backup GDT blocks are stored in their reserved primary GDT block.
 */
static int reserve_backup_gdb(handle_t *handle, struct inode *inode,
			      mockfs_group_t group)
{
	struct super_block *sb = inode->i_sb;
	int reserved_gdb =le16_to_cpu(MOCKFS_SB(sb)->s_es->s_reserved_gdt_blocks);
	struct buffer_head **primary;
	struct buffer_head *dind;
	struct mockfs_iloc iloc;
	mockfs_fsblk_t blk;
	__le32 *data, *end;
	int gdbackups = 0;
	int res, i;
	int err;

	primary = kmalloc(reserved_gdb * sizeof(*primary), GFP_NOFS);
	if (!primary)
		return -ENOMEM;

	data = MOCKFS_I(inode)->i_data + MOCKFS_DIND_BLOCK;
	dind = sb_bread(sb, le32_to_cpu(*data));
	if (!dind) {
		err = -EIO;
		goto exit_free;
	}

	blk = MOCKFS_SB(sb)->s_sbh->b_blocknr + 1 + MOCKFS_SB(sb)->s_gdb_count;
	data = (__le32 *)dind->b_data + (MOCKFS_SB(sb)->s_gdb_count %
					 MOCKFS_ADDR_PER_BLOCK(sb));
	end = (__le32 *)dind->b_data + MOCKFS_ADDR_PER_BLOCK(sb);

	/* Get each reserved primary GDT block and verify it holds backups */
	for (res = 0; res < reserved_gdb; res++, blk++) {
		if (le32_to_cpu(*data) != blk) {
			mockfs_warning(sb, "reserved block %llu"
				     " not at offset %ld",
				     blk,
				     (long)(data - (__le32 *)dind->b_data));
			err = -EINVAL;
			goto exit_bh;
		}
		primary[res] = sb_bread(sb, blk);
		if (!primary[res]) {
			err = -EIO;
			goto exit_bh;
		}
		gdbackups = verify_reserved_gdb(sb, group, primary[res]);
		if (gdbackups < 0) {
			brelse(primary[res]);
			err = gdbackups;
			goto exit_bh;
		}
		if (++data >= end)
			data = (__le32 *)dind->b_data;
	}

	for (i = 0; i < reserved_gdb; i++) {
		BUFFER_TRACE(primary[i], "get_write_access");
		if ((err = mockfs_journal_get_write_access(handle, primary[i])))
			goto exit_bh;
	}

	if ((err = mockfs_reserve_inode_write(handle, inode, &iloc)))
		goto exit_bh;

	/*
	 * Finally we can add each of the reserved backup GDT blocks from
	 * the new group to its reserved primary GDT block.
	 */
	blk = group * MOCKFS_BLOCKS_PER_GROUP(sb);
	for (i = 0; i < reserved_gdb; i++) {
		int err2;
		data = (__le32 *)primary[i]->b_data;
		/* printk("reserving backup %lu[%u] = %lu\n",
		       primary[i]->b_blocknr, gdbackups,
		       blk + primary[i]->b_blocknr); */
		data[gdbackups] = cpu_to_le32(blk + primary[i]->b_blocknr);
		err2 = mockfs_handle_dirty_metadata(handle, NULL, primary[i]);
		if (!err)
			err = err2;
	}
	inode->i_blocks += reserved_gdb * sb->s_blocksize >> 9;
	mockfs_mark_iloc_dirty(handle, inode, &iloc);

exit_bh:
	while (--res >= 0)
		brelse(primary[res]);
	brelse(dind);

exit_free:
	kfree(primary);

	return err;
}

/*
 * Update the backup copies of the mockfs metadata.  These don't need to be part
 * of the main resize transaction, because e2fsck will re-write them if there
 * is a problem (basically only OOM will cause a problem).  However, we
 * _should_ update the backups if possible, in case the primary gets trashed
 * for some reason and we need to run e2fsck from a backup superblock.  The
 * important part is that the new block and inode counts are in the backup
 * superblocks, and the location of the new group metadata in the GDT backups.
 *
 * We do not need take the s_resize_lock for this, because these
 * blocks are not otherwise touched by the filesystem code when it is
 * mounted.  We don't need to worry about last changing from
 * sbi->s_groups_count, because the worst that can happen is that we
 * do not copy the full number of backups at this time.  The resize
 * which changed s_groups_count will backup again.
 */
static void update_backups(struct super_block *sb, sector_t blk_off, char *data,
			   int size, int meta_bg)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	mockfs_group_t last;
	const int bpg = MOCKFS_BLOCKS_PER_GROUP(sb);
	unsigned three = 1;
	unsigned five = 5;
	unsigned seven = 7;
	mockfs_group_t group = 0;
	int rest = sb->s_blocksize - size;
	handle_t *handle;
	int err = 0, err2;

	handle = mockfs_journal_start_sb(sb, MOCKFS_HT_RESIZE, MOCKFS_MAX_TRANS_DATA);
	if (IS_ERR(handle)) {
		group = 1;
		err = PTR_ERR(handle);
		goto exit_err;
	}

	if (meta_bg == 0) {
		group = mockfs_list_backups(sb, &three, &five, &seven);
		last = sbi->s_groups_count;
	} else {
		group = mockfs_get_group_number(sb, blk_off) + 1;
		last = (mockfs_group_t)(group + MOCKFS_DESC_PER_BLOCK(sb) - 2);
	}

	while (group < sbi->s_groups_count) {
		struct buffer_head *bh;
		mockfs_fsblk_t backup_block;

		/* Out of journal space, and can't get more - abort - so sad */
		if (mockfs_handle_valid(handle) &&
		    handle->h_buffer_credits == 0 &&
		    mockfs_journal_extend(handle, MOCKFS_MAX_TRANS_DATA) &&
		    (err = mockfs_journal_restart(handle, MOCKFS_MAX_TRANS_DATA)))
			break;

		if (meta_bg == 0)
			backup_block = ((mockfs_fsblk_t)group) * bpg + blk_off;
		else
			backup_block = (mockfs_group_first_block_no(sb, group) +
					mockfs_bg_has_super(sb, group));

		bh = sb_getblk(sb, backup_block);
		if (unlikely(!bh)) {
			err = -ENOMEM;
			break;
		}
		mockfs_debug("update metadata backup %llu(+%llu)\n",
			   backup_block, backup_block -
			   mockfs_group_first_block_no(sb, group));
		BUFFER_TRACE(bh, "get_write_access");
		if ((err = mockfs_journal_get_write_access(handle, bh)))
			break;
		lock_buffer(bh);
		memcpy(bh->b_data, data, size);
		if (rest)
			memset(bh->b_data + size, 0, rest);
		set_buffer_uptodate(bh);
		unlock_buffer(bh);
		err = mockfs_handle_dirty_metadata(handle, NULL, bh);
		if (unlikely(err))
			mockfs_std_error(sb, err);
		brelse(bh);

		if (meta_bg == 0)
			group = mockfs_list_backups(sb, &three, &five, &seven);
		else if (group == last)
			break;
		else
			group = last;
	}
	if ((err2 = mockfs_journal_stop(handle)) && !err)
		err = err2;

	/*
	 * Ugh! Need to have e2fsck write the backup copies.  It is too
	 * late to revert the resize, we shouldn't fail just because of
	 * the backup copies (they are only needed in case of corruption).
	 *
	 * However, if we got here we have a journal problem too, so we
	 * can't really start a transaction to mark the superblock.
	 * Chicken out and just set the flag on the hope it will be written
	 * to disk, and if not - we will simply wait until next fsck.
	 */
exit_err:
	if (err) {
		mockfs_warning(sb, "can't update backup for group %u (err %d), "
			     "forcing fsck on next reboot", group, err);
		sbi->s_mount_state &= ~MOCKFS_VALID_FS;
		sbi->s_es->s_state &= cpu_to_le16(~MOCKFS_VALID_FS);
		mark_buffer_dirty(sbi->s_sbh);
	}
}

/*
 * mockfs_add_new_descs() adds @count group descriptor of groups
 * starting at @group
 *
 * @handle: journal handle
 * @sb: super block
 * @group: the group no. of the first group desc to be added
 * @resize_inode: the resize inode
 * @count: number of group descriptors to be added
 */
static int mockfs_add_new_descs(handle_t *handle, struct super_block *sb,
			      mockfs_group_t group, struct inode *resize_inode,
			      mockfs_group_t count)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_super_block *es = sbi->s_es;
	struct buffer_head *gdb_bh;
	int i, gdb_off, gdb_num, err = 0;
	int meta_bg;

	meta_bg = mockfs_has_feature_meta_bg(sb);
	for (i = 0; i < count; i++, group++) {
		int reserved_gdb = mockfs_bg_has_super(sb, group) ?
			le16_to_cpu(es->s_reserved_gdt_blocks) : 0;

		gdb_off = group % MOCKFS_DESC_PER_BLOCK(sb);
		gdb_num = group / MOCKFS_DESC_PER_BLOCK(sb);

		/*
		 * We will only either add reserved group blocks to a backup group
		 * or remove reserved blocks for the first group in a new group block.
		 * Doing both would be mean more complex code, and sane people don't
		 * use non-sparse filesystems anymore.  This is already checked above.
		 */
		if (gdb_off) {
			gdb_bh = sbi->s_group_desc[gdb_num];
			BUFFER_TRACE(gdb_bh, "get_write_access");
			err = mockfs_journal_get_write_access(handle, gdb_bh);

			if (!err && reserved_gdb && mockfs_bg_num_gdb(sb, group))
				err = reserve_backup_gdb(handle, resize_inode, group);
		} else if (meta_bg != 0) {
			err = add_new_gdb_meta_bg(sb, handle, group);
		} else {
			err = add_new_gdb(handle, resize_inode, group);
		}
		if (err)
			break;
	}
	return err;
}

static struct buffer_head *mockfs_get_bitmap(struct super_block *sb, __u64 block)
{
	struct buffer_head *bh = sb_getblk(sb, block);
	if (unlikely(!bh))
		return NULL;
	if (!bh_uptodate_or_lock(bh)) {
		if (bh_submit_read(bh) < 0) {
			brelse(bh);
			return NULL;
		}
	}

	return bh;
}

static int mockfs_set_bitmap_checksums(struct super_block *sb,
				     mockfs_group_t group,
				     struct mockfs_group_desc *gdp,
				     struct mockfs_new_group_data *group_data)
{
	struct buffer_head *bh;

	if (!mockfs_has_metadata_csum(sb))
		return 0;

	bh = mockfs_get_bitmap(sb, group_data->inode_bitmap);
	if (!bh)
		return -EIO;
	mockfs_inode_bitmap_csum_set(sb, group, gdp, bh,
				   MOCKFS_INODES_PER_GROUP(sb) / 8);
	brelse(bh);

	bh = mockfs_get_bitmap(sb, group_data->block_bitmap);
	if (!bh)
		return -EIO;
	mockfs_block_bitmap_csum_set(sb, group, gdp, bh);
	brelse(bh);

	return 0;
}

/*
 * mockfs_setup_new_descs() will set up the group descriptor descriptors of a flex bg
 */
static int mockfs_setup_new_descs(handle_t *handle, struct super_block *sb,
				struct mockfs_new_flex_group_data *flex_gd)
{
	struct mockfs_new_group_data	*group_data = flex_gd->groups;
	struct mockfs_group_desc		*gdp;
	struct mockfs_sb_info		*sbi = MOCKFS_SB(sb);
	struct buffer_head		*gdb_bh;
	mockfs_group_t			group;
	__u16				*bg_flags = flex_gd->bg_flags;
	int				i, gdb_off, gdb_num, err = 0;
	

	for (i = 0; i < flex_gd->count; i++, group_data++, bg_flags++) {
		group = group_data->group;

		gdb_off = group % MOCKFS_DESC_PER_BLOCK(sb);
		gdb_num = group / MOCKFS_DESC_PER_BLOCK(sb);

		/*
		 * get_write_access() has been called on gdb_bh by mockfs_add_new_desc().
		 */
		gdb_bh = sbi->s_group_desc[gdb_num];
		/* Update group descriptor block for new group */
		gdp = (struct mockfs_group_desc *)(gdb_bh->b_data +
						 gdb_off * MOCKFS_DESC_SIZE(sb));

		memset(gdp, 0, MOCKFS_DESC_SIZE(sb));
		mockfs_block_bitmap_set(sb, gdp, group_data->block_bitmap);
		mockfs_inode_bitmap_set(sb, gdp, group_data->inode_bitmap);
		err = mockfs_set_bitmap_checksums(sb, group, gdp, group_data);
		if (err) {
			mockfs_std_error(sb, err);
			break;
		}

		mockfs_inode_table_set(sb, gdp, group_data->inode_table);
		mockfs_free_group_clusters_set(sb, gdp,
			MOCKFS_NUM_B2C(sbi, group_data->free_blocks_count));
		mockfs_free_inodes_set(sb, gdp, MOCKFS_INODES_PER_GROUP(sb));
		if (mockfs_has_group_desc_csum(sb))
			mockfs_itable_unused_set(sb, gdp,
					       MOCKFS_INODES_PER_GROUP(sb));
		gdp->bg_flags = cpu_to_le16(*bg_flags);
		mockfs_group_desc_csum_set(sb, group, gdp);

		err = mockfs_handle_dirty_metadata(handle, NULL, gdb_bh);
		if (unlikely(err)) {
			mockfs_std_error(sb, err);
			break;
		}

		/*
		 * We can allocate memory for mb_alloc based on the new group
		 * descriptor
		 */
		err = mockfs_mb_add_groupinfo(sb, group, gdp);
		if (err)
			break;
	}
	return err;
}

/*
 * mockfs_update_super() updates the super block so that the newly added
 * groups can be seen by the filesystem.
 *
 * @sb: super block
 * @flex_gd: new added groups
 */
static void mockfs_update_super(struct super_block *sb,
			     struct mockfs_new_flex_group_data *flex_gd)
{
	mockfs_fsblk_t blocks_count = 0;
	mockfs_fsblk_t free_blocks = 0;
	mockfs_fsblk_t reserved_blocks = 0;
	struct mockfs_new_group_data *group_data = flex_gd->groups;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_super_block *es = sbi->s_es;
	int i;

	BUG_ON(flex_gd->count == 0 || group_data == NULL);
	/*
	 * Make the new blocks and inodes valid next.  We do this before
	 * increasing the group count so that once the group is enabled,
	 * all of its blocks and inodes are already valid.
	 *
	 * We always allocate group-by-group, then block-by-block or
	 * inode-by-inode within a group, so enabling these
	 * blocks/inodes before the group is live won't actually let us
	 * allocate the new space yet.
	 */
	for (i = 0; i < flex_gd->count; i++) {
		blocks_count += group_data[i].blocks_count;
		free_blocks += group_data[i].free_blocks_count;
	}

	reserved_blocks = mockfs_r_blocks_count(es) * 100;
	reserved_blocks = div64_u64(reserved_blocks, mockfs_blocks_count(es));
	reserved_blocks *= blocks_count;
	do_div(reserved_blocks, 100);

	mockfs_blocks_count_set(es, mockfs_blocks_count(es) + blocks_count);
	mockfs_free_blocks_count_set(es, mockfs_free_blocks_count(es) + free_blocks);
	le32_add_cpu(&es->s_inodes_count, MOCKFS_INODES_PER_GROUP(sb) *
		     flex_gd->count);
	le32_add_cpu(&es->s_free_inodes_count, MOCKFS_INODES_PER_GROUP(sb) *
		     flex_gd->count);

	mockfs_debug("free blocks count %llu", mockfs_free_blocks_count(es));
	/*
	 * We need to protect s_groups_count against other CPUs seeing
	 * inconsistent state in the superblock.
	 *
	 * The precise rules we use are:
	 *
	 * * Writers must perform a smp_wmb() after updating all
	 *   dependent data and before modifying the groups count
	 *
	 * * Readers must perform an smp_rmb() after reading the groups
	 *   count and before reading any dependent data.
	 *
	 * NB. These rules can be relaxed when checking the group count
	 * while freeing data, as we can only allocate from a block
	 * group after serialising against the group count, and we can
	 * only then free after serialising in turn against that
	 * allocation.
	 */
	smp_wmb();

	/* Update the global fs size fields */
	sbi->s_groups_count += flex_gd->count;
	sbi->s_blockfile_groups = min_t(mockfs_group_t, sbi->s_groups_count,
			(MOCKFS_MAX_BLOCK_FILE_PHYS / MOCKFS_BLOCKS_PER_GROUP(sb)));

	/* Update the reserved block counts only once the new group is
	 * active. */
	mockfs_r_blocks_count_set(es, mockfs_r_blocks_count(es) +
				reserved_blocks);

	/* Update the free space counts */
	percpu_counter_add(&sbi->s_freeclusters_counter,
			   MOCKFS_NUM_B2C(sbi, free_blocks));
	percpu_counter_add(&sbi->s_freeinodes_counter,
			   MOCKFS_INODES_PER_GROUP(sb) * flex_gd->count);

	mockfs_debug("free blocks count %llu",
		   percpu_counter_read(&sbi->s_freeclusters_counter));
	if (mockfs_has_feature_flex_bg(sb) && sbi->s_log_groups_per_flex) {
		mockfs_group_t flex_group;
		flex_group = mockfs_flex_group(sbi, group_data[0].group);
		atomic64_add(MOCKFS_NUM_B2C(sbi, free_blocks),
			     &sbi->s_flex_groups[flex_group].free_clusters);
		atomic_add(MOCKFS_INODES_PER_GROUP(sb) * flex_gd->count,
			   &sbi->s_flex_groups[flex_group].free_inodes);
	}

	/*
	 * Update the fs overhead information
	 */
	mockfs_calculate_overhead(sb);

	if (test_opt(sb, DEBUG))
		printk(KERN_DEBUG "MOCKFS-fs: added group %u:"
		       "%llu blocks(%llu free %llu reserved)\n", flex_gd->count,
		       blocks_count, free_blocks, reserved_blocks);
}

/* Add a flex group to an fs. Ensure we handle all possible error conditions
 * _before_ we start modifying the filesystem, because we cannot abort the
 * transaction and not have it write the data to disk.
 */
static int mockfs_flex_group_add(struct super_block *sb,
			       struct inode *resize_inode,
			       struct mockfs_new_flex_group_data *flex_gd)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_super_block *es = sbi->s_es;
	mockfs_fsblk_t o_blocks_count;
	mockfs_grpblk_t last;
	mockfs_group_t group;
	handle_t *handle;
	unsigned reserved_gdb;
	int err = 0, err2 = 0, credit;

	BUG_ON(!flex_gd->count || !flex_gd->groups || !flex_gd->bg_flags);

	reserved_gdb = le16_to_cpu(es->s_reserved_gdt_blocks);
	o_blocks_count = mockfs_blocks_count(es);
	mockfs_get_group_no_and_offset(sb, o_blocks_count, &group, &last);
	BUG_ON(last);

	err = setup_new_flex_group_blocks(sb, flex_gd);
	if (err)
		goto exit;
	/*
	 * We will always be modifying at least the superblock and  GDT
	 * blocks.  If we are adding a group past the last current GDT block,
	 * we will also modify the inode and the dindirect block.  If we
	 * are adding a group with superblock/GDT backups  we will also
	 * modify each of the reserved GDT dindirect blocks.
	 */
	credit = 3;	/* sb, resize inode, resize inode dindirect */
	/* GDT blocks */
	credit += 1 + DIV_ROUND_UP(flex_gd->count, MOCKFS_DESC_PER_BLOCK(sb));
	credit += reserved_gdb;	/* Reserved GDT dindirect blocks */
	handle = mockfs_journal_start_sb(sb, MOCKFS_HT_RESIZE, credit);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto exit;
	}

	BUFFER_TRACE(sbi->s_sbh, "get_write_access");
	err = mockfs_journal_get_write_access(handle, sbi->s_sbh);
	if (err)
		goto exit_journal;

	group = flex_gd->groups[0].group;
	BUG_ON(group != MOCKFS_SB(sb)->s_groups_count);
	err = mockfs_add_new_descs(handle, sb, group,
				resize_inode, flex_gd->count);
	if (err)
		goto exit_journal;

	err = mockfs_setup_new_descs(handle, sb, flex_gd);
	if (err)
		goto exit_journal;

	mockfs_update_super(sb, flex_gd);

	err = mockfs_handle_dirty_super(handle, sb);

exit_journal:
	err2 = mockfs_journal_stop(handle);
	if (!err)
		err = err2;

	if (!err) {
		int gdb_num = group / MOCKFS_DESC_PER_BLOCK(sb);
		int gdb_num_end = ((group + flex_gd->count - 1) /
				   MOCKFS_DESC_PER_BLOCK(sb));
		int meta_bg = mockfs_has_feature_meta_bg(sb);
		sector_t old_gdb = 0;

		update_backups(sb, sbi->s_sbh->b_blocknr, (char *)es,
			       sizeof(struct mockfs_super_block), 0);
		for (; gdb_num <= gdb_num_end; gdb_num++) {
			struct buffer_head *gdb_bh;

			gdb_bh = sbi->s_group_desc[gdb_num];
			if (old_gdb == gdb_bh->b_blocknr)
				continue;
			update_backups(sb, gdb_bh->b_blocknr, gdb_bh->b_data,
				       gdb_bh->b_size, meta_bg);
			old_gdb = gdb_bh->b_blocknr;
		}
	}
exit:
	return err;
}

static int mockfs_setup_next_flex_gd(struct super_block *sb,
				    struct mockfs_new_flex_group_data *flex_gd,
				    mockfs_fsblk_t n_blocks_count,
				    unsigned long flexbg_size)
{
	struct mockfs_super_block *es = MOCKFS_SB(sb)->s_es;
	struct mockfs_new_group_data *group_data = flex_gd->groups;
	mockfs_fsblk_t o_blocks_count;
	mockfs_group_t n_group;
	mockfs_group_t group;
	mockfs_group_t last_group;
	mockfs_grpblk_t last;
	mockfs_grpblk_t blocks_per_group;
	unsigned long i;

	blocks_per_group = MOCKFS_BLOCKS_PER_GROUP(sb);

	o_blocks_count = mockfs_blocks_count(es);

	if (o_blocks_count == n_blocks_count)
		return 0;

	mockfs_get_group_no_and_offset(sb, o_blocks_count, &group, &last);
	BUG_ON(last);
	mockfs_get_group_no_and_offset(sb, n_blocks_count - 1, &n_group, &last);

	last_group = group | (flexbg_size - 1);
	if (last_group > n_group)
		last_group = n_group;

	flex_gd->count = last_group - group + 1;

	for (i = 0; i < flex_gd->count; i++) {
		int overhead;

		group_data[i].group = group + i;
		group_data[i].blocks_count = blocks_per_group;
		overhead = mockfs_group_overhead_blocks(sb, group + i);
		group_data[i].free_blocks_count = blocks_per_group - overhead;
		if (mockfs_has_group_desc_csum(sb)) {
			flex_gd->bg_flags[i] = MOCKFS_BG_BLOCK_UNINIT |
					       MOCKFS_BG_INODE_UNINIT;
			if (!test_opt(sb, INIT_INODE_TABLE))
				flex_gd->bg_flags[i] |= MOCKFS_BG_INODE_ZEROED;
		} else
			flex_gd->bg_flags[i] = MOCKFS_BG_INODE_ZEROED;
	}

	if (last_group == n_group && mockfs_has_group_desc_csum(sb))
		/* We need to initialize block bitmap of last group. */
		flex_gd->bg_flags[i - 1] &= ~MOCKFS_BG_BLOCK_UNINIT;

	if ((last_group == n_group) && (last != blocks_per_group - 1)) {
		group_data[i - 1].blocks_count = last + 1;
		group_data[i - 1].free_blocks_count -= blocks_per_group-
					last - 1;
	}

	return 1;
}

/* Add group descriptor data to an existing or new group descriptor block.
 * Ensure we handle all possible error conditions _before_ we start modifying
 * the filesystem, because we cannot abort the transaction and not have it
 * write the data to disk.
 *
 * If we are on a GDT block boundary, we need to get the reserved GDT block.
 * Otherwise, we may need to add backup GDT blocks for a sparse group.
 *
 * We only need to hold the superblock lock while we are actually adding
 * in the new group's counts to the superblock.  Prior to that we have
 * not really "added" the group at all.  We re-check that we are still
 * adding in the last group in case things have changed since verifying.
 */
int mockfs_group_add(struct super_block *sb, struct mockfs_new_group_data *input)
{
	struct mockfs_new_flex_group_data flex_gd;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_super_block *es = sbi->s_es;
	int reserved_gdb = mockfs_bg_has_super(sb, input->group) ?
		le16_to_cpu(es->s_reserved_gdt_blocks) : 0;
	struct inode *inode = NULL;
	int gdb_off;
	int err;
	__u16 bg_flags = 0;

	gdb_off = input->group % MOCKFS_DESC_PER_BLOCK(sb);

	if (gdb_off == 0 && !mockfs_has_feature_sparse_super(sb)) {
		mockfs_warning(sb, "Can't resize non-sparse filesystem further");
		return -EPERM;
	}

	if (mockfs_blocks_count(es) + input->blocks_count <
	    mockfs_blocks_count(es)) {
		mockfs_warning(sb, "blocks_count overflow");
		return -EINVAL;
	}

	if (le32_to_cpu(es->s_inodes_count) + MOCKFS_INODES_PER_GROUP(sb) <
	    le32_to_cpu(es->s_inodes_count)) {
		mockfs_warning(sb, "inodes_count overflow");
		return -EINVAL;
	}

	if (reserved_gdb || gdb_off == 0) {
		if (mockfs_has_feature_resize_inode(sb) ||
		    !le16_to_cpu(es->s_reserved_gdt_blocks)) {
			mockfs_warning(sb,
				     "No reserved GDT blocks, can't resize");
			return -EPERM;
		}
		inode = mockfs_iget(sb, MOCKFS_RESIZE_INO);
		if (IS_ERR(inode)) {
			mockfs_warning(sb, "Error opening resize inode");
			return PTR_ERR(inode);
		}
	}


	err = verify_group_input(sb, input);
	if (err)
		goto out;

	err = mockfs_alloc_flex_bg_array(sb, input->group + 1);
	if (err)
		goto out;

	err = mockfs_mb_alloc_groupinfo(sb, input->group + 1);
	if (err)
		goto out;

	flex_gd.count = 1;
	flex_gd.groups = input;
	flex_gd.bg_flags = &bg_flags;
	err = mockfs_flex_group_add(sb, inode, &flex_gd);
out:
	iput(inode);
	return err;
} /* mockfs_group_add */

/*
 * extend a group without checking assuming that checking has been done.
 */
static int mockfs_group_extend_no_check(struct super_block *sb,
				      mockfs_fsblk_t o_blocks_count, mockfs_grpblk_t add)
{
	struct mockfs_super_block *es = MOCKFS_SB(sb)->s_es;
	handle_t *handle;
	int err = 0, err2;

	/* We will update the superblock, one block bitmap, and
	 * one group descriptor via mockfs_group_add_blocks().
	 */
	handle = mockfs_journal_start_sb(sb, MOCKFS_HT_RESIZE, 3);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		mockfs_warning(sb, "error %d on journal start", err);
		return err;
	}

	BUFFER_TRACE(MOCKFS_SB(sb)->s_sbh, "get_write_access");
	err = mockfs_journal_get_write_access(handle, MOCKFS_SB(sb)->s_sbh);
	if (err) {
		mockfs_warning(sb, "error %d on journal write access", err);
		goto errout;
	}

	mockfs_blocks_count_set(es, o_blocks_count + add);
	mockfs_free_blocks_count_set(es, mockfs_free_blocks_count(es) + add);
	mockfs_debug("freeing blocks %llu through %llu\n", o_blocks_count,
		   o_blocks_count + add);
	/* We add the blocks to the bitmap and set the group need init bit */
	err = mockfs_group_add_blocks(handle, sb, o_blocks_count, add);
	if (err)
		goto errout;
	mockfs_handle_dirty_super(handle, sb);
	mockfs_debug("freed blocks %llu through %llu\n", o_blocks_count,
		   o_blocks_count + add);
errout:
	err2 = mockfs_journal_stop(handle);
	if (err2 && !err)
		err = err2;

	if (!err) {
		if (test_opt(sb, DEBUG))
			printk(KERN_DEBUG "MOCKFS-fs: extended group to %llu "
			       "blocks\n", mockfs_blocks_count(es));
		update_backups(sb, MOCKFS_SB(sb)->s_sbh->b_blocknr,
			       (char *)es, sizeof(struct mockfs_super_block), 0);
	}
	return err;
}

/*
 * Extend the filesystem to the new number of blocks specified.  This entry
 * point is only used to extend the current filesystem to the end of the last
 * existing group.  It can be accessed via ioctl, or by "remount,resize=<size>"
 * for emergencies (because it has no dependencies on reserved blocks).
 *
 * If we _really_ wanted, we could use default values to call mockfs_group_add()
 * allow the "remount" trick to work for arbitrary resizing, assuming enough
 * GDT blocks are reserved to grow to the desired size.
 */
int mockfs_group_extend(struct super_block *sb, struct mockfs_super_block *es,
		      mockfs_fsblk_t n_blocks_count)
{
	mockfs_fsblk_t o_blocks_count;
	mockfs_grpblk_t last;
	mockfs_grpblk_t add;
	struct buffer_head *bh;
	int err;
	mockfs_group_t group;

	o_blocks_count = mockfs_blocks_count(es);

	if (test_opt(sb, DEBUG))
		mockfs_msg(sb, KERN_DEBUG,
			 "extending last group from %llu to %llu blocks",
			 o_blocks_count, n_blocks_count);

	if (n_blocks_count == 0 || n_blocks_count == o_blocks_count)
		return 0;

	if (n_blocks_count > (sector_t)(~0ULL) >> (sb->s_blocksize_bits - 9)) {
		mockfs_msg(sb, KERN_ERR,
			 "filesystem too large to resize to %llu blocks safely",
			 n_blocks_count);
		if (sizeof(sector_t) < 8)
			mockfs_warning(sb, "CONFIG_LBDAF not enabled");
		return -EINVAL;
	}

	if (n_blocks_count < o_blocks_count) {
		mockfs_warning(sb, "can't shrink FS - resize aborted");
		return -EINVAL;
	}

	/* Handle the remaining blocks in the last group only. */
	mockfs_get_group_no_and_offset(sb, o_blocks_count, &group, &last);

	if (last == 0) {
		mockfs_warning(sb, "need to use ext2online to resize further");
		return -EPERM;
	}

	add = MOCKFS_BLOCKS_PER_GROUP(sb) - last;

	if (o_blocks_count + add < o_blocks_count) {
		mockfs_warning(sb, "blocks_count overflow");
		return -EINVAL;
	}

	if (o_blocks_count + add > n_blocks_count)
		add = n_blocks_count - o_blocks_count;

	if (o_blocks_count + add < n_blocks_count)
		mockfs_warning(sb, "will only finish group (%llu blocks, %u new)",
			     o_blocks_count + add, add);

	/* See if the device is actually as big as what was requested */
	bh = sb_bread(sb, o_blocks_count + add - 1);
	if (!bh) {
		mockfs_warning(sb, "can't read last block, resize aborted");
		return -ENOSPC;
	}
	brelse(bh);

	err = mockfs_group_extend_no_check(sb, o_blocks_count, add);
	return err;
} /* mockfs_group_extend */


static int num_desc_blocks(struct super_block *sb, mockfs_group_t groups)
{
	return (groups + MOCKFS_DESC_PER_BLOCK(sb) - 1) / MOCKFS_DESC_PER_BLOCK(sb);
}

/*
 * Release the resize inode and drop the resize_inode feature if there
 * are no more reserved gdt blocks, and then convert the file system
 * to enable meta_bg
 */
static int mockfs_convert_meta_bg(struct super_block *sb, struct inode *inode)
{
	handle_t *handle;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_super_block *es = sbi->s_es;
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	mockfs_fsblk_t nr;
	int i, ret, err = 0;
	int credits = 1;

	mockfs_msg(sb, KERN_INFO, "Converting file system to meta_bg");
	if (inode) {
		if (es->s_reserved_gdt_blocks) {
			mockfs_error(sb, "Unexpected non-zero "
				   "s_reserved_gdt_blocks");
			return -EPERM;
		}

		/* Do a quick sanity check of the resize inode */
		if (inode->i_blocks != 1 << (inode->i_blkbits - 9))
			goto invalid_resize_inode;
		for (i = 0; i < MOCKFS_N_BLOCKS; i++) {
			if (i == MOCKFS_DIND_BLOCK) {
				if (ei->i_data[i])
					continue;
				else
					goto invalid_resize_inode;
			}
			if (ei->i_data[i])
				goto invalid_resize_inode;
		}
		credits += 3;	/* block bitmap, bg descriptor, resize inode */
	}

	handle = mockfs_journal_start_sb(sb, MOCKFS_HT_RESIZE, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	BUFFER_TRACE(sbi->s_sbh, "get_write_access");
	err = mockfs_journal_get_write_access(handle, sbi->s_sbh);
	if (err)
		goto errout;

	mockfs_clear_feature_resize_inode(sb);
	mockfs_set_feature_meta_bg(sb);
	sbi->s_es->s_first_meta_bg =
		cpu_to_le32(num_desc_blocks(sb, sbi->s_groups_count));

	err = mockfs_handle_dirty_super(handle, sb);
	if (err) {
		mockfs_std_error(sb, err);
		goto errout;
	}

	if (inode) {
		nr = le32_to_cpu(ei->i_data[MOCKFS_DIND_BLOCK]);
		mockfs_free_blocks(handle, inode, NULL, nr, 1,
				 MOCKFS_FREE_BLOCKS_METADATA |
				 MOCKFS_FREE_BLOCKS_FORGET);
		ei->i_data[MOCKFS_DIND_BLOCK] = 0;
		inode->i_blocks = 0;

		err = mockfs_mark_inode_dirty(handle, inode);
		if (err)
			mockfs_std_error(sb, err);
	}

errout:
	ret = mockfs_journal_stop(handle);
	if (!err)
		err = ret;
	return ret;

invalid_resize_inode:
	mockfs_error(sb, "corrupted/inconsistent resize inode");
	return -EINVAL;
}

/*
 * mockfs_resize_fs() resizes a fs to new size specified by @n_blocks_count
 *
 * @sb: super block of the fs to be resized
 * @n_blocks_count: the number of blocks resides in the resized fs
 */
int mockfs_resize_fs(struct super_block *sb, mockfs_fsblk_t n_blocks_count)
{
	struct mockfs_new_flex_group_data *flex_gd = NULL;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_super_block *es = sbi->s_es;
	struct buffer_head *bh;
	struct inode *resize_inode = NULL;
	mockfs_grpblk_t add, offset;
	unsigned long n_desc_blocks;
	unsigned long o_desc_blocks;
	mockfs_group_t o_group;
	mockfs_group_t n_group;
	mockfs_fsblk_t o_blocks_count;
	mockfs_fsblk_t n_blocks_count_retry = 0;
	unsigned long last_update_time = 0;
	int err = 0, flexbg_size = 1 << sbi->s_log_groups_per_flex;
	int meta_bg;

	/* See if the device is actually as big as what was requested */
	bh = sb_bread(sb, n_blocks_count - 1);
	if (!bh) {
		mockfs_warning(sb, "can't read last block, resize aborted");
		return -ENOSPC;
	}
	brelse(bh);

retry:
	o_blocks_count = mockfs_blocks_count(es);

	mockfs_msg(sb, KERN_INFO, "resizing filesystem from %llu "
		 "to %llu blocks", o_blocks_count, n_blocks_count);

	if (n_blocks_count < o_blocks_count) {
		/* On-line shrinking not supported */
		mockfs_warning(sb, "can't shrink FS - resize aborted");
		return -EINVAL;
	}

	if (n_blocks_count == o_blocks_count)
		/* Nothing need to do */
		return 0;

	n_group = mockfs_get_group_number(sb, n_blocks_count - 1);
	if (n_group > (0xFFFFFFFFUL / MOCKFS_INODES_PER_GROUP(sb))) {
		mockfs_warning(sb, "resize would cause inodes_count overflow");
		return -EINVAL;
	}
	mockfs_get_group_no_and_offset(sb, o_blocks_count - 1, &o_group, &offset);

	n_desc_blocks = num_desc_blocks(sb, n_group + 1);
	o_desc_blocks = num_desc_blocks(sb, sbi->s_groups_count);

	meta_bg = mockfs_has_feature_meta_bg(sb);

	if (mockfs_has_feature_resize_inode(sb)) {
		if (meta_bg) {
			mockfs_error(sb, "resize_inode and meta_bg enabled "
				   "simultaneously");
			return -EINVAL;
		}
		if (n_desc_blocks > o_desc_blocks +
		    le16_to_cpu(es->s_reserved_gdt_blocks)) {
			n_blocks_count_retry = n_blocks_count;
			n_desc_blocks = o_desc_blocks +
				le16_to_cpu(es->s_reserved_gdt_blocks);
			n_group = n_desc_blocks * MOCKFS_DESC_PER_BLOCK(sb);
			n_blocks_count = n_group * MOCKFS_BLOCKS_PER_GROUP(sb);
			n_group--; /* set to last group number */
		}

		if (!resize_inode)
			resize_inode = mockfs_iget(sb, MOCKFS_RESIZE_INO);
		if (IS_ERR(resize_inode)) {
			mockfs_warning(sb, "Error opening resize inode");
			return PTR_ERR(resize_inode);
		}
	}

	if ((!resize_inode && !meta_bg) || n_blocks_count == o_blocks_count) {
		err = mockfs_convert_meta_bg(sb, resize_inode);
		if (err)
			goto out;
		if (resize_inode) {
			iput(resize_inode);
			resize_inode = NULL;
		}
		if (n_blocks_count_retry) {
			n_blocks_count = n_blocks_count_retry;
			n_blocks_count_retry = 0;
			goto retry;
		}
	}

	/* extend the last group */
	if (n_group == o_group)
		add = n_blocks_count - o_blocks_count;
	else
		add = MOCKFS_BLOCKS_PER_GROUP(sb) - (offset + 1);
	if (add > 0) {
		err = mockfs_group_extend_no_check(sb, o_blocks_count, add);
		if (err)
			goto out;
	}

	if (mockfs_blocks_count(es) == n_blocks_count)
		goto out;

	err = mockfs_alloc_flex_bg_array(sb, n_group + 1);
	if (err)
		return err;

	err = mockfs_mb_alloc_groupinfo(sb, n_group + 1);
	if (err)
		goto out;

	flex_gd = alloc_flex_gd(flexbg_size);
	if (flex_gd == NULL) {
		err = -ENOMEM;
		goto out;
	}

	/* Add flex groups. Note that a regular group is a
	 * flex group with 1 group.
	 */
	while (mockfs_setup_next_flex_gd(sb, flex_gd, n_blocks_count,
					      flexbg_size)) {
		if (jiffies - last_update_time > HZ * 10) {
			if (last_update_time)
				mockfs_msg(sb, KERN_INFO,
					 "resized to %llu blocks",
					 mockfs_blocks_count(es));
			last_update_time = jiffies;
		}
		if (mockfs_alloc_group_tables(sb, flex_gd, flexbg_size) != 0)
			break;
		err = mockfs_flex_group_add(sb, resize_inode, flex_gd);
		if (unlikely(err))
			break;
	}

	if (!err && n_blocks_count_retry) {
		n_blocks_count = n_blocks_count_retry;
		n_blocks_count_retry = 0;
		free_flex_gd(flex_gd);
		flex_gd = NULL;
		goto retry;
	}

out:
	if (flex_gd)
		free_flex_gd(flex_gd);
	if (resize_inode != NULL)
		iput(resize_inode);
	mockfs_msg(sb, KERN_INFO, "resized filesystem to %llu", n_blocks_count);
	return err;
}
