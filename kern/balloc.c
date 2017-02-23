/*
 *  linux/fs/mockfs/balloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  Enhanced block allocation by Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/time.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include "mockfs.h"
#include "mockfs_jbd2.h"
#include "mballoc.h"


static unsigned mockfs_num_base_meta_clusters(struct super_block *sb,
					    mockfs_group_t block_group);
/*
 * balloc.c contains the blocks allocation and deallocation routines
 */

/*
 * Calculate block group number for a given block number
 */
mockfs_group_t mockfs_get_group_number(struct super_block *sb,
				   mockfs_fsblk_t block)
{
	mockfs_group_t group;

	if (test_opt2(sb, STD_GROUP_SIZE))
		group = (block -
			 le32_to_cpu(MOCKFS_SB(sb)->s_es->s_first_data_block)) >>
			(MOCKFS_BLOCK_SIZE_BITS(sb) + MOCKFS_CLUSTER_BITS(sb) + 3);
	else
		mockfs_get_group_no_and_offset(sb, block, &group, NULL);
	return group;
}

/*
 * Calculate the block group number and offset into the block/cluster
 * allocation bitmap, given a block number
 */
void mockfs_get_group_no_and_offset(struct super_block *sb, mockfs_fsblk_t blocknr,
		mockfs_group_t *blockgrpp, mockfs_grpblk_t *offsetp)
{
	struct mockfs_super_block *es = MOCKFS_SB(sb)->s_es;
	mockfs_grpblk_t offset;

	blocknr = blocknr - le32_to_cpu(es->s_first_data_block);
	offset = do_div(blocknr, MOCKFS_BLOCKS_PER_GROUP(sb)) >>
		MOCKFS_SB(sb)->s_cluster_bits;
	if (offsetp)
		*offsetp = offset;
	if (blockgrpp)
		*blockgrpp = blocknr;

}

/*
 * Check whether the 'block' lives within the 'block_group'. Returns 1 if so
 * and 0 otherwise.
 */
static inline int mockfs_block_in_group(struct super_block *sb,
				      mockfs_fsblk_t block,
				      mockfs_group_t block_group)
{
	mockfs_group_t actual_group;

	actual_group = mockfs_get_group_number(sb, block);
	return (actual_group == block_group) ? 1 : 0;
}

/* Return the number of clusters used for file system metadata; this
 * represents the overhead needed by the file system.
 */
static unsigned mockfs_num_overhead_clusters(struct super_block *sb,
					   mockfs_group_t block_group,
					   struct mockfs_group_desc *gdp)
{
	unsigned num_clusters;
	int block_cluster = -1, inode_cluster = -1, itbl_cluster = -1, i, c;
	mockfs_fsblk_t start = mockfs_group_first_block_no(sb, block_group);
	mockfs_fsblk_t itbl_blk;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);

	/* This is the number of clusters used by the superblock,
	 * block group descriptors, and reserved block group
	 * descriptor blocks */
	num_clusters = mockfs_num_base_meta_clusters(sb, block_group);

	/*
	 * For the allocation bitmaps and inode table, we first need
	 * to check to see if the block is in the block group.  If it
	 * is, then check to see if the cluster is already accounted
	 * for in the clusters used for the base metadata cluster, or
	 * if we can increment the base metadata cluster to include
	 * that block.  Otherwise, we will have to track the cluster
	 * used for the allocation bitmap or inode table explicitly.
	 * Normally all of these blocks are contiguous, so the special
	 * case handling shouldn't be necessary except for *very*
	 * unusual file system layouts.
	 */
	if (mockfs_block_in_group(sb, mockfs_block_bitmap(sb, gdp), block_group)) {
		block_cluster = MOCKFS_B2C(sbi,
					 mockfs_block_bitmap(sb, gdp) - start);
		if (block_cluster < num_clusters)
			block_cluster = -1;
		else if (block_cluster == num_clusters) {
			num_clusters++;
			block_cluster = -1;
		}
	}

	if (mockfs_block_in_group(sb, mockfs_inode_bitmap(sb, gdp), block_group)) {
		inode_cluster = MOCKFS_B2C(sbi,
					 mockfs_inode_bitmap(sb, gdp) - start);
		if (inode_cluster < num_clusters)
			inode_cluster = -1;
		else if (inode_cluster == num_clusters) {
			num_clusters++;
			inode_cluster = -1;
		}
	}

	itbl_blk = mockfs_inode_table(sb, gdp);
	for (i = 0; i < sbi->s_itb_per_group; i++) {
		if (mockfs_block_in_group(sb, itbl_blk + i, block_group)) {
			c = MOCKFS_B2C(sbi, itbl_blk + i - start);
			if ((c < num_clusters) || (c == inode_cluster) ||
			    (c == block_cluster) || (c == itbl_cluster))
				continue;
			if (c == num_clusters) {
				num_clusters++;
				continue;
			}
			num_clusters++;
			itbl_cluster = c;
		}
	}

	if (block_cluster != -1)
		num_clusters++;
	if (inode_cluster != -1)
		num_clusters++;

	return num_clusters;
}

static unsigned int num_clusters_in_group(struct super_block *sb,
					  mockfs_group_t block_group)
{
	unsigned int blocks;

	if (block_group == mockfs_get_groups_count(sb) - 1) {
		/*
		 * Even though mke2fs always initializes the first and
		 * last group, just in case some other tool was used,
		 * we need to make sure we calculate the right free
		 * blocks.
		 */
		blocks = mockfs_blocks_count(MOCKFS_SB(sb)->s_es) -
			mockfs_group_first_block_no(sb, block_group);
	} else
		blocks = MOCKFS_BLOCKS_PER_GROUP(sb);
	return MOCKFS_NUM_B2C(MOCKFS_SB(sb), blocks);
}

/* Initializes an uninitialized block bitmap */
static int mockfs_init_block_bitmap(struct super_block *sb,
				   struct buffer_head *bh,
				   mockfs_group_t block_group,
				   struct mockfs_group_desc *gdp)
{
	unsigned int bit, bit_max;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	mockfs_fsblk_t start, tmp;
	int flex_bg = 0;
	struct mockfs_group_info *grp;

	J_ASSERT_BH(bh, buffer_locked(bh));

	/* If checksum is bad mark all blocks used to prevent allocation
	 * essentially implementing a per-group read-only flag. */
	if (!mockfs_group_desc_csum_verify(sb, block_group, gdp)) {
		grp = mockfs_get_group_info(sb, block_group);
		if (!MOCKFS_MB_GRP_BBITMAP_CORRUPT(grp))
			percpu_counter_sub(&sbi->s_freeclusters_counter,
					   grp->bb_free);
		set_bit(MOCKFS_GROUP_INFO_BBITMAP_CORRUPT_BIT, &grp->bb_state);
		if (!MOCKFS_MB_GRP_IBITMAP_CORRUPT(grp)) {
			int count;
			count = mockfs_free_inodes_count(sb, gdp);
			percpu_counter_sub(&sbi->s_freeinodes_counter,
					   count);
		}
		set_bit(MOCKFS_GROUP_INFO_IBITMAP_CORRUPT_BIT, &grp->bb_state);
		return -EFSBADCRC;
	}
	memset(bh->b_data, 0, sb->s_blocksize);

	bit_max = mockfs_num_base_meta_clusters(sb, block_group);
	for (bit = 0; bit < bit_max; bit++)
		mockfs_set_bit(bit, bh->b_data);

	start = mockfs_group_first_block_no(sb, block_group);

	if (mockfs_has_feature_flex_bg(sb))
		flex_bg = 1;

	/* Set bits for block and inode bitmaps, and inode table */
	tmp = mockfs_block_bitmap(sb, gdp);
	if (!flex_bg || mockfs_block_in_group(sb, tmp, block_group))
		mockfs_set_bit(MOCKFS_B2C(sbi, tmp - start), bh->b_data);

	tmp = mockfs_inode_bitmap(sb, gdp);
	if (!flex_bg || mockfs_block_in_group(sb, tmp, block_group))
		mockfs_set_bit(MOCKFS_B2C(sbi, tmp - start), bh->b_data);

	tmp = mockfs_inode_table(sb, gdp);
	for (; tmp < mockfs_inode_table(sb, gdp) +
		     sbi->s_itb_per_group; tmp++) {
		if (!flex_bg || mockfs_block_in_group(sb, tmp, block_group))
			mockfs_set_bit(MOCKFS_B2C(sbi, tmp - start), bh->b_data);
	}

	/*
	 * Also if the number of blocks within the group is less than
	 * the blocksize * 8 ( which is the size of bitmap ), set rest
	 * of the block bitmap to 1
	 */
	mockfs_mark_bitmap_end(num_clusters_in_group(sb, block_group),
			     sb->s_blocksize * 8, bh->b_data);
	mockfs_block_bitmap_csum_set(sb, block_group, gdp, bh);
	mockfs_group_desc_csum_set(sb, block_group, gdp);
	return 0;
}

/* Return the number of free blocks in a block group.  It is used when
 * the block bitmap is uninitialized, so we can't just count the bits
 * in the bitmap. */
unsigned mockfs_free_clusters_after_init(struct super_block *sb,
				       mockfs_group_t block_group,
				       struct mockfs_group_desc *gdp)
{
	return num_clusters_in_group(sb, block_group) - 
		mockfs_num_overhead_clusters(sb, block_group, gdp);
}

/*
 * The free blocks are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.  The descriptors are loaded in memory
 * when a file system is mounted (see mockfs_fill_super).
 */

/**
 * mockfs_get_group_desc() -- load group descriptor from disk
 * @sb:			super block
 * @block_group:	given block group
 * @bh:			pointer to the buffer head to store the block
 *			group descriptor
 */
struct mockfs_group_desc * mockfs_get_group_desc(struct super_block *sb,
					     mockfs_group_t block_group,
					     struct buffer_head **bh)
{
	unsigned int group_desc;
	unsigned int offset;
	mockfs_group_t ngroups = mockfs_get_groups_count(sb);
	struct mockfs_group_desc *desc;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);

	if (block_group >= ngroups) {
		mockfs_error(sb, "block_group >= groups_count - block_group = %u,"
			   " groups_count = %u", block_group, ngroups);

		return NULL;
	}

	group_desc = block_group >> MOCKFS_DESC_PER_BLOCK_BITS(sb);
	offset = block_group & (MOCKFS_DESC_PER_BLOCK(sb) - 1);
	if (!sbi->s_group_desc[group_desc]) {
		mockfs_error(sb, "Group descriptor not loaded - "
			   "block_group = %u, group_desc = %u, desc = %u",
			   block_group, group_desc, offset);
		return NULL;
	}

	desc = (struct mockfs_group_desc *)(
		(__u8 *)sbi->s_group_desc[group_desc]->b_data +
		offset * MOCKFS_DESC_SIZE(sb));
	if (bh)
		*bh = sbi->s_group_desc[group_desc];
	return desc;
}

/*
 * Return the block number which was discovered to be invalid, or 0 if
 * the block bitmap is valid.
 */
static mockfs_fsblk_t mockfs_valid_block_bitmap(struct super_block *sb,
					    struct mockfs_group_desc *desc,
					    mockfs_group_t block_group,
					    struct buffer_head *bh)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	mockfs_grpblk_t offset;
	mockfs_grpblk_t next_zero_bit;
	mockfs_fsblk_t blk;
	mockfs_fsblk_t group_first_block;

	if (mockfs_has_feature_flex_bg(sb)) {
		/* with FLEX_BG, the inode/block bitmaps and itable
		 * blocks may not be in the group at all
		 * so the bitmap validation will be skipped for those groups
		 * or it has to also read the block group where the bitmaps
		 * are located to verify they are set.
		 */
		return 0;
	}
	group_first_block = mockfs_group_first_block_no(sb, block_group);

	/* check whether block bitmap block number is set */
	blk = mockfs_block_bitmap(sb, desc);
	offset = blk - group_first_block;
	if (!mockfs_test_bit(MOCKFS_B2C(sbi, offset), bh->b_data))
		/* bad block bitmap */
		return blk;

	/* check whether the inode bitmap block number is set */
	blk = mockfs_inode_bitmap(sb, desc);
	offset = blk - group_first_block;
	if (!mockfs_test_bit(MOCKFS_B2C(sbi, offset), bh->b_data))
		/* bad block bitmap */
		return blk;

	/* check whether the inode table block number is set */
	blk = mockfs_inode_table(sb, desc);
	offset = blk - group_first_block;
	next_zero_bit = mockfs_find_next_zero_bit(bh->b_data,
			MOCKFS_B2C(sbi, offset + MOCKFS_SB(sb)->s_itb_per_group),
			MOCKFS_B2C(sbi, offset));
	if (next_zero_bit <
	    MOCKFS_B2C(sbi, offset + MOCKFS_SB(sb)->s_itb_per_group))
		/* bad bitmap for inode tables */
		return blk;
	return 0;
}

static int mockfs_validate_block_bitmap(struct super_block *sb,
				      struct mockfs_group_desc *desc,
				      mockfs_group_t block_group,
				      struct buffer_head *bh)
{
	mockfs_fsblk_t	blk;
	struct mockfs_group_info *grp = mockfs_get_group_info(sb, block_group);
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);

	if (buffer_verified(bh))
		return 0;
	if (MOCKFS_MB_GRP_BBITMAP_CORRUPT(grp))
		return -EFSCORRUPTED;

	mockfs_lock_group(sb, block_group);
	if (unlikely(!mockfs_block_bitmap_csum_verify(sb, block_group,
			desc, bh))) {
		mockfs_unlock_group(sb, block_group);
		mockfs_error(sb, "bg %u: bad block bitmap checksum", block_group);
		if (!MOCKFS_MB_GRP_BBITMAP_CORRUPT(grp))
			percpu_counter_sub(&sbi->s_freeclusters_counter,
					   grp->bb_free);
		set_bit(MOCKFS_GROUP_INFO_BBITMAP_CORRUPT_BIT, &grp->bb_state);
		return -EFSBADCRC;
	}
	blk = mockfs_valid_block_bitmap(sb, desc, block_group, bh);
	if (unlikely(blk != 0)) {
		mockfs_unlock_group(sb, block_group);
		mockfs_error(sb, "bg %u: block %llu: invalid block bitmap",
			   block_group, blk);
		if (!MOCKFS_MB_GRP_BBITMAP_CORRUPT(grp))
			percpu_counter_sub(&sbi->s_freeclusters_counter,
					   grp->bb_free);
		set_bit(MOCKFS_GROUP_INFO_BBITMAP_CORRUPT_BIT, &grp->bb_state);
		return -EFSCORRUPTED;
	}
	set_buffer_verified(bh);
	mockfs_unlock_group(sb, block_group);
	return 0;
}

/**
 * mockfs_read_block_bitmap_nowait()
 * @sb:			super block
 * @block_group:	given block group
 *
 * Read the bitmap for a given block_group,and validate the
 * bits for block/inode/inode tables are set in the bitmaps
 *
 * Return buffer_head on success or NULL in case of failure.
 */
struct buffer_head *
mockfs_read_block_bitmap_nowait(struct super_block *sb, mockfs_group_t block_group)
{
	struct mockfs_group_desc *desc;
	struct buffer_head *bh;
	mockfs_fsblk_t bitmap_blk;
	int err;

	desc = mockfs_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return ERR_PTR(-EFSCORRUPTED);
	bitmap_blk = mockfs_block_bitmap(sb, desc);
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		mockfs_error(sb, "Cannot get buffer for block bitmap - "
			   "block_group = %u, block_bitmap = %llu",
			   block_group, bitmap_blk);
		return ERR_PTR(-ENOMEM);
	}

	if (bitmap_uptodate(bh))
		goto verify;

	lock_buffer(bh);
	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		goto verify;
	}
	mockfs_lock_group(sb, block_group);
	if (desc->bg_flags & cpu_to_le16(MOCKFS_BG_BLOCK_UNINIT)) {
		err = mockfs_init_block_bitmap(sb, bh, block_group, desc);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		mockfs_unlock_group(sb, block_group);
		unlock_buffer(bh);
		if (err) {
			mockfs_error(sb, "Failed to init block bitmap for group "
				   "%u: %d", block_group, err);
			goto out;
		}
		goto verify;
	}
	mockfs_unlock_group(sb, block_group);
	if (buffer_uptodate(bh)) {
		/*
		 * if not uninit if bh is uptodate,
		 * bitmap is also uptodate
		 */
		set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		goto verify;
	}
	/*
	 * submit the buffer_head for reading
	 */
	set_buffer_new(bh);
	bh->b_end_io = mockfs_end_bitmap_read;
	get_bh(bh);
	submit_bh(READ | REQ_META | REQ_PRIO, bh);
	return bh;
verify:
	err = mockfs_validate_block_bitmap(sb, desc, block_group, bh);
	if (err)
		goto out;
	return bh;
out:
	put_bh(bh);
	return ERR_PTR(err);
}

/* Returns 0 on success, 1 on error */
int mockfs_wait_block_bitmap(struct super_block *sb, mockfs_group_t block_group,
			   struct buffer_head *bh)
{
	struct mockfs_group_desc *desc;

	if (!buffer_new(bh))
		return 0;
	desc = mockfs_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return -EFSCORRUPTED;
	wait_on_buffer(bh);
	if (!buffer_uptodate(bh)) {
		mockfs_error(sb, "Cannot read block bitmap - "
			   "block_group = %u, block_bitmap = %llu",
			   block_group, (unsigned long long) bh->b_blocknr);
		return -EIO;
	}
	clear_buffer_new(bh);
	/* Panic or remount fs read-only if block bitmap is invalid */
	return mockfs_validate_block_bitmap(sb, desc, block_group, bh);
}

struct buffer_head *
mockfs_read_block_bitmap(struct super_block *sb, mockfs_group_t block_group)
{
	struct buffer_head *bh;
	int err;

	bh = mockfs_read_block_bitmap_nowait(sb, block_group);
	if (IS_ERR(bh))
		return bh;
	err = mockfs_wait_block_bitmap(sb, block_group, bh);
	if (err) {
		put_bh(bh);
		return ERR_PTR(err);
	}
	return bh;
}

/**
 * mockfs_has_free_clusters()
 * @sbi:	in-core super block structure.
 * @nclusters:	number of needed blocks
 * @flags:	flags from mockfs_mb_new_blocks()
 *
 * Check if filesystem has nclusters free & available for allocation.
 * On success return 1, return 0 on failure.
 */
static int mockfs_has_free_clusters(struct mockfs_sb_info *sbi,
				  s64 nclusters, unsigned int flags)
{
	s64 free_clusters, dirty_clusters, rsv, resv_clusters;
	struct percpu_counter *fcc = &sbi->s_freeclusters_counter;
	struct percpu_counter *dcc = &sbi->s_dirtyclusters_counter;

	free_clusters  = percpu_counter_read_positive(fcc);
	dirty_clusters = percpu_counter_read_positive(dcc);
	resv_clusters = atomic64_read(&sbi->s_resv_clusters);

	/*
	 * r_blocks_count should always be multiple of the cluster ratio so
	 * we are safe to do a plane bit shift only.
	 */
	rsv = (mockfs_r_blocks_count(sbi->s_es) >> sbi->s_cluster_bits) +
	      resv_clusters;

	if (free_clusters - (nclusters + rsv + dirty_clusters) <
					MOCKFS_FREECLUSTERS_WATERMARK) {
		free_clusters  = percpu_counter_sum_positive(fcc);
		dirty_clusters = percpu_counter_sum_positive(dcc);
	}
	/* Check whether we have space after accounting for current
	 * dirty clusters & root reserved clusters.
	 */
	if (free_clusters >= (rsv + nclusters + dirty_clusters))
		return 1;

	/* Hm, nope.  Are (enough) root reserved clusters available? */
	if (uid_eq(sbi->s_resuid, current_fsuid()) ||
	    (!gid_eq(sbi->s_resgid, GLOBAL_ROOT_GID) && in_group_p(sbi->s_resgid)) ||
	    capable(CAP_SYS_RESOURCE) ||
	    (flags & MOCKFS_MB_USE_ROOT_BLOCKS)) {

		if (free_clusters >= (nclusters + dirty_clusters +
				      resv_clusters))
			return 1;
	}
	/* No free blocks. Let's see if we can dip into reserved pool */
	if (flags & MOCKFS_MB_USE_RESERVED) {
		if (free_clusters >= (nclusters + dirty_clusters))
			return 1;
	}

	return 0;
}

int mockfs_claim_free_clusters(struct mockfs_sb_info *sbi,
			     s64 nclusters, unsigned int flags)
{
	if (mockfs_has_free_clusters(sbi, nclusters, flags)) {
		percpu_counter_add(&sbi->s_dirtyclusters_counter, nclusters);
		return 0;
	} else
		return -ENOSPC;
}

/**
 * mockfs_should_retry_alloc()
 * @sb:			super block
 * @retries		number of attemps has been made
 *
 * mockfs_should_retry_alloc() is called when ENOSPC is returned, and if
 * it is profitable to retry the operation, this function will wait
 * for the current or committing transaction to complete, and then
 * return TRUE.
 *
 * if the total number of retries exceed three times, return FALSE.
 */
int mockfs_should_retry_alloc(struct super_block *sb, int *retries)
{
	if (!mockfs_has_free_clusters(MOCKFS_SB(sb), 1, 0) ||
	    (*retries)++ > 3 ||
	    !MOCKFS_SB(sb)->s_journal)
		return 0;

	jbd_debug(1, "%s: retrying operation after ENOSPC\n", sb->s_id);

	return jbd2_journal_force_commit_nested(MOCKFS_SB(sb)->s_journal);
}

/*
 * mockfs_new_meta_blocks() -- allocate block for meta data (indexing) blocks
 *
 * @handle:             handle to this transaction
 * @inode:              file inode
 * @goal:               given target block(filesystem wide)
 * @count:		pointer to total number of clusters needed
 * @errp:               error code
 *
 * Return 1st allocated block number on success, *count stores total account
 * error stores in errp pointer
 */
mockfs_fsblk_t mockfs_new_meta_blocks(handle_t *handle, struct inode *inode,
				  mockfs_fsblk_t goal, unsigned int flags,
				  unsigned long *count, int *errp)
{
	struct mockfs_allocation_request ar;
	mockfs_fsblk_t ret;

	memset(&ar, 0, sizeof(ar));
	/* Fill with neighbour allocated blocks */
	ar.inode = inode;
	ar.goal = goal;
	ar.len = count ? *count : 1;
	ar.flags = flags;

	ret = mockfs_mb_new_blocks(handle, &ar, errp);
	if (count)
		*count = ar.len;
	/*
	 * Account for the allocated meta blocks.  We will never
	 * fail EDQUOT for metdata, but we do account for it.
	 */
	if (!(*errp) && (flags & MOCKFS_MB_DELALLOC_RESERVED)) {
		dquot_alloc_block_nofail(inode,
				MOCKFS_C2B(MOCKFS_SB(inode->i_sb), ar.len));
	}
	return ret;
}

/**
 * mockfs_count_free_clusters() -- count filesystem free clusters
 * @sb:		superblock
 *
 * Adds up the number of free clusters from each block group.
 */
mockfs_fsblk_t mockfs_count_free_clusters(struct super_block *sb)
{
	mockfs_fsblk_t desc_count;
	struct mockfs_group_desc *gdp;
	mockfs_group_t i;
	mockfs_group_t ngroups = mockfs_get_groups_count(sb);
	struct mockfs_group_info *grp;
#ifdef MOCKFSFS_DEBUG
	struct mockfs_super_block *es;
	mockfs_fsblk_t bitmap_count;
	unsigned int x;
	struct buffer_head *bitmap_bh = NULL;

	es = MOCKFS_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;

	for (i = 0; i < ngroups; i++) {
		gdp = mockfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		grp = NULL;
		if (MOCKFS_SB(sb)->s_group_info)
			grp = mockfs_get_group_info(sb, i);
		if (!grp || !MOCKFS_MB_GRP_BBITMAP_CORRUPT(grp))
			desc_count += mockfs_free_group_clusters(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = mockfs_read_block_bitmap(sb, i);
		if (IS_ERR(bitmap_bh)) {
			bitmap_bh = NULL;
			continue;
		}

		x = mockfs_count_free(bitmap_bh->b_data,
				    MOCKFS_CLUSTERS_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %u: stored = %d, counted = %u\n",
			i, mockfs_free_group_clusters(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "mockfs_count_free_clusters: stored = %llu"
	       ", computed = %llu, %llu\n",
	       MOCKFS_NUM_B2C(MOCKFS_SB(sb), mockfs_free_blocks_count(es)),
	       desc_count, bitmap_count);
	return bitmap_count;
#else
	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = mockfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		grp = NULL;
		if (MOCKFS_SB(sb)->s_group_info)
			grp = mockfs_get_group_info(sb, i);
		if (!grp || !MOCKFS_MB_GRP_BBITMAP_CORRUPT(grp))
			desc_count += mockfs_free_group_clusters(sb, gdp);
	}

	return desc_count;
#endif
}

static inline int test_root(mockfs_group_t a, int b)
{
	while (1) {
		if (a < b)
			return 0;
		if (a == b)
			return 1;
		if ((a % b) != 0)
			return 0;
		a = a / b;
	}
}

/**
 *	mockfs_bg_has_super - number of blocks used by the superblock in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the superblock (primary or backup)
 *	in this group.  Currently this will be only 0 or 1.
 */
int mockfs_bg_has_super(struct super_block *sb, mockfs_group_t group)
{
	struct mockfs_super_block *es = MOCKFS_SB(sb)->s_es;

	if (group == 0)
		return 1;
	if (mockfs_has_feature_sparse_super2(sb)) {
		if (group == le32_to_cpu(es->s_backup_bgs[0]) ||
		    group == le32_to_cpu(es->s_backup_bgs[1]))
			return 1;
		return 0;
	}
	if ((group <= 1) || !mockfs_has_feature_sparse_super(sb))
		return 1;
	if (!(group & 1))
		return 0;
	if (test_root(group, 3) || (test_root(group, 5)) ||
	    test_root(group, 7))
		return 1;

	return 0;
}

static unsigned long mockfs_bg_num_gdb_meta(struct super_block *sb,
					mockfs_group_t group)
{
	unsigned long metagroup = group / MOCKFS_DESC_PER_BLOCK(sb);
	mockfs_group_t first = metagroup * MOCKFS_DESC_PER_BLOCK(sb);
	mockfs_group_t last = first + MOCKFS_DESC_PER_BLOCK(sb) - 1;

	if (group == first || group == first + 1 || group == last)
		return 1;
	return 0;
}

static unsigned long mockfs_bg_num_gdb_nometa(struct super_block *sb,
					mockfs_group_t group)
{
	if (!mockfs_bg_has_super(sb, group))
		return 0;

	if (mockfs_has_feature_meta_bg(sb))
		return le32_to_cpu(MOCKFS_SB(sb)->s_es->s_first_meta_bg);
	else
		return MOCKFS_SB(sb)->s_gdb_count;
}

/**
 *	mockfs_bg_num_gdb - number of blocks used by the group table in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the group descriptor table
 *	(primary or backup) in this group.  In the future there may be a
 *	different number of descriptor blocks in each group.
 */
unsigned long mockfs_bg_num_gdb(struct super_block *sb, mockfs_group_t group)
{
	unsigned long first_meta_bg =
			le32_to_cpu(MOCKFS_SB(sb)->s_es->s_first_meta_bg);
	unsigned long metagroup = group / MOCKFS_DESC_PER_BLOCK(sb);

	if (!mockfs_has_feature_meta_bg(sb) || metagroup < first_meta_bg)
		return mockfs_bg_num_gdb_nometa(sb, group);

	return mockfs_bg_num_gdb_meta(sb,group);

}

/*
 * This function returns the number of file system metadata clusters at
 * the beginning of a block group, including the reserved gdt blocks.
 */
static unsigned mockfs_num_base_meta_clusters(struct super_block *sb,
				     mockfs_group_t block_group)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	unsigned num;

	/* Check for superblock and gdt backups in this group */
	num = mockfs_bg_has_super(sb, block_group);

	if (!mockfs_has_feature_meta_bg(sb) ||
	    block_group < le32_to_cpu(sbi->s_es->s_first_meta_bg) *
			  sbi->s_desc_per_block) {
		if (num) {
			num += mockfs_bg_num_gdb(sb, block_group);
			num += le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks);
		}
	} else { /* For META_BG_BLOCK_GROUPS */
		num += mockfs_bg_num_gdb(sb, block_group);
	}
	return MOCKFS_NUM_B2C(sbi, num);
}
/**
 *	mockfs_inode_to_goal_block - return a hint for block allocation
 *	@inode: inode for block allocation
 *
 *	Return the ideal location to start allocating blocks for a
 *	newly created inode.
 */
mockfs_fsblk_t mockfs_inode_to_goal_block(struct inode *inode)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	mockfs_group_t block_group;
	mockfs_grpblk_t colour;
	int flex_size = mockfs_flex_bg_size(MOCKFS_SB(inode->i_sb));
	mockfs_fsblk_t bg_start;
	mockfs_fsblk_t last_block;

	block_group = ei->i_block_group;
	if (flex_size >= MOCKFS_FLEX_SIZE_DIR_ALLOC_SCHEME) {
		/*
		 * If there are at least MOCKFS_FLEX_SIZE_DIR_ALLOC_SCHEME
		 * block groups per flexgroup, reserve the first block
		 * group for directories and special files.  Regular
		 * files will start at the second block group.  This
		 * tends to speed up directory access and improves
		 * fsck times.
		 */
		block_group &= ~(flex_size-1);
		if (S_ISREG(inode->i_mode))
			block_group++;
	}
	bg_start = mockfs_group_first_block_no(inode->i_sb, block_group);
	last_block = mockfs_blocks_count(MOCKFS_SB(inode->i_sb)->s_es) - 1;

	/*
	 * If we are doing delayed allocation, we don't need take
	 * colour into account.
	 */
	if (test_opt(inode->i_sb, DELALLOC))
		return bg_start;

	if (bg_start + MOCKFS_BLOCKS_PER_GROUP(inode->i_sb) <= last_block)
		colour = (current->pid % 16) *
			(MOCKFS_BLOCKS_PER_GROUP(inode->i_sb) / 16);
	else
		colour = (current->pid % 16) * ((last_block - bg_start) / 16);
	return bg_start + colour;
}

