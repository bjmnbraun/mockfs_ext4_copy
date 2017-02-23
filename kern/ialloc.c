/*
 *  linux/fs/mockfs/ialloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  BSD ufs-inspired inode and directory allocation by
 *  Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <asm/byteorder.h>

#include "mockfs.h"
#include "mockfs_jbd2.h"
#include "xattr.h"
#include "acl.h"


/*
 * ialloc.c contains the inodes allocation and deallocation routines
 */

/*
 * The free inodes are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.
 */

/*
 * To avoid calling the atomic setbit hundreds or thousands of times, we only
 * need to use it within a single byte (to ensure we get endianness right).
 * We can use memset for the rest of the bitmap as there are no other users.
 */
void mockfs_mark_bitmap_end(int start_bit, int end_bit, char *bitmap)
{
	int i;

	if (start_bit >= end_bit)
		return;

	mockfs_debug("mark end bits +%d through +%d used\n", start_bit, end_bit);
	for (i = start_bit; i < ((start_bit + 7) & ~7UL); i++)
		mockfs_set_bit(i, bitmap);
	if (i < end_bit)
		memset(bitmap + (i >> 3), 0xff, (end_bit - i) >> 3);
}

/* Initializes an uninitialized inode bitmap */
static int mockfs_init_inode_bitmap(struct super_block *sb,
				       struct buffer_head *bh,
				       mockfs_group_t block_group,
				       struct mockfs_group_desc *gdp)
{
	struct mockfs_group_info *grp;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	J_ASSERT_BH(bh, buffer_locked(bh));

	/* If checksum is bad mark all blocks and inodes use to prevent
	 * allocation, essentially implementing a per-group read-only flag. */
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

	memset(bh->b_data, 0, (MOCKFS_INODES_PER_GROUP(sb) + 7) / 8);
	mockfs_mark_bitmap_end(MOCKFS_INODES_PER_GROUP(sb), sb->s_blocksize * 8,
			bh->b_data);
	mockfs_inode_bitmap_csum_set(sb, block_group, gdp, bh,
				   MOCKFS_INODES_PER_GROUP(sb) / 8);
	mockfs_group_desc_csum_set(sb, block_group, gdp);

	return 0;
}

void mockfs_end_bitmap_read(struct buffer_head *bh, int uptodate)
{
	if (uptodate) {
		set_buffer_uptodate(bh);
		set_bitmap_uptodate(bh);
	}
	unlock_buffer(bh);
	put_bh(bh);
}

static int mockfs_validate_inode_bitmap(struct super_block *sb,
				      struct mockfs_group_desc *desc,
				      mockfs_group_t block_group,
				      struct buffer_head *bh)
{
	mockfs_fsblk_t	blk;
	struct mockfs_group_info *grp = mockfs_get_group_info(sb, block_group);
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);

	if (buffer_verified(bh))
		return 0;
	if (MOCKFS_MB_GRP_IBITMAP_CORRUPT(grp))
		return -EFSCORRUPTED;

	mockfs_lock_group(sb, block_group);
	blk = mockfs_inode_bitmap(sb, desc);
	if (!mockfs_inode_bitmap_csum_verify(sb, block_group, desc, bh,
					   MOCKFS_INODES_PER_GROUP(sb) / 8)) {
		mockfs_unlock_group(sb, block_group);
		mockfs_error(sb, "Corrupt inode bitmap - block_group = %u, "
			   "inode_bitmap = %llu", block_group, blk);
		grp = mockfs_get_group_info(sb, block_group);
		if (!MOCKFS_MB_GRP_IBITMAP_CORRUPT(grp)) {
			int count;
			count = mockfs_free_inodes_count(sb, desc);
			percpu_counter_sub(&sbi->s_freeinodes_counter,
					   count);
		}
		set_bit(MOCKFS_GROUP_INFO_IBITMAP_CORRUPT_BIT, &grp->bb_state);
		return -EFSBADCRC;
	}
	set_buffer_verified(bh);
	mockfs_unlock_group(sb, block_group);
	return 0;
}

/*
 * Read the inode allocation bitmap for a given block_group, reading
 * into the specified slot in the superblock's bitmap cache.
 *
 * Return buffer_head of bitmap on success or NULL.
 */
static struct buffer_head *
mockfs_read_inode_bitmap(struct super_block *sb, mockfs_group_t block_group)
{
	struct mockfs_group_desc *desc;
	struct buffer_head *bh = NULL;
	mockfs_fsblk_t bitmap_blk;
	int err;

	desc = mockfs_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return ERR_PTR(-EFSCORRUPTED);

	bitmap_blk = mockfs_inode_bitmap(sb, desc);
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		mockfs_error(sb, "Cannot read inode bitmap - "
			    "block_group = %u, inode_bitmap = %llu",
			    block_group, bitmap_blk);
		return ERR_PTR(-EIO);
	}
	if (bitmap_uptodate(bh))
		goto verify;

	lock_buffer(bh);
	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		goto verify;
	}

	mockfs_lock_group(sb, block_group);
	if (desc->bg_flags & cpu_to_le16(MOCKFS_BG_INODE_UNINIT)) {
		err = mockfs_init_inode_bitmap(sb, bh, block_group, desc);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		set_buffer_verified(bh);
		mockfs_unlock_group(sb, block_group);
		unlock_buffer(bh);
		if (err) {
			mockfs_error(sb, "Failed to init inode bitmap for group "
				   "%u: %d", block_group, err);
			goto out;
		}
		return bh;
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
	bh->b_end_io = mockfs_end_bitmap_read;
	get_bh(bh);
	submit_bh(READ | REQ_META | REQ_PRIO, bh);
	wait_on_buffer(bh);
	if (!buffer_uptodate(bh)) {
		put_bh(bh);
		mockfs_error(sb, "Cannot read inode bitmap - "
			   "block_group = %u, inode_bitmap = %llu",
			   block_group, bitmap_blk);
		return ERR_PTR(-EIO);
	}

verify:
	err = mockfs_validate_inode_bitmap(sb, desc, block_group, bh);
	if (err)
		goto out;
	return bh;
out:
	put_bh(bh);
	return ERR_PTR(err);
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 *
 * HOWEVER: we must make sure that we get no aliases,
 * which means that we have to call "clear_inode()"
 * _before_ we mark the inode not in use in the inode
 * bitmaps. Otherwise a newly created file might use
 * the same inode number (not actually the same pointer
 * though), and then we'd have two inodes sharing the
 * same inode number and space on the harddisk.
 */
void mockfs_free_inode(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	int is_directory;
	unsigned long ino;
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *bh2;
	mockfs_group_t block_group;
	unsigned long bit;
	struct mockfs_group_desc *gdp;
	struct mockfs_super_block *es;
	struct mockfs_sb_info *sbi;
	int fatal = 0, err, count, cleared;
	struct mockfs_group_info *grp;

	if (!sb) {
		printk(KERN_ERR "MOCKFS-fs: %s:%d: inode on "
		       "nonexistent device\n", __func__, __LINE__);
		return;
	}
	if (atomic_read(&inode->i_count) > 1) {
		mockfs_msg(sb, KERN_ERR, "%s:%d: inode #%lu: count=%d",
			 __func__, __LINE__, inode->i_ino,
			 atomic_read(&inode->i_count));
		return;
	}
	if (inode->i_nlink) {
		mockfs_msg(sb, KERN_ERR, "%s:%d: inode #%lu: nlink=%d\n",
			 __func__, __LINE__, inode->i_ino, inode->i_nlink);
		return;
	}
	sbi = MOCKFS_SB(sb);

	ino = inode->i_ino;
	mockfs_debug("freeing inode %lu\n", ino);

	/*
	 * Note: we must free any quota before locking the superblock,
	 * as writing the quota to disk may need the lock as well.
	 */
	dquot_initialize(inode);
	mockfs_xattr_delete_inode(handle, inode);
	dquot_free_inode(inode);
	dquot_drop(inode);

	is_directory = S_ISDIR(inode->i_mode);

	/* Do this BEFORE marking the inode not in use or returning an error */
	mockfs_clear_inode(inode);

	es = MOCKFS_SB(sb)->s_es;
	if (ino < MOCKFS_FIRST_INO(sb) || ino > le32_to_cpu(es->s_inodes_count)) {
		mockfs_error(sb, "reserved or nonexistent inode %lu", ino);
		goto error_return;
	}
	block_group = (ino - 1) / MOCKFS_INODES_PER_GROUP(sb);
	bit = (ino - 1) % MOCKFS_INODES_PER_GROUP(sb);
	bitmap_bh = mockfs_read_inode_bitmap(sb, block_group);
	/* Don't bother if the inode bitmap is corrupt. */
	grp = mockfs_get_group_info(sb, block_group);
	if (IS_ERR(bitmap_bh)) {
		fatal = PTR_ERR(bitmap_bh);
		bitmap_bh = NULL;
		goto error_return;
	}
	if (unlikely(MOCKFS_MB_GRP_IBITMAP_CORRUPT(grp))) {
		fatal = -EFSCORRUPTED;
		goto error_return;
	}

	BUFFER_TRACE(bitmap_bh, "get_write_access");
	fatal = mockfs_journal_get_write_access(handle, bitmap_bh);
	if (fatal)
		goto error_return;

	fatal = -ESRCH;
	gdp = mockfs_get_group_desc(sb, block_group, &bh2);
	if (gdp) {
		BUFFER_TRACE(bh2, "get_write_access");
		fatal = mockfs_journal_get_write_access(handle, bh2);
	}
	mockfs_lock_group(sb, block_group);
	cleared = mockfs_test_and_clear_bit(bit, bitmap_bh->b_data);
	if (fatal || !cleared) {
		mockfs_unlock_group(sb, block_group);
		goto out;
	}

	count = mockfs_free_inodes_count(sb, gdp) + 1;
	mockfs_free_inodes_set(sb, gdp, count);
	if (is_directory) {
		count = mockfs_used_dirs_count(sb, gdp) - 1;
		mockfs_used_dirs_set(sb, gdp, count);
		percpu_counter_dec(&sbi->s_dirs_counter);
	}
	mockfs_inode_bitmap_csum_set(sb, block_group, gdp, bitmap_bh,
				   MOCKFS_INODES_PER_GROUP(sb) / 8);
	mockfs_group_desc_csum_set(sb, block_group, gdp);
	mockfs_unlock_group(sb, block_group);

	percpu_counter_inc(&sbi->s_freeinodes_counter);
	if (sbi->s_log_groups_per_flex) {
		mockfs_group_t f = mockfs_flex_group(sbi, block_group);

		atomic_inc(&sbi->s_flex_groups[f].free_inodes);
		if (is_directory)
			atomic_dec(&sbi->s_flex_groups[f].used_dirs);
	}
	BUFFER_TRACE(bh2, "call mockfs_handle_dirty_metadata");
	fatal = mockfs_handle_dirty_metadata(handle, NULL, bh2);
out:
	if (cleared) {
		BUFFER_TRACE(bitmap_bh, "call mockfs_handle_dirty_metadata");
		err = mockfs_handle_dirty_metadata(handle, NULL, bitmap_bh);
		if (!fatal)
			fatal = err;
	} else {
		mockfs_error(sb, "bit already cleared for inode %lu", ino);
		if (gdp && !MOCKFS_MB_GRP_IBITMAP_CORRUPT(grp)) {
			int count;
			count = mockfs_free_inodes_count(sb, gdp);
			percpu_counter_sub(&sbi->s_freeinodes_counter,
					   count);
		}
		set_bit(MOCKFS_GROUP_INFO_IBITMAP_CORRUPT_BIT, &grp->bb_state);
	}

error_return:
	brelse(bitmap_bh);
	mockfs_std_error(sb, fatal);
}

struct orlov_stats {
	__u64 free_clusters;
	__u32 free_inodes;
	__u32 used_dirs;
};

/*
 * Helper function for Orlov's allocator; returns critical information
 * for a particular block group or flex_bg.  If flex_size is 1, then g
 * is a block group number; otherwise it is flex_bg number.
 */
static void get_orlov_stats(struct super_block *sb, mockfs_group_t g,
			    int flex_size, struct orlov_stats *stats)
{
	struct mockfs_group_desc *desc;
	struct flex_groups *flex_group = MOCKFS_SB(sb)->s_flex_groups;

	if (flex_size > 1) {
		stats->free_inodes = atomic_read(&flex_group[g].free_inodes);
		stats->free_clusters = atomic64_read(&flex_group[g].free_clusters);
		stats->used_dirs = atomic_read(&flex_group[g].used_dirs);
		return;
	}

	desc = mockfs_get_group_desc(sb, g, NULL);
	if (desc) {
		stats->free_inodes = mockfs_free_inodes_count(sb, desc);
		stats->free_clusters = mockfs_free_group_clusters(sb, desc);
		stats->used_dirs = mockfs_used_dirs_count(sb, desc);
	} else {
		stats->free_inodes = 0;
		stats->free_clusters = 0;
		stats->used_dirs = 0;
	}
}

/*
 * Orlov's allocator for directories.
 *
 * We always try to spread first-level directories.
 *
 * If there are blockgroups with both free inodes and free blocks counts
 * not worse than average we return one with smallest directory count.
 * Otherwise we simply return a random group.
 *
 * For the rest rules look so:
 *
 * It's OK to put directory into a group unless
 * it has too many directories already (max_dirs) or
 * it has too few free inodes left (min_inodes) or
 * it has too few free blocks left (min_blocks) or
 * Parent's group is preferred, if it doesn't satisfy these
 * conditions we search cyclically through the rest. If none
 * of the groups look good we just look for a group with more
 * free inodes than average (starting at parent's group).
 */

static int find_group_orlov(struct super_block *sb, struct inode *parent,
			    mockfs_group_t *group, umode_t mode,
			    const struct qstr *qstr)
{
	mockfs_group_t parent_group = MOCKFS_I(parent)->i_block_group;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	mockfs_group_t real_ngroups = mockfs_get_groups_count(sb);
	int inodes_per_group = MOCKFS_INODES_PER_GROUP(sb);
	unsigned int freei, avefreei, grp_free;
	mockfs_fsblk_t freeb, avefreec;
	unsigned int ndirs;
	int max_dirs, min_inodes;
	mockfs_grpblk_t min_clusters;
	mockfs_group_t i, grp, g, ngroups;
	struct mockfs_group_desc *desc;
	struct orlov_stats stats;
	int flex_size = mockfs_flex_bg_size(sbi);
	struct dx_hash_info hinfo;

	ngroups = real_ngroups;
	if (flex_size > 1) {
		ngroups = (real_ngroups + flex_size - 1) >>
			sbi->s_log_groups_per_flex;
		parent_group >>= sbi->s_log_groups_per_flex;
	}

	freei = percpu_counter_read_positive(&sbi->s_freeinodes_counter);
	avefreei = freei / ngroups;
	freeb = MOCKFS_C2B(sbi,
		percpu_counter_read_positive(&sbi->s_freeclusters_counter));
	avefreec = freeb;
	do_div(avefreec, ngroups);
	ndirs = percpu_counter_read_positive(&sbi->s_dirs_counter);

	if (S_ISDIR(mode) &&
	    ((parent == d_inode(sb->s_root)) ||
	     (mockfs_test_inode_flag(parent, MOCKFS_INODE_TOPDIR)))) {
		int best_ndir = inodes_per_group;
		int ret = -1;

		if (qstr) {
			hinfo.hash_version = DX_HASH_HALF_MD4;
			hinfo.seed = sbi->s_hash_seed;
			mockfsfs_dirhash(qstr->name, qstr->len, &hinfo);
			grp = hinfo.hash;
		} else
			grp = prandom_u32();
		parent_group = (unsigned)grp % ngroups;
		for (i = 0; i < ngroups; i++) {
			g = (parent_group + i) % ngroups;
			get_orlov_stats(sb, g, flex_size, &stats);
			if (!stats.free_inodes)
				continue;
			if (stats.used_dirs >= best_ndir)
				continue;
			if (stats.free_inodes < avefreei)
				continue;
			if (stats.free_clusters < avefreec)
				continue;
			grp = g;
			ret = 0;
			best_ndir = stats.used_dirs;
		}
		if (ret)
			goto fallback;
	found_flex_bg:
		if (flex_size == 1) {
			*group = grp;
			return 0;
		}

		/*
		 * We pack inodes at the beginning of the flexgroup's
		 * inode tables.  Block allocation decisions will do
		 * something similar, although regular files will
		 * start at 2nd block group of the flexgroup.  See
		 * mockfs_ext_find_goal() and mockfs_find_near().
		 */
		grp *= flex_size;
		for (i = 0; i < flex_size; i++) {
			if (grp+i >= real_ngroups)
				break;
			desc = mockfs_get_group_desc(sb, grp+i, NULL);
			if (desc && mockfs_free_inodes_count(sb, desc)) {
				*group = grp+i;
				return 0;
			}
		}
		goto fallback;
	}

	max_dirs = ndirs / ngroups + inodes_per_group / 16;
	min_inodes = avefreei - inodes_per_group*flex_size / 4;
	if (min_inodes < 1)
		min_inodes = 1;
	min_clusters = avefreec - MOCKFS_CLUSTERS_PER_GROUP(sb)*flex_size / 4;

	/*
	 * Start looking in the flex group where we last allocated an
	 * inode for this parent directory
	 */
	if (MOCKFS_I(parent)->i_last_alloc_group != ~0) {
		parent_group = MOCKFS_I(parent)->i_last_alloc_group;
		if (flex_size > 1)
			parent_group >>= sbi->s_log_groups_per_flex;
	}

	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		get_orlov_stats(sb, grp, flex_size, &stats);
		if (stats.used_dirs >= max_dirs)
			continue;
		if (stats.free_inodes < min_inodes)
			continue;
		if (stats.free_clusters < min_clusters)
			continue;
		goto found_flex_bg;
	}

fallback:
	ngroups = real_ngroups;
	avefreei = freei / ngroups;
fallback_retry:
	parent_group = MOCKFS_I(parent)->i_block_group;
	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		desc = mockfs_get_group_desc(sb, grp, NULL);
		if (desc) {
			grp_free = mockfs_free_inodes_count(sb, desc);
			if (grp_free && grp_free >= avefreei) {
				*group = grp;
				return 0;
			}
		}
	}

	if (avefreei) {
		/*
		 * The free-inodes counter is approximate, and for really small
		 * filesystems the above test can fail to find any blockgroups
		 */
		avefreei = 0;
		goto fallback_retry;
	}

	return -1;
}

static int find_group_other(struct super_block *sb, struct inode *parent,
			    mockfs_group_t *group, umode_t mode)
{
	mockfs_group_t parent_group = MOCKFS_I(parent)->i_block_group;
	mockfs_group_t i, last, ngroups = mockfs_get_groups_count(sb);
	struct mockfs_group_desc *desc;
	int flex_size = mockfs_flex_bg_size(MOCKFS_SB(sb));

	/*
	 * Try to place the inode is the same flex group as its
	 * parent.  If we can't find space, use the Orlov algorithm to
	 * find another flex group, and store that information in the
	 * parent directory's inode information so that use that flex
	 * group for future allocations.
	 */
	if (flex_size > 1) {
		int retry = 0;

	try_again:
		parent_group &= ~(flex_size-1);
		last = parent_group + flex_size;
		if (last > ngroups)
			last = ngroups;
		for  (i = parent_group; i < last; i++) {
			desc = mockfs_get_group_desc(sb, i, NULL);
			if (desc && mockfs_free_inodes_count(sb, desc)) {
				*group = i;
				return 0;
			}
		}
		if (!retry && MOCKFS_I(parent)->i_last_alloc_group != ~0) {
			retry = 1;
			parent_group = MOCKFS_I(parent)->i_last_alloc_group;
			goto try_again;
		}
		/*
		 * If this didn't work, use the Orlov search algorithm
		 * to find a new flex group; we pass in the mode to
		 * avoid the topdir algorithms.
		 */
		*group = parent_group + flex_size;
		if (*group > ngroups)
			*group = 0;
		return find_group_orlov(sb, parent, group, mode, NULL);
	}

	/*
	 * Try to place the inode in its parent directory
	 */
	*group = parent_group;
	desc = mockfs_get_group_desc(sb, *group, NULL);
	if (desc && mockfs_free_inodes_count(sb, desc) &&
	    mockfs_free_group_clusters(sb, desc))
		return 0;

	/*
	 * We're going to place this inode in a different blockgroup from its
	 * parent.  We want to cause files in a common directory to all land in
	 * the same blockgroup.  But we want files which are in a different
	 * directory which shares a blockgroup with our parent to land in a
	 * different blockgroup.
	 *
	 * So add our directory's i_ino into the starting point for the hash.
	 */
	*group = (*group + parent->i_ino) % ngroups;

	/*
	 * Use a quadratic hash to find a group with a free inode and some free
	 * blocks.
	 */
	for (i = 1; i < ngroups; i <<= 1) {
		*group += i;
		if (*group >= ngroups)
			*group -= ngroups;
		desc = mockfs_get_group_desc(sb, *group, NULL);
		if (desc && mockfs_free_inodes_count(sb, desc) &&
		    mockfs_free_group_clusters(sb, desc))
			return 0;
	}

	/*
	 * That failed: try linear search for a free inode, even if that group
	 * has no free blocks.
	 */
	*group = parent_group;
	for (i = 0; i < ngroups; i++) {
		if (++*group >= ngroups)
			*group = 0;
		desc = mockfs_get_group_desc(sb, *group, NULL);
		if (desc && mockfs_free_inodes_count(sb, desc))
			return 0;
	}

	return -1;
}

/*
 * In no journal mode, if an inode has recently been deleted, we want
 * to avoid reusing it until we're reasonably sure the inode table
 * block has been written back to disk.  (Yes, these values are
 * somewhat arbitrary...)
 */
#define RECENTCY_MIN	5
#define RECENTCY_DIRTY	30

static int recently_deleted(struct super_block *sb, mockfs_group_t group, int ino)
{
	struct mockfs_group_desc	*gdp;
	struct mockfs_inode	*raw_inode;
	struct buffer_head	*bh;
	unsigned long		dtime, now;
	int	inodes_per_block = MOCKFS_SB(sb)->s_inodes_per_block;
	int	offset, ret = 0, recentcy = RECENTCY_MIN;

	gdp = mockfs_get_group_desc(sb, group, NULL);
	if (unlikely(!gdp))
		return 0;

	bh = sb_getblk(sb, mockfs_inode_table(sb, gdp) +
		       (ino / inodes_per_block));
	if (unlikely(!bh) || !buffer_uptodate(bh))
		/*
		 * If the block is not in the buffer cache, then it
		 * must have been written out.
		 */
		goto out;

	offset = (ino % inodes_per_block) * MOCKFS_INODE_SIZE(sb);
	raw_inode = (struct mockfs_inode *) (bh->b_data + offset);
	dtime = le32_to_cpu(raw_inode->i_dtime);
	now = get_seconds();
	if (buffer_dirty(bh))
		recentcy += RECENTCY_DIRTY;

	if (dtime && (dtime < now) && (now < dtime + recentcy))
		ret = 1;
out:
	brelse(bh);
	return ret;
}

/*
 * There are two policies for allocating an inode.  If the new inode is
 * a directory, then a forward search is made for a block group with both
 * free space and a low directory-to-inode ratio; if that fails, then of
 * the groups with above-average free space, that group with the fewest
 * directories already is chosen.
 *
 * For other inodes, search forward from the parent directory's block
 * group to find a free inode.
 */
struct inode *__mockfs_new_inode(handle_t *handle, struct inode *dir,
			       umode_t mode, const struct qstr *qstr,
			       __u32 goal, uid_t *owner, int handle_type,
			       unsigned int line_no, int nblocks)
{
	struct super_block *sb;
	struct buffer_head *inode_bitmap_bh = NULL;
	struct buffer_head *group_desc_bh;
	mockfs_group_t ngroups, group = 0;
	unsigned long ino = 0;
	struct inode *inode;
	struct mockfs_group_desc *gdp = NULL;
	struct mockfs_inode_info *ei;
	struct mockfs_sb_info *sbi;
	int ret2, err;
	struct inode *ret;
	mockfs_group_t i;
	mockfs_group_t flex_group;
	struct mockfs_group_info *grp;
	int encrypt = 0;

	/* Cannot create files in a deleted directory */
	if (!dir || !dir->i_nlink)
		return ERR_PTR(-EPERM);

	if ((mockfs_encrypted_inode(dir) ||
	     DUMMY_ENCRYPTION_ENABLED(MOCKFS_SB(dir->i_sb))) &&
	    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode))) {
		err = mockfs_get_encryption_info(dir);
		if (err)
			return ERR_PTR(err);
		if (mockfs_encryption_info(dir) == NULL)
			return ERR_PTR(-EPERM);
		if (!handle)
			nblocks += MOCKFS_DATA_TRANS_BLOCKS(dir->i_sb);
		encrypt = 1;
	}

	sb = dir->i_sb;
	ngroups = mockfs_get_groups_count(sb);
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	ei = MOCKFS_I(inode);
	sbi = MOCKFS_SB(sb);

	/*
	 * Initialize owners and quota early so that we don't have to account
	 * for quota initialization worst case in standard inode creating
	 * transaction
	 */
	if (owner) {
		inode->i_mode = mode;
		i_uid_write(inode, owner[0]);
		i_gid_write(inode, owner[1]);
	} else if (test_opt(sb, GRPID)) {
		inode->i_mode = mode;
		inode->i_uid = current_fsuid();
		inode->i_gid = dir->i_gid;
	} else
		inode_init_owner(inode, dir, mode);

	if (MOCKFS_HAS_RO_COMPAT_FEATURE(sb, MOCKFS_FEATURE_RO_COMPAT_PROJECT) &&
	    mockfs_test_inode_flag(dir, MOCKFS_INODE_PROJINHERIT))
		ei->i_projid = MOCKFS_I(dir)->i_projid;
	else
		ei->i_projid = make_kprojid(&init_user_ns, MOCKFS_DEF_PROJID);

	err = dquot_initialize(inode);
	if (err)
		goto out;

	if (!goal)
		goal = sbi->s_inode_goal;

	if (goal && goal <= le32_to_cpu(sbi->s_es->s_inodes_count)) {
		group = (goal - 1) / MOCKFS_INODES_PER_GROUP(sb);
		ino = (goal - 1) % MOCKFS_INODES_PER_GROUP(sb);
		ret2 = 0;
		goto got_group;
	}

	if (S_ISDIR(mode))
		ret2 = find_group_orlov(sb, dir, &group, mode, qstr);
	else
		ret2 = find_group_other(sb, dir, &group, mode);

got_group:
	MOCKFS_I(dir)->i_last_alloc_group = group;
	err = -ENOSPC;
	if (ret2 == -1)
		goto out;

	/*
	 * Normally we will only go through one pass of this loop,
	 * unless we get unlucky and it turns out the group we selected
	 * had its last inode grabbed by someone else.
	 */
	for (i = 0; i < ngroups; i++, ino = 0) {
		err = -EIO;

		gdp = mockfs_get_group_desc(sb, group, &group_desc_bh);
		if (!gdp)
			goto out;

		/*
		 * Check free inodes count before loading bitmap.
		 */
		if (mockfs_free_inodes_count(sb, gdp) == 0) {
			if (++group == ngroups)
				group = 0;
			continue;
		}

		grp = mockfs_get_group_info(sb, group);
		/* Skip groups with already-known suspicious inode tables */
		if (MOCKFS_MB_GRP_IBITMAP_CORRUPT(grp)) {
			if (++group == ngroups)
				group = 0;
			continue;
		}

		brelse(inode_bitmap_bh);
		inode_bitmap_bh = mockfs_read_inode_bitmap(sb, group);
		/* Skip groups with suspicious inode tables */
		if (MOCKFS_MB_GRP_IBITMAP_CORRUPT(grp) ||
		    IS_ERR(inode_bitmap_bh)) {
			inode_bitmap_bh = NULL;
			if (++group == ngroups)
				group = 0;
			continue;
		}

repeat_in_this_group:
		ino = mockfs_find_next_zero_bit((unsigned long *)
					      inode_bitmap_bh->b_data,
					      MOCKFS_INODES_PER_GROUP(sb), ino);
		if (ino >= MOCKFS_INODES_PER_GROUP(sb))
			goto next_group;
		if (group == 0 && (ino+1) < MOCKFS_FIRST_INO(sb)) {
			mockfs_error(sb, "reserved inode found cleared - "
				   "inode=%lu", ino + 1);
			continue;
		}
		if ((MOCKFS_SB(sb)->s_journal == NULL) &&
		    recently_deleted(sb, group, ino)) {
			ino++;
			goto next_inode;
		}
		if (!handle) {
			BUG_ON(nblocks <= 0);
			handle = __mockfs_journal_start_sb(dir->i_sb, line_no,
							 handle_type, nblocks,
							 0);
			if (IS_ERR(handle)) {
				err = PTR_ERR(handle);
				mockfs_std_error(sb, err);
				goto out;
			}
		}
		BUFFER_TRACE(inode_bitmap_bh, "get_write_access");
		err = mockfs_journal_get_write_access(handle, inode_bitmap_bh);
		if (err) {
			mockfs_std_error(sb, err);
			goto out;
		}
		mockfs_lock_group(sb, group);
		ret2 = mockfs_test_and_set_bit(ino, inode_bitmap_bh->b_data);
		mockfs_unlock_group(sb, group);
		ino++;		/* the inode bitmap is zero-based */
		if (!ret2)
			goto got; /* we grabbed the inode! */
next_inode:
		if (ino < MOCKFS_INODES_PER_GROUP(sb))
			goto repeat_in_this_group;
next_group:
		if (++group == ngroups)
			group = 0;
	}
	err = -ENOSPC;
	goto out;

got:
	BUFFER_TRACE(inode_bitmap_bh, "call mockfs_handle_dirty_metadata");
	err = mockfs_handle_dirty_metadata(handle, NULL, inode_bitmap_bh);
	if (err) {
		mockfs_std_error(sb, err);
		goto out;
	}

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	err = mockfs_journal_get_write_access(handle, group_desc_bh);
	if (err) {
		mockfs_std_error(sb, err);
		goto out;
	}

	/* We may have to initialize the block bitmap if it isn't already */
	if (mockfs_has_group_desc_csum(sb) &&
	    gdp->bg_flags & cpu_to_le16(MOCKFS_BG_BLOCK_UNINIT)) {
		struct buffer_head *block_bitmap_bh;

		block_bitmap_bh = mockfs_read_block_bitmap(sb, group);
		if (IS_ERR(block_bitmap_bh)) {
			err = PTR_ERR(block_bitmap_bh);
			goto out;
		}
		BUFFER_TRACE(block_bitmap_bh, "get block bitmap access");
		err = mockfs_journal_get_write_access(handle, block_bitmap_bh);
		if (err) {
			brelse(block_bitmap_bh);
			mockfs_std_error(sb, err);
			goto out;
		}

		BUFFER_TRACE(block_bitmap_bh, "dirty block bitmap");
		err = mockfs_handle_dirty_metadata(handle, NULL, block_bitmap_bh);

		/* recheck and clear flag under lock if we still need to */
		mockfs_lock_group(sb, group);
		if (gdp->bg_flags & cpu_to_le16(MOCKFS_BG_BLOCK_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~MOCKFS_BG_BLOCK_UNINIT);
			mockfs_free_group_clusters_set(sb, gdp,
				mockfs_free_clusters_after_init(sb, group, gdp));
			mockfs_block_bitmap_csum_set(sb, group, gdp,
						   block_bitmap_bh);
			mockfs_group_desc_csum_set(sb, group, gdp);
		}
		mockfs_unlock_group(sb, group);
		brelse(block_bitmap_bh);

		if (err) {
			mockfs_std_error(sb, err);
			goto out;
		}
	}

	/* Update the relevant bg descriptor fields */
	if (mockfs_has_group_desc_csum(sb)) {
		int free;
		struct mockfs_group_info *grp = mockfs_get_group_info(sb, group);

		down_read(&grp->alloc_sem); /* protect vs itable lazyinit */
		mockfs_lock_group(sb, group); /* while we modify the bg desc */
		free = MOCKFS_INODES_PER_GROUP(sb) -
			mockfs_itable_unused_count(sb, gdp);
		if (gdp->bg_flags & cpu_to_le16(MOCKFS_BG_INODE_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~MOCKFS_BG_INODE_UNINIT);
			free = 0;
		}
		/*
		 * Check the relative inode number against the last used
		 * relative inode number in this group. if it is greater
		 * we need to update the bg_itable_unused count
		 */
		if (ino > free)
			mockfs_itable_unused_set(sb, gdp,
					(MOCKFS_INODES_PER_GROUP(sb) - ino));
		up_read(&grp->alloc_sem);
	} else {
		mockfs_lock_group(sb, group);
	}

	mockfs_free_inodes_set(sb, gdp, mockfs_free_inodes_count(sb, gdp) - 1);
	if (S_ISDIR(mode)) {
		mockfs_used_dirs_set(sb, gdp, mockfs_used_dirs_count(sb, gdp) + 1);
		if (sbi->s_log_groups_per_flex) {
			mockfs_group_t f = mockfs_flex_group(sbi, group);

			atomic_inc(&sbi->s_flex_groups[f].used_dirs);
		}
	}
	if (mockfs_has_group_desc_csum(sb)) {
		mockfs_inode_bitmap_csum_set(sb, group, gdp, inode_bitmap_bh,
					   MOCKFS_INODES_PER_GROUP(sb) / 8);
		mockfs_group_desc_csum_set(sb, group, gdp);
	}
	mockfs_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh, "call mockfs_handle_dirty_metadata");
	err = mockfs_handle_dirty_metadata(handle, NULL, group_desc_bh);
	if (err) {
		mockfs_std_error(sb, err);
		goto out;
	}

	percpu_counter_dec(&sbi->s_freeinodes_counter);
	if (S_ISDIR(mode))
		percpu_counter_inc(&sbi->s_dirs_counter);

	if (sbi->s_log_groups_per_flex) {
		flex_group = mockfs_flex_group(sbi, group);
		atomic_dec(&sbi->s_flex_groups[flex_group].free_inodes);
	}

	inode->i_ino = ino + group * MOCKFS_INODES_PER_GROUP(sb);
	/* This is the optimal IO size (for stat), not the fs block size */
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = ei->i_crtime =
						       mockfs_current_time(inode);

	memset(ei->i_data, 0, sizeof(ei->i_data));
	ei->i_dir_start_lookup = 0;
	ei->i_disksize = 0;

	/* Don't inherit extent flag from directory, amongst others. */
	ei->i_flags =
		mockfs_mask_flags(mode, MOCKFS_I(dir)->i_flags & MOCKFS_FL_INHERITED);
	ei->i_file_acl = 0;
	ei->i_dtime = 0;
	ei->i_block_group = group;
	ei->i_last_alloc_group = ~0;

	mockfs_set_inode_flags(inode);
	if (IS_DIRSYNC(inode))
		mockfs_handle_sync(handle);
	if (insert_inode_locked(inode) < 0) {
		/*
		 * Likely a bitmap corruption causing inode to be allocated
		 * twice.
		 */
		err = -EIO;
		mockfs_error(sb, "failed to insert inode %lu: doubly allocated?",
			   inode->i_ino);
		goto out;
	}
	spin_lock(&sbi->s_next_gen_lock);
	inode->i_generation = sbi->s_next_generation++;
	spin_unlock(&sbi->s_next_gen_lock);

	/* Precompute checksum seed for inode metadata */
	if (mockfs_has_metadata_csum(sb)) {
		__u32 csum;
		__le32 inum = cpu_to_le32(inode->i_ino);
		__le32 gen = cpu_to_le32(inode->i_generation);
		csum = mockfs_chksum(sbi, sbi->s_csum_seed, (__u8 *)&inum,
				   sizeof(inum));
		ei->i_csum_seed = mockfs_chksum(sbi, csum, (__u8 *)&gen,
					      sizeof(gen));
	}

	mockfs_clear_state_flags(ei); /* Only relevant on 32-bit archs */
	mockfs_set_inode_state(inode, MOCKFS_STATE_NEW);

	ei->i_extra_isize = MOCKFS_SB(sb)->s_want_extra_isize;
	ei->i_inline_off = 0;
	if (mockfs_has_feature_inline_data(sb))
		mockfs_set_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA);
	ret = inode;
	err = dquot_alloc_inode(inode);
	if (err)
		goto fail_drop;

	err = mockfs_init_acl(handle, inode, dir);
	if (err)
		goto fail_free_drop;

	err = mockfs_init_security(handle, inode, dir, qstr);
	if (err)
		goto fail_free_drop;

	if (mockfs_has_feature_extents(sb)) {
		/* set extent flag only for directory, file and normal symlink*/
		if (S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode)) {
			mockfs_set_inode_flag(inode, MOCKFS_INODE_EXTENTS);
			mockfs_ext_tree_init(handle, inode);
		}
	}

	if (mockfs_handle_valid(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		ei->i_datasync_tid = handle->h_transaction->t_tid;
	}

	if (encrypt) {
		err = mockfs_inherit_context(dir, inode);
		if (err)
			goto fail_free_drop;
	}

	err = mockfs_mark_inode_dirty(handle, inode);
	if (err) {
		mockfs_std_error(sb, err);
		goto fail_free_drop;
	}

	mockfs_debug("allocating inode %lu\n", inode->i_ino);
	brelse(inode_bitmap_bh);
	return ret;

fail_free_drop:
	dquot_free_inode(inode);
fail_drop:
	clear_nlink(inode);
	unlock_new_inode(inode);
out:
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	iput(inode);
	brelse(inode_bitmap_bh);
	return ERR_PTR(err);
}

/* Verify that we are loading a valid orphan from disk */
struct inode *mockfs_orphan_get(struct super_block *sb, unsigned long ino)
{
	unsigned long max_ino = le32_to_cpu(MOCKFS_SB(sb)->s_es->s_inodes_count);
	mockfs_group_t block_group;
	int bit;
	struct buffer_head *bitmap_bh;
	struct inode *inode = NULL;
	long err = -EIO;

	/* Error cases - e2fsck has already cleaned up for us */
	if (ino > max_ino) {
		mockfs_warning(sb, "bad orphan ino %lu!  e2fsck was run?", ino);
		err = -EFSCORRUPTED;
		goto error;
	}

	block_group = (ino - 1) / MOCKFS_INODES_PER_GROUP(sb);
	bit = (ino - 1) % MOCKFS_INODES_PER_GROUP(sb);
	bitmap_bh = mockfs_read_inode_bitmap(sb, block_group);
	if (IS_ERR(bitmap_bh)) {
		err = PTR_ERR(bitmap_bh);
		mockfs_warning(sb, "inode bitmap error %ld for orphan %lu",
			     ino, err);
		goto error;
	}

	/* Having the inode bit set should be a 100% indicator that this
	 * is a valid orphan (no e2fsck run on fs).  Orphans also include
	 * inodes that were being truncated, so we can't check i_nlink==0.
	 */
	if (!mockfs_test_bit(bit, bitmap_bh->b_data))
		goto bad_orphan;

	inode = mockfs_iget(sb, ino);
	if (IS_ERR(inode))
		goto iget_failed;

	/*
	 * If the orphans has i_nlinks > 0 then it should be able to be
	 * truncated, otherwise it won't be removed from the orphan list
	 * during processing and an infinite loop will result.
	 */
	if (inode->i_nlink && !mockfs_can_truncate(inode))
		goto bad_orphan;

	if (NEXT_ORPHAN(inode) > max_ino)
		goto bad_orphan;
	brelse(bitmap_bh);
	return inode;

iget_failed:
	err = PTR_ERR(inode);
	inode = NULL;
bad_orphan:
	mockfs_warning(sb, "bad orphan inode %lu!  e2fsck was run?", ino);
	printk(KERN_WARNING "mockfs_test_bit(bit=%d, block=%llu) = %d\n",
	       bit, (unsigned long long)bitmap_bh->b_blocknr,
	       mockfs_test_bit(bit, bitmap_bh->b_data));
	printk(KERN_WARNING "inode=%p\n", inode);
	if (inode) {
		printk(KERN_WARNING "is_bad_inode(inode)=%d\n",
		       is_bad_inode(inode));
		printk(KERN_WARNING "NEXT_ORPHAN(inode)=%u\n",
		       NEXT_ORPHAN(inode));
		printk(KERN_WARNING "max_ino=%lu\n", max_ino);
		printk(KERN_WARNING "i_nlink=%u\n", inode->i_nlink);
		/* Avoid freeing blocks if we got a bad deleted inode */
		if (inode->i_nlink == 0)
			inode->i_blocks = 0;
		iput(inode);
	}
	brelse(bitmap_bh);
error:
	return ERR_PTR(err);
}

unsigned long mockfs_count_free_inodes(struct super_block *sb)
{
	unsigned long desc_count;
	struct mockfs_group_desc *gdp;
	mockfs_group_t i, ngroups = mockfs_get_groups_count(sb);
#ifdef MOCKFSFS_DEBUG
	struct mockfs_super_block *es;
	unsigned long bitmap_count, x;
	struct buffer_head *bitmap_bh = NULL;

	es = MOCKFS_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;
	for (i = 0; i < ngroups; i++) {
		gdp = mockfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += mockfs_free_inodes_count(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = mockfs_read_inode_bitmap(sb, i);
		if (IS_ERR(bitmap_bh)) {
			bitmap_bh = NULL;
			continue;
		}

		x = mockfs_count_free(bitmap_bh->b_data,
				    MOCKFS_INODES_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %lu: stored = %d, counted = %lu\n",
			(unsigned long) i, mockfs_free_inodes_count(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "mockfs_count_free_inodes: "
	       "stored = %u, computed = %lu, %lu\n",
	       le32_to_cpu(es->s_free_inodes_count), desc_count, bitmap_count);
	return desc_count;
#else
	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = mockfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += mockfs_free_inodes_count(sb, gdp);
		cond_resched();
	}
	return desc_count;
#endif
}

/* Called at mount-time, super-block is locked */
unsigned long mockfs_count_dirs(struct super_block * sb)
{
	unsigned long count = 0;
	mockfs_group_t i, ngroups = mockfs_get_groups_count(sb);

	for (i = 0; i < ngroups; i++) {
		struct mockfs_group_desc *gdp = mockfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		count += mockfs_used_dirs_count(sb, gdp);
	}
	return count;
}

/*
 * Zeroes not yet zeroed inode table - just write zeroes through the whole
 * inode table. Must be called without any spinlock held. The only place
 * where it is called from on active part of filesystem is mockfslazyinit
 * thread, so we do not need any special locks, however we have to prevent
 * inode allocation from the current group, so we take alloc_sem lock, to
 * block mockfs_new_inode() until we are finished.
 */
int mockfs_init_inode_table(struct super_block *sb, mockfs_group_t group,
				 int barrier)
{
	struct mockfs_group_info *grp = mockfs_get_group_info(sb, group);
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_group_desc *gdp = NULL;
	struct buffer_head *group_desc_bh;
	handle_t *handle;
	mockfs_fsblk_t blk;
	int num, ret = 0, used_blks = 0;

	/* This should not happen, but just to be sure check this */
	if (sb->s_flags & MS_RDONLY) {
		ret = 1;
		goto out;
	}

	gdp = mockfs_get_group_desc(sb, group, &group_desc_bh);
	if (!gdp)
		goto out;

	/*
	 * We do not need to lock this, because we are the only one
	 * handling this flag.
	 */
	if (gdp->bg_flags & cpu_to_le16(MOCKFS_BG_INODE_ZEROED))
		goto out;

	handle = mockfs_journal_start_sb(sb, MOCKFS_HT_MISC, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out;
	}

	down_write(&grp->alloc_sem);
	/*
	 * If inode bitmap was already initialized there may be some
	 * used inodes so we need to skip blocks with used inodes in
	 * inode table.
	 */
	if (!(gdp->bg_flags & cpu_to_le16(MOCKFS_BG_INODE_UNINIT)))
		used_blks = DIV_ROUND_UP((MOCKFS_INODES_PER_GROUP(sb) -
			    mockfs_itable_unused_count(sb, gdp)),
			    sbi->s_inodes_per_block);

	if ((used_blks < 0) || (used_blks > sbi->s_itb_per_group)) {
		mockfs_error(sb, "Something is wrong with group %u: "
			   "used itable blocks: %d; "
			   "itable unused count: %u",
			   group, used_blks,
			   mockfs_itable_unused_count(sb, gdp));
		ret = 1;
		goto err_out;
	}

	blk = mockfs_inode_table(sb, gdp) + used_blks;
	num = sbi->s_itb_per_group - used_blks;

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	ret = mockfs_journal_get_write_access(handle,
					    group_desc_bh);
	if (ret)
		goto err_out;

	/*
	 * Skip zeroout if the inode table is full. But we set the ZEROED
	 * flag anyway, because obviously, when it is full it does not need
	 * further zeroing.
	 */
	if (unlikely(num == 0))
		goto skip_zeroout;

	mockfs_debug("going to zero out inode table in group %d\n",
		   group);
	ret = sb_issue_zeroout(sb, blk, num, GFP_NOFS);
	if (ret < 0)
		goto err_out;
	if (barrier)
		blkdev_issue_flush(sb->s_bdev, GFP_NOFS, NULL);

skip_zeroout:
	mockfs_lock_group(sb, group);
	gdp->bg_flags |= cpu_to_le16(MOCKFS_BG_INODE_ZEROED);
	mockfs_group_desc_csum_set(sb, group, gdp);
	mockfs_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh,
		     "call mockfs_handle_dirty_metadata");
	ret = mockfs_handle_dirty_metadata(handle, NULL,
					 group_desc_bh);

err_out:
	up_write(&grp->alloc_sem);
	mockfs_journal_stop(handle);
out:
	return ret;
}
