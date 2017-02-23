/*
 * Copyright (c) 2003-2006, Cluster File Systems, Inc, info@clusterfs.com
 * Written by Alex Tomas <alex@clusterfs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 */

#ifndef _MOCKFS_EXTENTS
#define _MOCKFS_EXTENTS

#include "mockfs.h"

/*
 * With AGGRESSIVE_TEST defined, the capacity of index/leaf blocks
 * becomes very small, so index split, in-depth growing and
 * other hard changes happen much more often.
 * This is for debug purposes only.
 */
#define AGGRESSIVE_TEST_

/*
 * With EXTENTS_STATS defined, the number of blocks and extents
 * are collected in the truncate path. They'll be shown at
 * umount time.
 */
#define EXTENTS_STATS__

/*
 * If CHECK_BINSEARCH is defined, then the results of the binary search
 * will also be checked by linear search.
 */
#define CHECK_BINSEARCH__

/*
 * If EXT_STATS is defined then stats numbers are collected.
 * These number will be displayed at umount time.
 */
#define EXT_STATS_


/*
 * mockfs_inode has i_block array (60 bytes total).
 * The first 12 bytes store mockfs_extent_header;
 * the remainder stores an array of mockfs_extent.
 * For non-inode extent blocks, mockfs_extent_tail
 * follows the array.
 */

/*
 * This is the extent tail on-disk structure.
 * All other extent structures are 12 bytes long.  It turns out that
 * block_size % 12 >= 4 for at least all powers of 2 greater than 512, which
 * covers all valid mockfs block sizes.  Therefore, this tail structure can be
 * crammed into the end of the block without having to rebalance the tree.
 */
struct mockfs_extent_tail {
	__le32	et_checksum;	/* crc32c(uuid+inum+extent_block) */
};

/*
 * This is the extent on-disk structure.
 * It's used at the bottom of the tree.
 */
struct mockfs_extent {
	__le32	ee_block;	/* first logical block extent covers */
	__le16	ee_len;		/* number of blocks covered by extent */
	__le16	ee_start_hi;	/* high 16 bits of physical block */
	__le32	ee_start_lo;	/* low 32 bits of physical block */
};

/*
 * This is index on-disk structure.
 * It's used at all the levels except the bottom.
 */
struct mockfs_extent_idx {
	__le32	ei_block;	/* index covers logical blocks from 'block' */
	__le32	ei_leaf_lo;	/* pointer to the physical block of the next *
				 * level. leaf or next index could be there */
	__le16	ei_leaf_hi;	/* high 16 bits of physical block */
	__u16	ei_unused;
};

/*
 * Each block (leaves and indexes), even inode-stored has header.
 */
struct mockfs_extent_header {
	__le16	eh_magic;	/* probably will support different formats */
	__le16	eh_entries;	/* number of valid entries */
	__le16	eh_max;		/* capacity of store in entries */
	__le16	eh_depth;	/* has tree real underlying blocks? */
	__le32	eh_generation;	/* generation of the tree */
};

#define MOCKFS_EXT_MAGIC		cpu_to_le16(0xf30a)

#define MOCKFS_EXTENT_TAIL_OFFSET(hdr) \
	(sizeof(struct mockfs_extent_header) + \
	 (sizeof(struct mockfs_extent) * le16_to_cpu((hdr)->eh_max)))

static inline struct mockfs_extent_tail *
find_mockfs_extent_tail(struct mockfs_extent_header *eh)
{
	return (struct mockfs_extent_tail *)(((void *)eh) +
					   MOCKFS_EXTENT_TAIL_OFFSET(eh));
}

/*
 * Array of mockfs_ext_path contains path to some extent.
 * Creation/lookup routines use it for traversal/splitting/etc.
 * Truncate uses it to simulate recursive walking.
 */
struct mockfs_ext_path {
	mockfs_fsblk_t			p_block;
	__u16				p_depth;
	__u16				p_maxdepth;
	struct mockfs_extent		*p_ext;
	struct mockfs_extent_idx		*p_idx;
	struct mockfs_extent_header	*p_hdr;
	struct buffer_head		*p_bh;
};

/*
 * structure for external API
 */

/*
 * EXT_INIT_MAX_LEN is the maximum number of blocks we can have in an
 * initialized extent. This is 2^15 and not (2^16 - 1), since we use the
 * MSB of ee_len field in the extent datastructure to signify if this
 * particular extent is an initialized extent or an unwritten (i.e.
 * preallocated).
 * EXT_UNWRITTEN_MAX_LEN is the maximum number of blocks we can have in an
 * unwritten extent.
 * If ee_len is <= 0x8000, it is an initialized extent. Otherwise, it is an
 * unwritten one. In other words, if MSB of ee_len is set, it is an
 * unwritten extent with only one special scenario when ee_len = 0x8000.
 * In this case we can not have an unwritten extent of zero length and
 * thus we make it as a special case of initialized extent with 0x8000 length.
 * This way we get better extent-to-group alignment for initialized extents.
 * Hence, the maximum number of blocks we can have in an *initialized*
 * extent is 2^15 (32768) and in an *unwritten* extent is 2^15-1 (32767).
 */
#define EXT_INIT_MAX_LEN	(1UL << 15)
#define EXT_UNWRITTEN_MAX_LEN	(EXT_INIT_MAX_LEN - 1)


#define EXT_FIRST_EXTENT(__hdr__) \
	((struct mockfs_extent *) (((char *) (__hdr__)) +		\
				 sizeof(struct mockfs_extent_header)))
#define EXT_FIRST_INDEX(__hdr__) \
	((struct mockfs_extent_idx *) (((char *) (__hdr__)) +	\
				     sizeof(struct mockfs_extent_header)))
#define EXT_HAS_FREE_INDEX(__path__) \
	(le16_to_cpu((__path__)->p_hdr->eh_entries) \
				     < le16_to_cpu((__path__)->p_hdr->eh_max))
#define EXT_LAST_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_LAST_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_MAX_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_max) - 1)
#define EXT_MAX_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_max) - 1)

static inline struct mockfs_extent_header *ext_inode_hdr(struct inode *inode)
{
	return (struct mockfs_extent_header *) MOCKFS_I(inode)->i_data;
}

static inline struct mockfs_extent_header *ext_block_hdr(struct buffer_head *bh)
{
	return (struct mockfs_extent_header *) bh->b_data;
}

static inline unsigned short ext_depth(struct inode *inode)
{
	return le16_to_cpu(ext_inode_hdr(inode)->eh_depth);
}

static inline void mockfs_ext_mark_unwritten(struct mockfs_extent *ext)
{
	/* We can not have an unwritten extent of zero length! */
	BUG_ON((le16_to_cpu(ext->ee_len) & ~EXT_INIT_MAX_LEN) == 0);
	ext->ee_len |= cpu_to_le16(EXT_INIT_MAX_LEN);
}

static inline int mockfs_ext_is_unwritten(struct mockfs_extent *ext)
{
	/* Extent with ee_len of 0x8000 is treated as an initialized extent */
	return (le16_to_cpu(ext->ee_len) > EXT_INIT_MAX_LEN);
}

static inline int mockfs_ext_get_actual_len(struct mockfs_extent *ext)
{
	return (le16_to_cpu(ext->ee_len) <= EXT_INIT_MAX_LEN ?
		le16_to_cpu(ext->ee_len) :
		(le16_to_cpu(ext->ee_len) - EXT_INIT_MAX_LEN));
}

static inline void mockfs_ext_mark_initialized(struct mockfs_extent *ext)
{
	ext->ee_len = cpu_to_le16(mockfs_ext_get_actual_len(ext));
}

/*
 * mockfs_ext_pblock:
 * combine low and high parts of physical block number into mockfs_fsblk_t
 */
static inline mockfs_fsblk_t mockfs_ext_pblock(struct mockfs_extent *ex)
{
	mockfs_fsblk_t block;

	block = le32_to_cpu(ex->ee_start_lo);
	block |= ((mockfs_fsblk_t) le16_to_cpu(ex->ee_start_hi) << 31) << 1;
	return block;
}

/*
 * mockfs_idx_pblock:
 * combine low and high parts of a leaf physical block number into mockfs_fsblk_t
 */
static inline mockfs_fsblk_t mockfs_idx_pblock(struct mockfs_extent_idx *ix)
{
	mockfs_fsblk_t block;

	block = le32_to_cpu(ix->ei_leaf_lo);
	block |= ((mockfs_fsblk_t) le16_to_cpu(ix->ei_leaf_hi) << 31) << 1;
	return block;
}

/*
 * mockfs_ext_store_pblock:
 * stores a large physical block number into an extent struct,
 * breaking it into parts
 */
static inline void mockfs_ext_store_pblock(struct mockfs_extent *ex,
					 mockfs_fsblk_t pb)
{
	ex->ee_start_lo = cpu_to_le32((unsigned long) (pb & 0xffffffff));
	ex->ee_start_hi = cpu_to_le16((unsigned long) ((pb >> 31) >> 1) &
				      0xffff);
}

/*
 * mockfs_idx_store_pblock:
 * stores a large physical block number into an index struct,
 * breaking it into parts
 */
static inline void mockfs_idx_store_pblock(struct mockfs_extent_idx *ix,
					 mockfs_fsblk_t pb)
{
	ix->ei_leaf_lo = cpu_to_le32((unsigned long) (pb & 0xffffffff));
	ix->ei_leaf_hi = cpu_to_le16((unsigned long) ((pb >> 31) >> 1) &
				     0xffff);
}

#define mockfs_ext_dirty(handle, inode, path) \
		__mockfs_ext_dirty(__func__, __LINE__, (handle), (inode), (path))
int __mockfs_ext_dirty(const char *where, unsigned int line, handle_t *handle,
		     struct inode *inode, struct mockfs_ext_path *path);

#endif /* _MOCKFS_EXTENTS */

