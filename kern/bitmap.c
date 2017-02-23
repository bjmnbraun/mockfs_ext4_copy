/*
 *  linux/fs/mockfs/bitmap.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/buffer_head.h>
#include "mockfs.h"

unsigned int mockfs_count_free(char *bitmap, unsigned int numchars)
{
	return numchars * BITS_PER_BYTE - memweight(bitmap, numchars);
}

int mockfs_inode_bitmap_csum_verify(struct super_block *sb, mockfs_group_t group,
				  struct mockfs_group_desc *gdp,
				  struct buffer_head *bh, int sz)
{
	__u32 hi;
	__u32 provided, calculated;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);

	if (!mockfs_has_metadata_csum(sb))
		return 1;

	provided = le16_to_cpu(gdp->bg_inode_bitmap_csum_lo);
	calculated = mockfs_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= MOCKFS_BG_INODE_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_inode_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	return provided == calculated;
}

void mockfs_inode_bitmap_csum_set(struct super_block *sb, mockfs_group_t group,
				struct mockfs_group_desc *gdp,
				struct buffer_head *bh, int sz)
{
	__u32 csum;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);

	if (!mockfs_has_metadata_csum(sb))
		return;

	csum = mockfs_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_inode_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= MOCKFS_BG_INODE_BITMAP_CSUM_HI_END)
		gdp->bg_inode_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}

int mockfs_block_bitmap_csum_verify(struct super_block *sb, mockfs_group_t group,
				  struct mockfs_group_desc *gdp,
				  struct buffer_head *bh)
{
	__u32 hi;
	__u32 provided, calculated;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	int sz = MOCKFS_CLUSTERS_PER_GROUP(sb) / 8;

	if (!mockfs_has_metadata_csum(sb))
		return 1;

	provided = le16_to_cpu(gdp->bg_block_bitmap_csum_lo);
	calculated = mockfs_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= MOCKFS_BG_BLOCK_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_block_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	if (provided == calculated)
		return 1;

	return 0;
}

void mockfs_block_bitmap_csum_set(struct super_block *sb, mockfs_group_t group,
				struct mockfs_group_desc *gdp,
				struct buffer_head *bh)
{
	int sz = MOCKFS_CLUSTERS_PER_GROUP(sb) / 8;
	__u32 csum;
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);

	if (!mockfs_has_metadata_csum(sb))
		return;

	csum = mockfs_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_block_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= MOCKFS_BG_BLOCK_BITMAP_CSUM_HI_END)
		gdp->bg_block_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}
