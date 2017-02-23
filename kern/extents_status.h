/*
 *  fs/mockfs/extents_status.h
 *
 * Written by Yongqiang Yang <xiaoqiangnk@gmail.com>
 * Modified by
 *	Allison Henderson <achender@linux.vnet.ibm.com>
 *	Zheng Liu <wenqing.lz@taobao.com>
 *
 */

#ifndef _MOCKFS_EXTENTS_STATUS_H
#define _MOCKFS_EXTENTS_STATUS_H

/*
 * Turn on ES_DEBUG__ to get lots of info about extent status operations.
 */
#ifdef ES_DEBUG__
#define es_debug(fmt, ...)	printk(fmt, ##__VA_ARGS__)
#else
#define es_debug(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif

/*
 * With ES_AGGRESSIVE_TEST defined, the result of es caching will be
 * checked with old map_block's result.
 */
#define ES_AGGRESSIVE_TEST__

/*
 * These flags live in the high bits of extent_status.es_pblk
 */
enum {
	ES_WRITTEN_B,
	ES_UNWRITTEN_B,
	ES_DELAYED_B,
	ES_HOLE_B,
	ES_REFERENCED_B,
	ES_FLAGS
};

#define ES_SHIFT (sizeof(mockfs_fsblk_t)*8 - ES_FLAGS)
#define ES_MASK (~((mockfs_fsblk_t)0) << ES_SHIFT)

#define EXTENT_STATUS_WRITTEN	(1 << ES_WRITTEN_B)
#define EXTENT_STATUS_UNWRITTEN (1 << ES_UNWRITTEN_B)
#define EXTENT_STATUS_DELAYED	(1 << ES_DELAYED_B)
#define EXTENT_STATUS_HOLE	(1 << ES_HOLE_B)
#define EXTENT_STATUS_REFERENCED	(1 << ES_REFERENCED_B)

#define ES_TYPE_MASK	((mockfs_fsblk_t)(EXTENT_STATUS_WRITTEN | \
			  EXTENT_STATUS_UNWRITTEN | \
			  EXTENT_STATUS_DELAYED | \
			  EXTENT_STATUS_HOLE) << ES_SHIFT)

struct mockfs_sb_info;
struct mockfs_extent;

struct extent_status {
	struct rb_node rb_node;
	mockfs_lblk_t es_lblk;	/* first logical block extent covers */
	mockfs_lblk_t es_len;	/* length of extent in block */
	mockfs_fsblk_t es_pblk;	/* first physical block */
};

struct mockfs_es_tree {
	struct rb_root root;
	struct extent_status *cache_es;	/* recently accessed extent */
};

struct mockfs_es_stats {
	unsigned long es_stats_shrunk;
	unsigned long es_stats_cache_hits;
	unsigned long es_stats_cache_misses;
	u64 es_stats_scan_time;
	u64 es_stats_max_scan_time;
	struct percpu_counter es_stats_all_cnt;
	struct percpu_counter es_stats_shk_cnt;
};

extern int __init mockfs_init_es(void);
extern void mockfs_exit_es(void);
extern void mockfs_es_init_tree(struct mockfs_es_tree *tree);

extern int mockfs_es_insert_extent(struct inode *inode, mockfs_lblk_t lblk,
				 mockfs_lblk_t len, mockfs_fsblk_t pblk,
				 unsigned int status);
extern void mockfs_es_cache_extent(struct inode *inode, mockfs_lblk_t lblk,
				 mockfs_lblk_t len, mockfs_fsblk_t pblk,
				 unsigned int status);
extern int mockfs_es_remove_extent(struct inode *inode, mockfs_lblk_t lblk,
				 mockfs_lblk_t len);
extern void mockfs_es_find_delayed_extent_range(struct inode *inode,
					mockfs_lblk_t lblk, mockfs_lblk_t end,
					struct extent_status *es);
extern int mockfs_es_lookup_extent(struct inode *inode, mockfs_lblk_t lblk,
				 struct extent_status *es);

static inline unsigned int mockfs_es_status(struct extent_status *es)
{
	return es->es_pblk >> ES_SHIFT;
}

static inline unsigned int mockfs_es_type(struct extent_status *es)
{
	return (es->es_pblk & ES_TYPE_MASK) >> ES_SHIFT;
}

static inline int mockfs_es_is_written(struct extent_status *es)
{
	return (mockfs_es_type(es) & EXTENT_STATUS_WRITTEN) != 0;
}

static inline int mockfs_es_is_unwritten(struct extent_status *es)
{
	return (mockfs_es_type(es) & EXTENT_STATUS_UNWRITTEN) != 0;
}

static inline int mockfs_es_is_delayed(struct extent_status *es)
{
	return (mockfs_es_type(es) & EXTENT_STATUS_DELAYED) != 0;
}

static inline int mockfs_es_is_hole(struct extent_status *es)
{
	return (mockfs_es_type(es) & EXTENT_STATUS_HOLE) != 0;
}

static inline void mockfs_es_set_referenced(struct extent_status *es)
{
	es->es_pblk |= ((mockfs_fsblk_t)EXTENT_STATUS_REFERENCED) << ES_SHIFT;
}

static inline void mockfs_es_clear_referenced(struct extent_status *es)
{
	es->es_pblk &= ~(((mockfs_fsblk_t)EXTENT_STATUS_REFERENCED) << ES_SHIFT);
}

static inline int mockfs_es_is_referenced(struct extent_status *es)
{
	return (mockfs_es_status(es) & EXTENT_STATUS_REFERENCED) != 0;
}

static inline mockfs_fsblk_t mockfs_es_pblock(struct extent_status *es)
{
	return es->es_pblk & ~ES_MASK;
}

static inline void mockfs_es_store_pblock(struct extent_status *es,
					mockfs_fsblk_t pb)
{
	mockfs_fsblk_t block;

	block = (pb & ~ES_MASK) | (es->es_pblk & ES_MASK);
	es->es_pblk = block;
}

static inline void mockfs_es_store_status(struct extent_status *es,
					unsigned int status)
{
	es->es_pblk = (((mockfs_fsblk_t)status << ES_SHIFT) & ES_MASK) |
		      (es->es_pblk & ~ES_MASK);
}

static inline void mockfs_es_store_pblock_status(struct extent_status *es,
					       mockfs_fsblk_t pb,
					       unsigned int status)
{
	es->es_pblk = (((mockfs_fsblk_t)status << ES_SHIFT) & ES_MASK) |
		      (pb & ~ES_MASK);
}

extern int mockfs_es_register_shrinker(struct mockfs_sb_info *sbi);
extern void mockfs_es_unregister_shrinker(struct mockfs_sb_info *sbi);

extern int mockfs_seq_es_shrinker_info_show(struct seq_file *seq, void *v);

#endif /* _MOCKFS_EXTENTS_STATUS_H */
