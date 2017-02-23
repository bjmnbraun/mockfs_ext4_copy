/*
 *  linux/fs/mockfs/sysfs.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Theodore Ts'o (tytso@mit.edu)
 *
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>

#include "mockfs.h"
#include "mockfs_jbd2.h"

typedef enum {
	attr_noop,
	attr_delayed_allocation_blocks,
	attr_session_write_kbytes,
	attr_lifetime_write_kbytes,
	attr_reserved_clusters,
	attr_inode_readahead,
	attr_trigger_test_error,
	attr_feature,
	attr_pointer_ui,
	attr_pointer_atomic,
} attr_id_t;

typedef enum {
	ptr_explicit,
	ptr_mockfs_sb_info_offset,
	ptr_mockfs_super_block_offset,
} attr_ptr_t;

static const char *proc_dirname = "fs/mockfs";
static struct proc_dir_entry *mockfs_proc_root;

struct mockfs_attr {
	struct attribute attr;
	short attr_id;
	short attr_ptr;
	union {
		int offset;
		void *explicit_ptr;
	} u;
};

static ssize_t session_write_kbytes_show(struct mockfs_attr *a,
					 struct mockfs_sb_info *sbi, char *buf)
{
	struct super_block *sb = sbi->s_buddy_cache->i_sb;

	if (!sb->s_bdev->bd_part)
		return snprintf(buf, PAGE_SIZE, "0\n");
	return snprintf(buf, PAGE_SIZE, "%lu\n",
			(part_stat_read(sb->s_bdev->bd_part, sectors[1]) -
			 sbi->s_sectors_written_start) >> 1);
}

static ssize_t lifetime_write_kbytes_show(struct mockfs_attr *a,
					  struct mockfs_sb_info *sbi, char *buf)
{
	struct super_block *sb = sbi->s_buddy_cache->i_sb;

	if (!sb->s_bdev->bd_part)
		return snprintf(buf, PAGE_SIZE, "0\n");
	return snprintf(buf, PAGE_SIZE, "%llu\n",
			(unsigned long long)(sbi->s_kbytes_written +
			((part_stat_read(sb->s_bdev->bd_part, sectors[1]) -
			  MOCKFS_SB(sb)->s_sectors_written_start) >> 1)));
}

static ssize_t inode_readahead_blks_store(struct mockfs_attr *a,
					  struct mockfs_sb_info *sbi,
					  const char *buf, size_t count)
{
	unsigned long t;
	int ret;

	ret = kstrtoul(skip_spaces(buf), 0, &t);
	if (ret)
		return ret;

	if (t && (!is_power_of_2(t) || t > 0x40000000))
		return -EINVAL;

	sbi->s_inode_readahead_blks = t;
	return count;
}

static ssize_t reserved_clusters_store(struct mockfs_attr *a,
				   struct mockfs_sb_info *sbi,
				   const char *buf, size_t count)
{
	unsigned long long val;
	mockfs_fsblk_t clusters = (mockfs_blocks_count(sbi->s_es) >>
				 sbi->s_cluster_bits);
	int ret;

	ret = kstrtoull(skip_spaces(buf), 0, &val);
	if (!ret || val >= clusters)
		return -EINVAL;

	atomic64_set(&sbi->s_resv_clusters, val);
	return count;
}

static ssize_t trigger_test_error(struct mockfs_attr *a,
				  struct mockfs_sb_info *sbi,
				  const char *buf, size_t count)
{
	int len = count;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (len && buf[len-1] == '\n')
		len--;

	if (len)
		mockfs_error(sbi->s_sb, "%.*s", len, buf);
	return count;
}

#define MOCKFS_ATTR(_name,_mode,_id)					\
static struct mockfs_attr mockfs_attr_##_name = {				\
	.attr = {.name = __stringify(_name), .mode = _mode },		\
	.attr_id = attr_##_id,						\
}

#define MOCKFS_ATTR_FUNC(_name,_mode)  MOCKFS_ATTR(_name,_mode,_name)

#define MOCKFS_ATTR_FEATURE(_name)   MOCKFS_ATTR(_name, 0444, feature)

#define MOCKFS_ATTR_OFFSET(_name,_mode,_id,_struct,_elname)	\
static struct mockfs_attr mockfs_attr_##_name = {			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.attr_id = attr_##_id,					\
	.attr_ptr = ptr_##_struct##_offset,			\
	.u = {							\
		.offset = offsetof(struct _struct, _elname),\
	},							\
}

#define MOCKFS_RO_ATTR_ES_UI(_name,_elname)				\
	MOCKFS_ATTR_OFFSET(_name, 0444, pointer_ui, mockfs_super_block, _elname)

#define MOCKFS_RW_ATTR_SBI_UI(_name,_elname)	\
	MOCKFS_ATTR_OFFSET(_name, 0644, pointer_ui, mockfs_sb_info, _elname)

#define MOCKFS_ATTR_PTR(_name,_mode,_id,_ptr) \
static struct mockfs_attr mockfs_attr_##_name = {			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.attr_id = attr_##_id,					\
	.attr_ptr = ptr_explicit,				\
	.u = {							\
		.explicit_ptr = _ptr,				\
	},							\
}

#define ATTR_LIST(name) &mockfs_attr_##name.attr

MOCKFS_ATTR_FUNC(delayed_allocation_blocks, 0444);
MOCKFS_ATTR_FUNC(session_write_kbytes, 0444);
MOCKFS_ATTR_FUNC(lifetime_write_kbytes, 0444);
MOCKFS_ATTR_FUNC(reserved_clusters, 0644);

MOCKFS_ATTR_OFFSET(inode_readahead_blks, 0644, inode_readahead,
		 mockfs_sb_info, s_inode_readahead_blks);
MOCKFS_RW_ATTR_SBI_UI(inode_goal, s_inode_goal);
MOCKFS_RW_ATTR_SBI_UI(mb_stats, s_mb_stats);
MOCKFS_RW_ATTR_SBI_UI(mb_max_to_scan, s_mb_max_to_scan);
MOCKFS_RW_ATTR_SBI_UI(mb_min_to_scan, s_mb_min_to_scan);
MOCKFS_RW_ATTR_SBI_UI(mb_order2_req, s_mb_order2_reqs);
MOCKFS_RW_ATTR_SBI_UI(mb_stream_req, s_mb_stream_request);
MOCKFS_RW_ATTR_SBI_UI(mb_group_prealloc, s_mb_group_prealloc);
MOCKFS_RW_ATTR_SBI_UI(extent_max_zeroout_kb, s_extent_max_zeroout_kb);
MOCKFS_ATTR(trigger_fs_error, 0200, trigger_test_error);
MOCKFS_RW_ATTR_SBI_UI(err_ratelimit_interval_ms, s_err_ratelimit_state.interval);
MOCKFS_RW_ATTR_SBI_UI(err_ratelimit_burst, s_err_ratelimit_state.burst);
MOCKFS_RW_ATTR_SBI_UI(warning_ratelimit_interval_ms, s_warning_ratelimit_state.interval);
MOCKFS_RW_ATTR_SBI_UI(warning_ratelimit_burst, s_warning_ratelimit_state.burst);
MOCKFS_RW_ATTR_SBI_UI(msg_ratelimit_interval_ms, s_msg_ratelimit_state.interval);
MOCKFS_RW_ATTR_SBI_UI(msg_ratelimit_burst, s_msg_ratelimit_state.burst);
MOCKFS_RO_ATTR_ES_UI(errors_count, s_error_count);
MOCKFS_RO_ATTR_ES_UI(first_error_time, s_first_error_time);
MOCKFS_RO_ATTR_ES_UI(last_error_time, s_last_error_time);

static unsigned int old_bump_val = 128;
MOCKFS_ATTR_PTR(max_writeback_mb_bump, 0444, pointer_ui, &old_bump_val);

static struct attribute *mockfs_attrs[] = {
	ATTR_LIST(delayed_allocation_blocks),
	ATTR_LIST(session_write_kbytes),
	ATTR_LIST(lifetime_write_kbytes),
	ATTR_LIST(reserved_clusters),
	ATTR_LIST(inode_readahead_blks),
	ATTR_LIST(inode_goal),
	ATTR_LIST(mb_stats),
	ATTR_LIST(mb_max_to_scan),
	ATTR_LIST(mb_min_to_scan),
	ATTR_LIST(mb_order2_req),
	ATTR_LIST(mb_stream_req),
	ATTR_LIST(mb_group_prealloc),
	ATTR_LIST(max_writeback_mb_bump),
	ATTR_LIST(extent_max_zeroout_kb),
	ATTR_LIST(trigger_fs_error),
	ATTR_LIST(err_ratelimit_interval_ms),
	ATTR_LIST(err_ratelimit_burst),
	ATTR_LIST(warning_ratelimit_interval_ms),
	ATTR_LIST(warning_ratelimit_burst),
	ATTR_LIST(msg_ratelimit_interval_ms),
	ATTR_LIST(msg_ratelimit_burst),
	ATTR_LIST(errors_count),
	ATTR_LIST(first_error_time),
	ATTR_LIST(last_error_time),
	NULL,
};

/* Features this copy of mockfs supports */
MOCKFS_ATTR_FEATURE(lazy_itable_init);
MOCKFS_ATTR_FEATURE(batched_discard);
MOCKFS_ATTR_FEATURE(meta_bg_resize);
MOCKFS_ATTR_FEATURE(encryption);
MOCKFS_ATTR_FEATURE(metadata_csum_seed);

static struct attribute *mockfs_feat_attrs[] = {
	ATTR_LIST(lazy_itable_init),
	ATTR_LIST(batched_discard),
	ATTR_LIST(meta_bg_resize),
	ATTR_LIST(encryption),
	ATTR_LIST(metadata_csum_seed),
	NULL,
};

static void *calc_ptr(struct mockfs_attr *a, struct mockfs_sb_info *sbi)
{
	switch (a->attr_ptr) {
	case ptr_explicit:
		return a->u.explicit_ptr;
	case ptr_mockfs_sb_info_offset:
		return (void *) (((char *) sbi) + a->u.offset);
	case ptr_mockfs_super_block_offset:
		return (void *) (((char *) sbi->s_es) + a->u.offset);
	}
	return NULL;
}

static ssize_t mockfs_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct mockfs_sb_info *sbi = container_of(kobj, struct mockfs_sb_info,
						s_kobj);
	struct mockfs_attr *a = container_of(attr, struct mockfs_attr, attr);
	void *ptr = calc_ptr(a, sbi);

	switch (a->attr_id) {
	case attr_delayed_allocation_blocks:
		return snprintf(buf, PAGE_SIZE, "%llu\n",
				(s64) MOCKFS_C2B(sbi,
		       percpu_counter_sum(&sbi->s_dirtyclusters_counter)));
	case attr_session_write_kbytes:
		return session_write_kbytes_show(a, sbi, buf);
	case attr_lifetime_write_kbytes:
		return lifetime_write_kbytes_show(a, sbi, buf);
	case attr_reserved_clusters:
		return snprintf(buf, PAGE_SIZE, "%llu\n",
				(unsigned long long)
				atomic64_read(&sbi->s_resv_clusters));
	case attr_inode_readahead:
	case attr_pointer_ui:
		if (!ptr)
			return 0;
		return snprintf(buf, PAGE_SIZE, "%u\n",
				*((unsigned int *) ptr));
	case attr_pointer_atomic:
		if (!ptr)
			return 0;
		return snprintf(buf, PAGE_SIZE, "%d\n",
				atomic_read((atomic_t *) ptr));
	case attr_feature:
		return snprintf(buf, PAGE_SIZE, "supported\n");
	}

	return 0;
}

static ssize_t mockfs_attr_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buf, size_t len)
{
	struct mockfs_sb_info *sbi = container_of(kobj, struct mockfs_sb_info,
						s_kobj);
	struct mockfs_attr *a = container_of(attr, struct mockfs_attr, attr);
	void *ptr = calc_ptr(a, sbi);
	unsigned long t;
	int ret;

	switch (a->attr_id) {
	case attr_reserved_clusters:
		return reserved_clusters_store(a, sbi, buf, len);
	case attr_pointer_ui:
		if (!ptr)
			return 0;
		ret = kstrtoul(skip_spaces(buf), 0, &t);
		if (ret)
			return ret;
		*((unsigned int *) ptr) = t;
		return len;
	case attr_inode_readahead:
		return inode_readahead_blks_store(a, sbi, buf, len);
	case attr_trigger_test_error:
		return trigger_test_error(a, sbi, buf, len);
	}
	return 0;
}

static void mockfs_sb_release(struct kobject *kobj)
{
	struct mockfs_sb_info *sbi = container_of(kobj, struct mockfs_sb_info,
						s_kobj);
	complete(&sbi->s_kobj_unregister);
}

static const struct sysfs_ops mockfs_attr_ops = {
	.show	= mockfs_attr_show,
	.store	= mockfs_attr_store,
};

static struct kobj_type mockfs_sb_ktype = {
	.default_attrs	= mockfs_attrs,
	.sysfs_ops	= &mockfs_attr_ops,
	.release	= mockfs_sb_release,
};

static struct kobj_type mockfs_ktype = {
	.sysfs_ops	= &mockfs_attr_ops,
};

static struct kset mockfs_kset = {
	.kobj   = {.ktype = &mockfs_ktype},
};

static struct kobj_type mockfs_feat_ktype = {
	.default_attrs	= mockfs_feat_attrs,
	.sysfs_ops	= &mockfs_attr_ops,
};

static struct kobject mockfs_feat = {
	.kset	= &mockfs_kset,
};

#define PROC_FILE_SHOW_DEFN(name) \
static int name##_open(struct inode *inode, struct file *file) \
{ \
	return single_open(file, mockfs_seq_##name##_show, PDE_DATA(inode)); \
} \
\
static const struct file_operations mockfs_seq_##name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= name##_open, \
	.read		= seq_read, \
	.llseek		= seq_lseek, \
	.release	= single_release, \
}

#define PROC_FILE_LIST(name) \
	{ __stringify(name), &mockfs_seq_##name##_fops }

PROC_FILE_SHOW_DEFN(es_shrinker_info);
PROC_FILE_SHOW_DEFN(options);

static struct mockfs_proc_files {
	const char *name;
	const struct file_operations *fops;
} proc_files[] = {
	PROC_FILE_LIST(options),
	PROC_FILE_LIST(es_shrinker_info),
	PROC_FILE_LIST(mb_groups),
	{ NULL, NULL },
};

int mockfs_register_sysfs(struct super_block *sb)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_proc_files *p;
	int err;

	sbi->s_kobj.kset = &mockfs_kset;
	init_completion(&sbi->s_kobj_unregister);
	err = kobject_init_and_add(&sbi->s_kobj, &mockfs_sb_ktype, NULL,
				   "%s", sb->s_id);
	if (err)
		return err;

	if (mockfs_proc_root)
		sbi->s_proc = proc_mkdir(sb->s_id, mockfs_proc_root);

	if (sbi->s_proc) {
		for (p = proc_files; p->name; p++)
			proc_create_data(p->name, S_IRUGO, sbi->s_proc,
					 p->fops, sb);
	}
	return 0;
}

void mockfs_unregister_sysfs(struct super_block *sb)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(sb);
	struct mockfs_proc_files *p;

	if (sbi->s_proc) {
		for (p = proc_files; p->name; p++)
			remove_proc_entry(p->name, sbi->s_proc);
		remove_proc_entry(sb->s_id, mockfs_proc_root);
	}
	kobject_del(&sbi->s_kobj);
}

int __init mockfs_init_sysfs(void)
{
	int ret;

	kobject_set_name(&mockfs_kset.kobj, "mockfs");
	mockfs_kset.kobj.parent = fs_kobj;
	ret = kset_register(&mockfs_kset);
	if (ret)
		return ret;

	ret = kobject_init_and_add(&mockfs_feat, &mockfs_feat_ktype,
				   NULL, "features");
	if (ret)
		kset_unregister(&mockfs_kset);
	else
		mockfs_proc_root = proc_mkdir(proc_dirname, NULL);
	return ret;
}

void mockfs_exit_sysfs(void)
{
	kobject_put(&mockfs_feat);
	kset_unregister(&mockfs_kset);
	remove_proc_entry(proc_dirname, NULL);
	mockfs_proc_root = NULL;
}

