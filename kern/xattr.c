/*
 * linux/fs/mockfs/xattr.c
 *
 * Copyright (C) 2001-2003 Andreas Gruenbacher, <agruen@suse.de>
 *
 * Fix by Harrison Xing <harrison@mountainviewdata.com>.
 * Ext4 code with a lot of help from Eric Jarman <ejarman@acm.org>.
 * Extended attributes for symlinks and special files added per
 *  suggestion of Luka Renko <luka.renko@hermes.si>.
 * xattr consolidation Copyright (c) 2004 James Morris <jmorris@redhat.com>,
 *  Red Hat Inc.
 * ea-in-inode support by Alex Tomas <alex@clusterfs.com> aka bzzz
 *  and Andreas Gruenbacher <agruen@suse.de>.
 */

/*
 * Extended attributes are stored directly in inodes (on file systems with
 * inodes bigger than 128 bytes) and on additional disk blocks. The i_file_acl
 * field contains the block number if an inode uses an additional block. All
 * attributes must fit in the inode and one additional block. Blocks that
 * contain the identical set of attributes may be shared among several inodes.
 * Identical blocks are detected by keeping a cache of blocks that have
 * recently been accessed.
 *
 * The attributes in inodes and on blocks have a different header; the entries
 * are stored in the same format:
 *
 *   +------------------+
 *   | header           |
 *   | entry 1          | |
 *   | entry 2          | | growing downwards
 *   | entry 3          | v
 *   | four null bytes  |
 *   | . . .            |
 *   | value 1          | ^
 *   | value 3          | | growing upwards
 *   | value 2          | |
 *   +------------------+
 *
 * The header is followed by multiple entry descriptors. In disk blocks, the
 * entry descriptors are kept sorted. In inodes, they are unsorted. The
 * attribute values are aligned to the end of the block in no specific order.
 *
 * Locking strategy
 * ----------------
 * MOCKFS_I(inode)->i_file_acl is protected by MOCKFS_I(inode)->xattr_sem.
 * EA blocks are only changed if they are exclusive to an inode, so
 * holding xattr_sem also means that nothing but the EA block's reference
 * count can change. Multiple writers to the same block are synchronized
 * by the buffer lock.
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mbcache.h>
#include <linux/quotaops.h>
#include "mockfs_jbd2.h"
#include "mockfs.h"
#include "xattr.h"
#include "acl.h"

#ifdef MOCKFS_XATTR_DEBUG
# define ea_idebug(inode, f...) do { \
		printk(KERN_DEBUG "inode %s:%lu: ", \
			inode->i_sb->s_id, inode->i_ino); \
		printk(f); \
		printk("\n"); \
	} while (0)
# define ea_bdebug(bh, f...) do { \
		printk(KERN_DEBUG "block %pg:%lu: ",		   \
		       bh->b_bdev, (unsigned long) bh->b_blocknr); \
		printk(f); \
		printk("\n"); \
	} while (0)
#else
# define ea_idebug(inode, fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
# define ea_bdebug(bh, fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif

static void mockfs_xattr_cache_insert(struct mb_cache *, struct buffer_head *);
static struct buffer_head *mockfs_xattr_cache_find(struct inode *,
						 struct mockfs_xattr_header *,
						 struct mb_cache_entry **);
static void mockfs_xattr_rehash(struct mockfs_xattr_header *,
			      struct mockfs_xattr_entry *);
static int mockfs_xattr_list(struct dentry *dentry, char *buffer,
			   size_t buffer_size);

static const struct xattr_handler *mockfs_xattr_handler_map[] = {
	[MOCKFS_XATTR_INDEX_USER]		     = &mockfs_xattr_user_handler,
#ifdef CONFIG_MOCKFS_FS_POSIX_ACL
	[MOCKFS_XATTR_INDEX_POSIX_ACL_ACCESS]  = &posix_acl_access_xattr_handler,
	[MOCKFS_XATTR_INDEX_POSIX_ACL_DEFAULT] = &posix_acl_default_xattr_handler,
#endif
	[MOCKFS_XATTR_INDEX_TRUSTED]	     = &mockfs_xattr_trusted_handler,
#ifdef CONFIG_MOCKFS_FS_SECURITY
	[MOCKFS_XATTR_INDEX_SECURITY]	     = &mockfs_xattr_security_handler,
#endif
};

const struct xattr_handler *mockfs_xattr_handlers[] = {
	&mockfs_xattr_user_handler,
	&mockfs_xattr_trusted_handler,
#ifdef CONFIG_MOCKFS_FS_POSIX_ACL
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
#endif
#ifdef CONFIG_MOCKFS_FS_SECURITY
	&mockfs_xattr_security_handler,
#endif
	NULL
};

#define MOCKFS_GET_MB_CACHE(inode)	(((struct mockfs_sb_info *) \
				inode->i_sb->s_fs_info)->s_mb_cache)

static __le32 mockfs_xattr_block_csum(struct inode *inode,
				    sector_t block_nr,
				    struct mockfs_xattr_header *hdr)
{
	struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);
	__u32 csum;
	__le32 save_csum;
	__le64 dsk_block_nr = cpu_to_le64(block_nr);

	save_csum = hdr->h_checksum;
	hdr->h_checksum = 0;
	csum = mockfs_chksum(sbi, sbi->s_csum_seed, (__u8 *)&dsk_block_nr,
			   sizeof(dsk_block_nr));
	csum = mockfs_chksum(sbi, csum, (__u8 *)hdr,
			   MOCKFS_BLOCK_SIZE(inode->i_sb));

	hdr->h_checksum = save_csum;
	return cpu_to_le32(csum);
}

static int mockfs_xattr_block_csum_verify(struct inode *inode,
					sector_t block_nr,
					struct mockfs_xattr_header *hdr)
{
	if (mockfs_has_metadata_csum(inode->i_sb) &&
	    (hdr->h_checksum != mockfs_xattr_block_csum(inode, block_nr, hdr)))
		return 0;
	return 1;
}

static void mockfs_xattr_block_csum_set(struct inode *inode,
				      sector_t block_nr,
				      struct mockfs_xattr_header *hdr)
{
	if (!mockfs_has_metadata_csum(inode->i_sb))
		return;

	hdr->h_checksum = mockfs_xattr_block_csum(inode, block_nr, hdr);
}

static inline int mockfs_handle_dirty_xattr_block(handle_t *handle,
						struct inode *inode,
						struct buffer_head *bh)
{
	mockfs_xattr_block_csum_set(inode, bh->b_blocknr, BHDR(bh));
	return mockfs_handle_dirty_metadata(handle, inode, bh);
}

static inline const struct xattr_handler *
mockfs_xattr_handler(int name_index)
{
	const struct xattr_handler *handler = NULL;

	if (name_index > 0 && name_index < ARRAY_SIZE(mockfs_xattr_handler_map))
		handler = mockfs_xattr_handler_map[name_index];
	return handler;
}

/*
 * Inode operation listxattr()
 *
 * d_inode(dentry)->i_mutex: don't care
 */
ssize_t
mockfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	return mockfs_xattr_list(dentry, buffer, size);
}

static int
mockfs_xattr_check_names(struct mockfs_xattr_entry *entry, void *end,
		       void *value_start)
{
	struct mockfs_xattr_entry *e = entry;

	while (!IS_LAST_ENTRY(e)) {
		struct mockfs_xattr_entry *next = MOCKFS_XATTR_NEXT(e);
		if ((void *)next >= end)
			return -EFSCORRUPTED;
		e = next;
	}

	while (!IS_LAST_ENTRY(entry)) {
		if (entry->e_value_size != 0 &&
		    (value_start + le16_to_cpu(entry->e_value_offs) <
		     (void *)e + sizeof(__u32) ||
		     value_start + le16_to_cpu(entry->e_value_offs) +
		    le32_to_cpu(entry->e_value_size) > end))
			return -EFSCORRUPTED;
		entry = MOCKFS_XATTR_NEXT(entry);
	}

	return 0;
}

static inline int
mockfs_xattr_check_block(struct inode *inode, struct buffer_head *bh)
{
	int error;

	if (buffer_verified(bh))
		return 0;

	if (BHDR(bh)->h_magic != cpu_to_le32(MOCKFS_XATTR_MAGIC) ||
	    BHDR(bh)->h_blocks != cpu_to_le32(1))
		return -EFSCORRUPTED;
	if (!mockfs_xattr_block_csum_verify(inode, bh->b_blocknr, BHDR(bh)))
		return -EFSBADCRC;
	error = mockfs_xattr_check_names(BFIRST(bh), bh->b_data + bh->b_size,
				       bh->b_data);
	if (!error)
		set_buffer_verified(bh);
	return error;
}

static int
__xattr_check_inode(struct inode *inode, struct mockfs_xattr_ibody_header *header,
			 void *end, const char *function, unsigned int line)
{
	struct mockfs_xattr_entry *entry = IFIRST(header);
	int error = -EFSCORRUPTED;

	if (((void *) header >= end) ||
	    (header->h_magic != le32_to_cpu(MOCKFS_XATTR_MAGIC)))
		goto errout;
	error = mockfs_xattr_check_names(entry, end, entry);
errout:
	if (error)
		__mockfs_error_inode(inode, function, line, 0,
				   "corrupted in-inode xattr");
	return error;
}

#define xattr_check_inode(inode, header, end) \
	__xattr_check_inode((inode), (header), (end), __func__, __LINE__)

static inline int
mockfs_xattr_check_entry(struct mockfs_xattr_entry *entry, size_t size)
{
	size_t value_size = le32_to_cpu(entry->e_value_size);

	if (entry->e_value_block != 0 || value_size > size ||
	    le16_to_cpu(entry->e_value_offs) + value_size > size)
		return -EFSCORRUPTED;
	return 0;
}

static int
mockfs_xattr_find_entry(struct mockfs_xattr_entry **pentry, int name_index,
		      const char *name, size_t size, int sorted)
{
	struct mockfs_xattr_entry *entry;
	size_t name_len;
	int cmp = 1;

	if (name == NULL)
		return -EINVAL;
	name_len = strlen(name);
	entry = *pentry;
	for (; !IS_LAST_ENTRY(entry); entry = MOCKFS_XATTR_NEXT(entry)) {
		cmp = name_index - entry->e_name_index;
		if (!cmp)
			cmp = name_len - entry->e_name_len;
		if (!cmp)
			cmp = memcmp(name, entry->e_name, name_len);
		if (cmp <= 0 && (sorted || cmp == 0))
			break;
	}
	*pentry = entry;
	if (!cmp && mockfs_xattr_check_entry(entry, size))
		return -EFSCORRUPTED;
	return cmp ? -ENODATA : 0;
}

static int
mockfs_xattr_block_get(struct inode *inode, int name_index, const char *name,
		     void *buffer, size_t buffer_size)
{
	struct buffer_head *bh = NULL;
	struct mockfs_xattr_entry *entry;
	size_t size;
	int error;
	struct mb_cache *mockfs_mb_cache = MOCKFS_GET_MB_CACHE(inode);

	ea_idebug(inode, "name=%d.%s, buffer=%p, buffer_size=%ld",
		  name_index, name, buffer, (long)buffer_size);

	error = -ENODATA;
	if (!MOCKFS_I(inode)->i_file_acl)
		goto cleanup;
	ea_idebug(inode, "reading block %llu",
		  (unsigned long long)MOCKFS_I(inode)->i_file_acl);
	bh = sb_bread(inode->i_sb, MOCKFS_I(inode)->i_file_acl);
	if (!bh)
		goto cleanup;
	ea_bdebug(bh, "b_count=%d, refcount=%d",
		atomic_read(&(bh->b_count)), le32_to_cpu(BHDR(bh)->h_refcount));
	if (mockfs_xattr_check_block(inode, bh)) {
bad_block:
		MOCKFS_ERROR_INODE(inode, "bad block %llu",
				 MOCKFS_I(inode)->i_file_acl);
		error = -EFSCORRUPTED;
		goto cleanup;
	}
	mockfs_xattr_cache_insert(mockfs_mb_cache, bh);
	entry = BFIRST(bh);
	error = mockfs_xattr_find_entry(&entry, name_index, name, bh->b_size, 1);
	if (error == -EFSCORRUPTED)
		goto bad_block;
	if (error)
		goto cleanup;
	size = le32_to_cpu(entry->e_value_size);
	if (buffer) {
		error = -ERANGE;
		if (size > buffer_size)
			goto cleanup;
		memcpy(buffer, bh->b_data + le16_to_cpu(entry->e_value_offs),
		       size);
	}
	error = size;

cleanup:
	brelse(bh);
	return error;
}

int
mockfs_xattr_ibody_get(struct inode *inode, int name_index, const char *name,
		     void *buffer, size_t buffer_size)
{
	struct mockfs_xattr_ibody_header *header;
	struct mockfs_xattr_entry *entry;
	struct mockfs_inode *raw_inode;
	struct mockfs_iloc iloc;
	size_t size;
	void *end;
	int error;

	if (!mockfs_test_inode_state(inode, MOCKFS_STATE_XATTR))
		return -ENODATA;
	error = mockfs_get_inode_loc(inode, &iloc);
	if (error)
		return error;
	raw_inode = mockfs_raw_inode(&iloc);
	header = IHDR(inode, raw_inode);
	entry = IFIRST(header);
	end = (void *)raw_inode + MOCKFS_SB(inode->i_sb)->s_inode_size;
	error = xattr_check_inode(inode, header, end);
	if (error)
		goto cleanup;
	error = mockfs_xattr_find_entry(&entry, name_index, name,
				      end - (void *)entry, 0);
	if (error)
		goto cleanup;
	size = le32_to_cpu(entry->e_value_size);
	if (buffer) {
		error = -ERANGE;
		if (size > buffer_size)
			goto cleanup;
		memcpy(buffer, (void *)IFIRST(header) +
		       le16_to_cpu(entry->e_value_offs), size);
	}
	error = size;

cleanup:
	brelse(iloc.bh);
	return error;
}

/*
 * mockfs_xattr_get()
 *
 * Copy an extended attribute into the buffer
 * provided, or compute the buffer size required.
 * Buffer is NULL to compute the size of the buffer required.
 *
 * Returns a negative error number on failure, or the number of bytes
 * used / required on success.
 */
int
mockfs_xattr_get(struct inode *inode, int name_index, const char *name,
	       void *buffer, size_t buffer_size)
{
	int error;

	if (strlen(name) > 255)
		return -ERANGE;

	down_read(&MOCKFS_I(inode)->xattr_sem);
	error = mockfs_xattr_ibody_get(inode, name_index, name, buffer,
				     buffer_size);
	if (error == -ENODATA)
		error = mockfs_xattr_block_get(inode, name_index, name, buffer,
					     buffer_size);
	up_read(&MOCKFS_I(inode)->xattr_sem);
	return error;
}

static int
mockfs_xattr_list_entries(struct dentry *dentry, struct mockfs_xattr_entry *entry,
			char *buffer, size_t buffer_size)
{
	size_t rest = buffer_size;

	for (; !IS_LAST_ENTRY(entry); entry = MOCKFS_XATTR_NEXT(entry)) {
		const struct xattr_handler *handler =
			mockfs_xattr_handler(entry->e_name_index);

		if (handler && (!handler->list || handler->list(dentry))) {
			const char *prefix = handler->prefix ?: handler->name;
			size_t prefix_len = strlen(prefix);
			size_t size = prefix_len + entry->e_name_len + 1;

			if (buffer) {
				if (size > rest)
					return -ERANGE;
				memcpy(buffer, prefix, prefix_len);
				buffer += prefix_len;
				memcpy(buffer, entry->e_name, entry->e_name_len);
				buffer += entry->e_name_len;
				*buffer++ = 0;
			}
			rest -= size;
		}
	}
	return buffer_size - rest;  /* total size */
}

static int
mockfs_xattr_block_list(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct inode *inode = d_inode(dentry);
	struct buffer_head *bh = NULL;
	int error;
	struct mb_cache *mockfs_mb_cache = MOCKFS_GET_MB_CACHE(inode);

	ea_idebug(inode, "buffer=%p, buffer_size=%ld",
		  buffer, (long)buffer_size);

	error = 0;
	if (!MOCKFS_I(inode)->i_file_acl)
		goto cleanup;
	ea_idebug(inode, "reading block %llu",
		  (unsigned long long)MOCKFS_I(inode)->i_file_acl);
	bh = sb_bread(inode->i_sb, MOCKFS_I(inode)->i_file_acl);
	error = -EIO;
	if (!bh)
		goto cleanup;
	ea_bdebug(bh, "b_count=%d, refcount=%d",
		atomic_read(&(bh->b_count)), le32_to_cpu(BHDR(bh)->h_refcount));
	if (mockfs_xattr_check_block(inode, bh)) {
		MOCKFS_ERROR_INODE(inode, "bad block %llu",
				 MOCKFS_I(inode)->i_file_acl);
		error = -EFSCORRUPTED;
		goto cleanup;
	}
	mockfs_xattr_cache_insert(mockfs_mb_cache, bh);
	error = mockfs_xattr_list_entries(dentry, BFIRST(bh), buffer, buffer_size);

cleanup:
	brelse(bh);

	return error;
}

static int
mockfs_xattr_ibody_list(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct inode *inode = d_inode(dentry);
	struct mockfs_xattr_ibody_header *header;
	struct mockfs_inode *raw_inode;
	struct mockfs_iloc iloc;
	void *end;
	int error;

	if (!mockfs_test_inode_state(inode, MOCKFS_STATE_XATTR))
		return 0;
	error = mockfs_get_inode_loc(inode, &iloc);
	if (error)
		return error;
	raw_inode = mockfs_raw_inode(&iloc);
	header = IHDR(inode, raw_inode);
	end = (void *)raw_inode + MOCKFS_SB(inode->i_sb)->s_inode_size;
	error = xattr_check_inode(inode, header, end);
	if (error)
		goto cleanup;
	error = mockfs_xattr_list_entries(dentry, IFIRST(header),
					buffer, buffer_size);

cleanup:
	brelse(iloc.bh);
	return error;
}

/*
 * mockfs_xattr_list()
 *
 * Copy a list of attribute names into the buffer
 * provided, or compute the buffer size required.
 * Buffer is NULL to compute the size of the buffer required.
 *
 * Returns a negative error number on failure, or the number of bytes
 * used / required on success.
 */
static int
mockfs_xattr_list(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int ret, ret2;

	down_read(&MOCKFS_I(d_inode(dentry))->xattr_sem);
	ret = ret2 = mockfs_xattr_ibody_list(dentry, buffer, buffer_size);
	if (ret < 0)
		goto errout;
	if (buffer) {
		buffer += ret;
		buffer_size -= ret;
	}
	ret = mockfs_xattr_block_list(dentry, buffer, buffer_size);
	if (ret < 0)
		goto errout;
	ret += ret2;
errout:
	up_read(&MOCKFS_I(d_inode(dentry))->xattr_sem);
	return ret;
}

/*
 * If the MOCKFS_FEATURE_COMPAT_EXT_ATTR feature of this file system is
 * not set, set it.
 */
static void mockfs_xattr_update_super_block(handle_t *handle,
					  struct super_block *sb)
{
	if (mockfs_has_feature_xattr(sb))
		return;

	BUFFER_TRACE(MOCKFS_SB(sb)->s_sbh, "get_write_access");
	if (mockfs_journal_get_write_access(handle, MOCKFS_SB(sb)->s_sbh) == 0) {
		mockfs_set_feature_xattr(sb);
		mockfs_handle_dirty_super(handle, sb);
	}
}

/*
 * Release the xattr block BH: If the reference count is > 1, decrement it;
 * otherwise free the block.
 */
static void
mockfs_xattr_release_block(handle_t *handle, struct inode *inode,
			 struct buffer_head *bh)
{
	struct mb_cache *mockfs_mb_cache = MOCKFS_GET_MB_CACHE(inode);
	u32 hash, ref;
	int error = 0;

	BUFFER_TRACE(bh, "get_write_access");
	error = mockfs_journal_get_write_access(handle, bh);
	if (error)
		goto out;

	lock_buffer(bh);
	hash = le32_to_cpu(BHDR(bh)->h_hash);
	ref = le32_to_cpu(BHDR(bh)->h_refcount);
	if (ref == 1) {
		ea_bdebug(bh, "refcount now=0; freeing");
		/*
		 * This must happen under buffer lock for
		 * mockfs_xattr_block_set() to reliably detect freed block
		 */
		mb_cache_entry_delete_block(mockfs_mb_cache, hash, bh->b_blocknr);
		get_bh(bh);
		unlock_buffer(bh);
		mockfs_free_blocks(handle, inode, bh, 0, 1,
				 MOCKFS_FREE_BLOCKS_METADATA |
				 MOCKFS_FREE_BLOCKS_FORGET);
	} else {
		ref--;
		BHDR(bh)->h_refcount = cpu_to_le32(ref);
		if (ref == MOCKFS_XATTR_REFCOUNT_MAX - 1) {
			struct mb_cache_entry *ce;

			ce = mb_cache_entry_get(mockfs_mb_cache, hash,
						bh->b_blocknr);
			if (ce) {
				ce->e_reusable = 1;
				mb_cache_entry_put(mockfs_mb_cache, ce);
			}
		}

		/*
		 * Beware of this ugliness: Releasing of xattr block references
		 * from different inodes can race and so we have to protect
		 * from a race where someone else frees the block (and releases
		 * its journal_head) before we are done dirtying the buffer. In
		 * nojournal mode this race is harmless and we actually cannot
		 * call mockfs_handle_dirty_xattr_block() with locked buffer as
		 * that function can call sync_dirty_buffer() so for that case
		 * we handle the dirtying after unlocking the buffer.
		 */
		if (mockfs_handle_valid(handle))
			error = mockfs_handle_dirty_xattr_block(handle, inode,
							      bh);
		unlock_buffer(bh);
		if (!mockfs_handle_valid(handle))
			error = mockfs_handle_dirty_xattr_block(handle, inode,
							      bh);
		if (IS_SYNC(inode))
			mockfs_handle_sync(handle);
		dquot_free_block(inode, MOCKFS_C2B(MOCKFS_SB(inode->i_sb), 1));
		ea_bdebug(bh, "refcount now=%d; releasing",
			  le32_to_cpu(BHDR(bh)->h_refcount));
	}
out:
	mockfs_std_error(inode->i_sb, error);
	return;
}

/*
 * Find the available free space for EAs. This also returns the total number of
 * bytes used by EA entries.
 */
static size_t mockfs_xattr_free_space(struct mockfs_xattr_entry *last,
				    size_t *min_offs, void *base, int *total)
{
	for (; !IS_LAST_ENTRY(last); last = MOCKFS_XATTR_NEXT(last)) {
		if (!last->e_value_block && last->e_value_size) {
			size_t offs = le16_to_cpu(last->e_value_offs);
			if (offs < *min_offs)
				*min_offs = offs;
		}
		if (total)
			*total += MOCKFS_XATTR_LEN(last->e_name_len);
	}
	return (*min_offs - ((void *)last - base) - sizeof(__u32));
}

static int
mockfs_xattr_set_entry(struct mockfs_xattr_info *i, struct mockfs_xattr_search *s)
{
	struct mockfs_xattr_entry *last;
	size_t free, min_offs = s->end - s->base, name_len = strlen(i->name);

	/* Compute min_offs and last. */
	last = s->first;
	for (; !IS_LAST_ENTRY(last); last = MOCKFS_XATTR_NEXT(last)) {
		if (!last->e_value_block && last->e_value_size) {
			size_t offs = le16_to_cpu(last->e_value_offs);
			if (offs < min_offs)
				min_offs = offs;
		}
	}
	free = min_offs - ((void *)last - s->base) - sizeof(__u32);
	if (!s->not_found) {
		if (!s->here->e_value_block && s->here->e_value_size) {
			size_t size = le32_to_cpu(s->here->e_value_size);
			free += MOCKFS_XATTR_SIZE(size);
		}
		free += MOCKFS_XATTR_LEN(name_len);
	}
	if (i->value) {
		if (free < MOCKFS_XATTR_LEN(name_len) +
			   MOCKFS_XATTR_SIZE(i->value_len))
			return -ENOSPC;
	}

	if (i->value && s->not_found) {
		/* Insert the new name. */
		size_t size = MOCKFS_XATTR_LEN(name_len);
		size_t rest = (void *)last - (void *)s->here + sizeof(__u32);
		memmove((void *)s->here + size, s->here, rest);
		memset(s->here, 0, size);
		s->here->e_name_index = i->name_index;
		s->here->e_name_len = name_len;
		memcpy(s->here->e_name, i->name, name_len);
	} else {
		if (!s->here->e_value_block && s->here->e_value_size) {
			void *first_val = s->base + min_offs;
			size_t offs = le16_to_cpu(s->here->e_value_offs);
			void *val = s->base + offs;
			size_t size = MOCKFS_XATTR_SIZE(
				le32_to_cpu(s->here->e_value_size));

			if (i->value && size == MOCKFS_XATTR_SIZE(i->value_len)) {
				/* The old and the new value have the same
				   size. Just replace. */
				s->here->e_value_size =
					cpu_to_le32(i->value_len);
				if (i->value == MOCKFS_ZERO_XATTR_VALUE) {
					memset(val, 0, size);
				} else {
					/* Clear pad bytes first. */
					memset(val + size - MOCKFS_XATTR_PAD, 0,
					       MOCKFS_XATTR_PAD);
					memcpy(val, i->value, i->value_len);
				}
				return 0;
			}

			/* Remove the old value. */
			memmove(first_val + size, first_val, val - first_val);
			memset(first_val, 0, size);
			s->here->e_value_size = 0;
			s->here->e_value_offs = 0;
			min_offs += size;

			/* Adjust all value offsets. */
			last = s->first;
			while (!IS_LAST_ENTRY(last)) {
				size_t o = le16_to_cpu(last->e_value_offs);
				if (!last->e_value_block &&
				    last->e_value_size && o < offs)
					last->e_value_offs =
						cpu_to_le16(o + size);
				last = MOCKFS_XATTR_NEXT(last);
			}
		}
		if (!i->value) {
			/* Remove the old name. */
			size_t size = MOCKFS_XATTR_LEN(name_len);
			last = ENTRY((void *)last - size);
			memmove(s->here, (void *)s->here + size,
				(void *)last - (void *)s->here + sizeof(__u32));
			memset(last, 0, size);
		}
	}

	if (i->value) {
		/* Insert the new value. */
		s->here->e_value_size = cpu_to_le32(i->value_len);
		if (i->value_len) {
			size_t size = MOCKFS_XATTR_SIZE(i->value_len);
			void *val = s->base + min_offs - size;
			s->here->e_value_offs = cpu_to_le16(min_offs - size);
			if (i->value == MOCKFS_ZERO_XATTR_VALUE) {
				memset(val, 0, size);
			} else {
				/* Clear the pad bytes first. */
				memset(val + size - MOCKFS_XATTR_PAD, 0,
				       MOCKFS_XATTR_PAD);
				memcpy(val, i->value, i->value_len);
			}
		}
	}
	return 0;
}

struct mockfs_xattr_block_find {
	struct mockfs_xattr_search s;
	struct buffer_head *bh;
};

static int
mockfs_xattr_block_find(struct inode *inode, struct mockfs_xattr_info *i,
		      struct mockfs_xattr_block_find *bs)
{
	struct super_block *sb = inode->i_sb;
	int error;

	ea_idebug(inode, "name=%d.%s, value=%p, value_len=%ld",
		  i->name_index, i->name, i->value, (long)i->value_len);

	if (MOCKFS_I(inode)->i_file_acl) {
		/* The inode already has an extended attribute block. */
		bs->bh = sb_bread(sb, MOCKFS_I(inode)->i_file_acl);
		error = -EIO;
		if (!bs->bh)
			goto cleanup;
		ea_bdebug(bs->bh, "b_count=%d, refcount=%d",
			atomic_read(&(bs->bh->b_count)),
			le32_to_cpu(BHDR(bs->bh)->h_refcount));
		if (mockfs_xattr_check_block(inode, bs->bh)) {
			MOCKFS_ERROR_INODE(inode, "bad block %llu",
					 MOCKFS_I(inode)->i_file_acl);
			error = -EFSCORRUPTED;
			goto cleanup;
		}
		/* Find the named attribute. */
		bs->s.base = BHDR(bs->bh);
		bs->s.first = BFIRST(bs->bh);
		bs->s.end = bs->bh->b_data + bs->bh->b_size;
		bs->s.here = bs->s.first;
		error = mockfs_xattr_find_entry(&bs->s.here, i->name_index,
					      i->name, bs->bh->b_size, 1);
		if (error && error != -ENODATA)
			goto cleanup;
		bs->s.not_found = error;
	}
	error = 0;

cleanup:
	return error;
}

static int
mockfs_xattr_block_set(handle_t *handle, struct inode *inode,
		     struct mockfs_xattr_info *i,
		     struct mockfs_xattr_block_find *bs)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *new_bh = NULL;
	struct mockfs_xattr_search *s = &bs->s;
	struct mb_cache_entry *ce = NULL;
	int error = 0;
	struct mb_cache *mockfs_mb_cache = MOCKFS_GET_MB_CACHE(inode);

#define header(x) ((struct mockfs_xattr_header *)(x))

	if (i->value && i->value_len > sb->s_blocksize)
		return -ENOSPC;
	if (s->base) {
		BUFFER_TRACE(bs->bh, "get_write_access");
		error = mockfs_journal_get_write_access(handle, bs->bh);
		if (error)
			goto cleanup;
		lock_buffer(bs->bh);

		if (header(s->base)->h_refcount == cpu_to_le32(1)) {
			__u32 hash = le32_to_cpu(BHDR(bs->bh)->h_hash);

			/*
			 * This must happen under buffer lock for
			 * mockfs_xattr_block_set() to reliably detect modified
			 * block
			 */
			mb_cache_entry_delete_block(mockfs_mb_cache, hash,
						    bs->bh->b_blocknr);
			ea_bdebug(bs->bh, "modifying in-place");
			error = mockfs_xattr_set_entry(i, s);
			if (!error) {
				if (!IS_LAST_ENTRY(s->first))
					mockfs_xattr_rehash(header(s->base),
							  s->here);
				mockfs_xattr_cache_insert(mockfs_mb_cache,
					bs->bh);
			}
			unlock_buffer(bs->bh);
			if (error == -EFSCORRUPTED)
				goto bad_block;
			if (!error)
				error = mockfs_handle_dirty_xattr_block(handle,
								      inode,
								      bs->bh);
			if (error)
				goto cleanup;
			goto inserted;
		} else {
			int offset = (char *)s->here - bs->bh->b_data;

			unlock_buffer(bs->bh);
			ea_bdebug(bs->bh, "cloning");
			s->base = kmalloc(bs->bh->b_size, GFP_NOFS);
			error = -ENOMEM;
			if (s->base == NULL)
				goto cleanup;
			memcpy(s->base, BHDR(bs->bh), bs->bh->b_size);
			s->first = ENTRY(header(s->base)+1);
			header(s->base)->h_refcount = cpu_to_le32(1);
			s->here = ENTRY(s->base + offset);
			s->end = s->base + bs->bh->b_size;
		}
	} else {
		/* Allocate a buffer where we construct the new block. */
		s->base = kzalloc(sb->s_blocksize, GFP_NOFS);
		/* assert(header == s->base) */
		error = -ENOMEM;
		if (s->base == NULL)
			goto cleanup;
		header(s->base)->h_magic = cpu_to_le32(MOCKFS_XATTR_MAGIC);
		header(s->base)->h_blocks = cpu_to_le32(1);
		header(s->base)->h_refcount = cpu_to_le32(1);
		s->first = ENTRY(header(s->base)+1);
		s->here = ENTRY(header(s->base)+1);
		s->end = s->base + sb->s_blocksize;
	}

	error = mockfs_xattr_set_entry(i, s);
	if (error == -EFSCORRUPTED)
		goto bad_block;
	if (error)
		goto cleanup;
	if (!IS_LAST_ENTRY(s->first))
		mockfs_xattr_rehash(header(s->base), s->here);

inserted:
	if (!IS_LAST_ENTRY(s->first)) {
		new_bh = mockfs_xattr_cache_find(inode, header(s->base), &ce);
		if (new_bh) {
			/* We found an identical block in the cache. */
			if (new_bh == bs->bh)
				ea_bdebug(new_bh, "keeping");
			else {
				u32 ref;

				/* The old block is released after updating
				   the inode. */
				error = dquot_alloc_block(inode,
						MOCKFS_C2B(MOCKFS_SB(sb), 1));
				if (error)
					goto cleanup;
				BUFFER_TRACE(new_bh, "get_write_access");
				error = mockfs_journal_get_write_access(handle,
								      new_bh);
				if (error)
					goto cleanup_dquot;
				lock_buffer(new_bh);
				/*
				 * We have to be careful about races with
				 * freeing, rehashing or adding references to
				 * xattr block. Once we hold buffer lock xattr
				 * block's state is stable so we can check
				 * whether the block got freed / rehashed or
				 * not.  Since we unhash mbcache entry under
				 * buffer lock when freeing / rehashing xattr
				 * block, checking whether entry is still
				 * hashed is reliable. Same rules hold for
				 * e_reusable handling.
				 */
				if (hlist_bl_unhashed(&ce->e_hash_list) ||
				    !ce->e_reusable) {
					/*
					 * Undo everything and check mbcache
					 * again.
					 */
					unlock_buffer(new_bh);
					dquot_free_block(inode,
							 MOCKFS_C2B(MOCKFS_SB(sb),
								  1));
					brelse(new_bh);
					mb_cache_entry_put(mockfs_mb_cache, ce);
					ce = NULL;
					new_bh = NULL;
					goto inserted;
				}
				ref = le32_to_cpu(BHDR(new_bh)->h_refcount) + 1;
				BHDR(new_bh)->h_refcount = cpu_to_le32(ref);
				if (ref >= MOCKFS_XATTR_REFCOUNT_MAX)
					ce->e_reusable = 0;
				ea_bdebug(new_bh, "reusing; refcount now=%d",
					  ref);
				unlock_buffer(new_bh);
				error = mockfs_handle_dirty_xattr_block(handle,
								      inode,
								      new_bh);
				if (error)
					goto cleanup_dquot;
			}
			mb_cache_entry_touch(mockfs_mb_cache, ce);
			mb_cache_entry_put(mockfs_mb_cache, ce);
			ce = NULL;
		} else if (bs->bh && s->base == bs->bh->b_data) {
			/* We were modifying this block in-place. */
			ea_bdebug(bs->bh, "keeping this block");
			new_bh = bs->bh;
			get_bh(new_bh);
		} else {
			/* We need to allocate a new block */
			mockfs_fsblk_t goal, block;

			goal = mockfs_group_first_block_no(sb,
						MOCKFS_I(inode)->i_block_group);

			/* non-extent files can't have physical blocks past 2^32 */
			if (!(mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS)))
				goal = goal & MOCKFS_MAX_BLOCK_FILE_PHYS;

			block = mockfs_new_meta_blocks(handle, inode, goal, 0,
						     NULL, &error);
			if (error)
				goto cleanup;

			if (!(mockfs_test_inode_flag(inode, MOCKFS_INODE_EXTENTS)))
				BUG_ON(block > MOCKFS_MAX_BLOCK_FILE_PHYS);

			ea_idebug(inode, "creating block %llu",
				  (unsigned long long)block);

			new_bh = sb_getblk(sb, block);
			if (unlikely(!new_bh)) {
				error = -ENOMEM;
getblk_failed:
				mockfs_free_blocks(handle, inode, NULL, block, 1,
						 MOCKFS_FREE_BLOCKS_METADATA);
				goto cleanup;
			}
			lock_buffer(new_bh);
			error = mockfs_journal_get_create_access(handle, new_bh);
			if (error) {
				unlock_buffer(new_bh);
				error = -EIO;
				goto getblk_failed;
			}
			memcpy(new_bh->b_data, s->base, new_bh->b_size);
			set_buffer_uptodate(new_bh);
			unlock_buffer(new_bh);
			mockfs_xattr_cache_insert(mockfs_mb_cache, new_bh);
			error = mockfs_handle_dirty_xattr_block(handle,
							      inode, new_bh);
			if (error)
				goto cleanup;
		}
	}

	/* Update the inode. */
	MOCKFS_I(inode)->i_file_acl = new_bh ? new_bh->b_blocknr : 0;

	/* Drop the previous xattr block. */
	if (bs->bh && bs->bh != new_bh)
		mockfs_xattr_release_block(handle, inode, bs->bh);
	error = 0;

cleanup:
	if (ce)
		mb_cache_entry_put(mockfs_mb_cache, ce);
	brelse(new_bh);
	if (!(bs->bh && s->base == bs->bh->b_data))
		kfree(s->base);

	return error;

cleanup_dquot:
	dquot_free_block(inode, MOCKFS_C2B(MOCKFS_SB(sb), 1));
	goto cleanup;

bad_block:
	MOCKFS_ERROR_INODE(inode, "bad block %llu",
			 MOCKFS_I(inode)->i_file_acl);
	goto cleanup;

#undef header
}

int mockfs_xattr_ibody_find(struct inode *inode, struct mockfs_xattr_info *i,
			  struct mockfs_xattr_ibody_find *is)
{
	struct mockfs_xattr_ibody_header *header;
	struct mockfs_inode *raw_inode;
	int error;

	if (MOCKFS_I(inode)->i_extra_isize == 0)
		return 0;
	raw_inode = mockfs_raw_inode(&is->iloc);
	header = IHDR(inode, raw_inode);
	is->s.base = is->s.first = IFIRST(header);
	is->s.here = is->s.first;
	is->s.end = (void *)raw_inode + MOCKFS_SB(inode->i_sb)->s_inode_size;
	if (mockfs_test_inode_state(inode, MOCKFS_STATE_XATTR)) {
		error = xattr_check_inode(inode, header, is->s.end);
		if (error)
			return error;
		/* Find the named attribute. */
		error = mockfs_xattr_find_entry(&is->s.here, i->name_index,
					      i->name, is->s.end -
					      (void *)is->s.base, 0);
		if (error && error != -ENODATA)
			return error;
		is->s.not_found = error;
	}
	return 0;
}

int mockfs_xattr_ibody_inline_set(handle_t *handle, struct inode *inode,
				struct mockfs_xattr_info *i,
				struct mockfs_xattr_ibody_find *is)
{
	struct mockfs_xattr_ibody_header *header;
	struct mockfs_xattr_search *s = &is->s;
	int error;

	if (MOCKFS_I(inode)->i_extra_isize == 0)
		return -ENOSPC;
	error = mockfs_xattr_set_entry(i, s);
	if (error) {
		if (error == -ENOSPC &&
		    mockfs_has_inline_data(inode)) {
			error = mockfs_try_to_evict_inline_data(handle, inode,
					MOCKFS_XATTR_LEN(strlen(i->name) +
					MOCKFS_XATTR_SIZE(i->value_len)));
			if (error)
				return error;
			error = mockfs_xattr_ibody_find(inode, i, is);
			if (error)
				return error;
			error = mockfs_xattr_set_entry(i, s);
		}
		if (error)
			return error;
	}
	header = IHDR(inode, mockfs_raw_inode(&is->iloc));
	if (!IS_LAST_ENTRY(s->first)) {
		header->h_magic = cpu_to_le32(MOCKFS_XATTR_MAGIC);
		mockfs_set_inode_state(inode, MOCKFS_STATE_XATTR);
	} else {
		header->h_magic = cpu_to_le32(0);
		mockfs_clear_inode_state(inode, MOCKFS_STATE_XATTR);
	}
	return 0;
}

static int mockfs_xattr_ibody_set(handle_t *handle, struct inode *inode,
				struct mockfs_xattr_info *i,
				struct mockfs_xattr_ibody_find *is)
{
	struct mockfs_xattr_ibody_header *header;
	struct mockfs_xattr_search *s = &is->s;
	int error;

	if (MOCKFS_I(inode)->i_extra_isize == 0)
		return -ENOSPC;
	error = mockfs_xattr_set_entry(i, s);
	if (error)
		return error;
	header = IHDR(inode, mockfs_raw_inode(&is->iloc));
	if (!IS_LAST_ENTRY(s->first)) {
		header->h_magic = cpu_to_le32(MOCKFS_XATTR_MAGIC);
		mockfs_set_inode_state(inode, MOCKFS_STATE_XATTR);
	} else {
		header->h_magic = cpu_to_le32(0);
		mockfs_clear_inode_state(inode, MOCKFS_STATE_XATTR);
	}
	return 0;
}

static int mockfs_xattr_value_same(struct mockfs_xattr_search *s,
				 struct mockfs_xattr_info *i)
{
	void *value;

	if (le32_to_cpu(s->here->e_value_size) != i->value_len)
		return 0;
	value = ((void *)s->base) + le16_to_cpu(s->here->e_value_offs);
	return !memcmp(value, i->value, i->value_len);
}

/*
 * mockfs_xattr_set_handle()
 *
 * Create, replace or remove an extended attribute for this inode.  Value
 * is NULL to remove an existing extended attribute, and non-NULL to
 * either replace an existing extended attribute, or create a new extended
 * attribute. The flags XATTR_REPLACE and XATTR_CREATE
 * specify that an extended attribute must exist and must not exist
 * previous to the call, respectively.
 *
 * Returns 0, or a negative error number on failure.
 */
int
mockfs_xattr_set_handle(handle_t *handle, struct inode *inode, int name_index,
		      const char *name, const void *value, size_t value_len,
		      int flags)
{
	struct mockfs_xattr_info i = {
		.name_index = name_index,
		.name = name,
		.value = value,
		.value_len = value_len,

	};
	struct mockfs_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct mockfs_xattr_block_find bs = {
		.s = { .not_found = -ENODATA, },
	};
	unsigned long no_expand;
	int error;

	if (!name)
		return -EINVAL;
	if (strlen(name) > 255)
		return -ERANGE;
	down_write(&MOCKFS_I(inode)->xattr_sem);
	no_expand = mockfs_test_inode_state(inode, MOCKFS_STATE_NO_EXPAND);
	mockfs_set_inode_state(inode, MOCKFS_STATE_NO_EXPAND);

	error = mockfs_reserve_inode_write(handle, inode, &is.iloc);
	if (error)
		goto cleanup;

	if (mockfs_test_inode_state(inode, MOCKFS_STATE_NEW)) {
		struct mockfs_inode *raw_inode = mockfs_raw_inode(&is.iloc);
		memset(raw_inode, 0, MOCKFS_SB(inode->i_sb)->s_inode_size);
		mockfs_clear_inode_state(inode, MOCKFS_STATE_NEW);
	}

	error = mockfs_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto cleanup;
	if (is.s.not_found)
		error = mockfs_xattr_block_find(inode, &i, &bs);
	if (error)
		goto cleanup;
	if (is.s.not_found && bs.s.not_found) {
		error = -ENODATA;
		if (flags & XATTR_REPLACE)
			goto cleanup;
		error = 0;
		if (!value)
			goto cleanup;
	} else {
		error = -EEXIST;
		if (flags & XATTR_CREATE)
			goto cleanup;
	}
	if (!value) {
		if (!is.s.not_found)
			error = mockfs_xattr_ibody_set(handle, inode, &i, &is);
		else if (!bs.s.not_found)
			error = mockfs_xattr_block_set(handle, inode, &i, &bs);
	} else {
		error = 0;
		/* Xattr value did not change? Save us some work and bail out */
		if (!is.s.not_found && mockfs_xattr_value_same(&is.s, &i))
			goto cleanup;
		if (!bs.s.not_found && mockfs_xattr_value_same(&bs.s, &i))
			goto cleanup;

		error = mockfs_xattr_ibody_set(handle, inode, &i, &is);
		if (!error && !bs.s.not_found) {
			i.value = NULL;
			error = mockfs_xattr_block_set(handle, inode, &i, &bs);
		} else if (error == -ENOSPC) {
			if (MOCKFS_I(inode)->i_file_acl && !bs.s.base) {
				error = mockfs_xattr_block_find(inode, &i, &bs);
				if (error)
					goto cleanup;
			}
			error = mockfs_xattr_block_set(handle, inode, &i, &bs);
			if (error)
				goto cleanup;
			if (!is.s.not_found) {
				i.value = NULL;
				error = mockfs_xattr_ibody_set(handle, inode, &i,
							     &is);
			}
		}
	}
	if (!error) {
		mockfs_xattr_update_super_block(handle, inode->i_sb);
		inode->i_ctime = mockfs_current_time(inode);
		if (!value)
			mockfs_clear_inode_state(inode, MOCKFS_STATE_NO_EXPAND);
		error = mockfs_mark_iloc_dirty(handle, inode, &is.iloc);
		/*
		 * The bh is consumed by mockfs_mark_iloc_dirty, even with
		 * error != 0.
		 */
		is.iloc.bh = NULL;
		if (IS_SYNC(inode))
			mockfs_handle_sync(handle);
	}

cleanup:
	brelse(is.iloc.bh);
	brelse(bs.bh);
	if (no_expand == 0)
		mockfs_clear_inode_state(inode, MOCKFS_STATE_NO_EXPAND);
	up_write(&MOCKFS_I(inode)->xattr_sem);
	return error;
}

/*
 * mockfs_xattr_set()
 *
 * Like mockfs_xattr_set_handle, but start from an inode. This extended
 * attribute modification is a filesystem transaction by itself.
 *
 * Returns 0, or a negative error number on failure.
 */
int
mockfs_xattr_set(struct inode *inode, int name_index, const char *name,
	       const void *value, size_t value_len, int flags)
{
	handle_t *handle;
	int error, retries = 0;
	int credits = mockfs_jbd2_credits_xattr(inode);

retry:
	handle = mockfs_journal_start(inode, MOCKFS_HT_XATTR, credits);
	if (IS_ERR(handle)) {
		error = PTR_ERR(handle);
	} else {
		int error2;

		error = mockfs_xattr_set_handle(handle, inode, name_index, name,
					      value, value_len, flags);
		error2 = mockfs_journal_stop(handle);
		if (error == -ENOSPC &&
		    mockfs_should_retry_alloc(inode->i_sb, &retries))
			goto retry;
		if (error == 0)
			error = error2;
	}

	return error;
}

/*
 * Shift the EA entries in the inode to create space for the increased
 * i_extra_isize.
 */
static void mockfs_xattr_shift_entries(struct mockfs_xattr_entry *entry,
				     int value_offs_shift, void *to,
				     void *from, size_t n, int blocksize)
{
	struct mockfs_xattr_entry *last = entry;
	int new_offs;

	/* Adjust the value offsets of the entries */
	for (; !IS_LAST_ENTRY(last); last = MOCKFS_XATTR_NEXT(last)) {
		if (!last->e_value_block && last->e_value_size) {
			new_offs = le16_to_cpu(last->e_value_offs) +
							value_offs_shift;
			BUG_ON(new_offs + le32_to_cpu(last->e_value_size)
				 > blocksize);
			last->e_value_offs = cpu_to_le16(new_offs);
		}
	}
	/* Shift the entries by n bytes */
	memmove(to, from, n);
}

/*
 * Expand an inode by new_extra_isize bytes when EAs are present.
 * Returns 0 on success or negative error number on failure.
 */
int mockfs_expand_extra_isize_ea(struct inode *inode, int new_extra_isize,
			       struct mockfs_inode *raw_inode, handle_t *handle)
{
	struct mockfs_xattr_ibody_header *header;
	struct mockfs_xattr_entry *entry, *last, *first;
	struct buffer_head *bh = NULL;
	struct mockfs_xattr_ibody_find *is = NULL;
	struct mockfs_xattr_block_find *bs = NULL;
	char *buffer = NULL, *b_entry_name = NULL;
	size_t min_offs, free;
	int total_ino;
	void *base, *start, *end;
	int extra_isize = 0, error = 0, tried_min_extra_isize = 0;
	int s_min_extra_isize = le16_to_cpu(MOCKFS_SB(inode->i_sb)->s_es->s_min_extra_isize);

	down_write(&MOCKFS_I(inode)->xattr_sem);
retry:
	if (MOCKFS_I(inode)->i_extra_isize >= new_extra_isize) {
		up_write(&MOCKFS_I(inode)->xattr_sem);
		return 0;
	}

	header = IHDR(inode, raw_inode);
	entry = IFIRST(header);

	/*
	 * Check if enough free space is available in the inode to shift the
	 * entries ahead by new_extra_isize.
	 */

	base = start = entry;
	end = (void *)raw_inode + MOCKFS_SB(inode->i_sb)->s_inode_size;
	min_offs = end - base;
	last = entry;
	total_ino = sizeof(struct mockfs_xattr_ibody_header);

	error = xattr_check_inode(inode, header, end);
	if (error)
		goto cleanup;

	free = mockfs_xattr_free_space(last, &min_offs, base, &total_ino);
	if (free >= new_extra_isize) {
		entry = IFIRST(header);
		mockfs_xattr_shift_entries(entry,	MOCKFS_I(inode)->i_extra_isize
				- new_extra_isize, (void *)raw_inode +
				MOCKFS_GOOD_OLD_INODE_SIZE + new_extra_isize,
				(void *)header, total_ino,
				inode->i_sb->s_blocksize);
		MOCKFS_I(inode)->i_extra_isize = new_extra_isize;
		error = 0;
		goto cleanup;
	}

	/*
	 * Enough free space isn't available in the inode, check if
	 * EA block can hold new_extra_isize bytes.
	 */
	if (MOCKFS_I(inode)->i_file_acl) {
		bh = sb_bread(inode->i_sb, MOCKFS_I(inode)->i_file_acl);
		error = -EIO;
		if (!bh)
			goto cleanup;
		if (mockfs_xattr_check_block(inode, bh)) {
			MOCKFS_ERROR_INODE(inode, "bad block %llu",
					 MOCKFS_I(inode)->i_file_acl);
			error = -EFSCORRUPTED;
			goto cleanup;
		}
		base = BHDR(bh);
		first = BFIRST(bh);
		end = bh->b_data + bh->b_size;
		min_offs = end - base;
		free = mockfs_xattr_free_space(first, &min_offs, base, NULL);
		if (free < new_extra_isize) {
			if (!tried_min_extra_isize && s_min_extra_isize) {
				tried_min_extra_isize++;
				new_extra_isize = s_min_extra_isize;
				brelse(bh);
				goto retry;
			}
			error = -1;
			goto cleanup;
		}
	} else {
		free = inode->i_sb->s_blocksize;
	}

	while (new_extra_isize > 0) {
		size_t offs, size, entry_size;
		struct mockfs_xattr_entry *small_entry = NULL;
		struct mockfs_xattr_info i = {
			.value = NULL,
			.value_len = 0,
		};
		unsigned int total_size;  /* EA entry size + value size */
		unsigned int shift_bytes; /* No. of bytes to shift EAs by? */
		unsigned int min_total_size = ~0U;

		is = kzalloc(sizeof(struct mockfs_xattr_ibody_find), GFP_NOFS);
		bs = kzalloc(sizeof(struct mockfs_xattr_block_find), GFP_NOFS);
		if (!is || !bs) {
			error = -ENOMEM;
			goto cleanup;
		}

		is->s.not_found = -ENODATA;
		bs->s.not_found = -ENODATA;
		is->iloc.bh = NULL;
		bs->bh = NULL;

		last = IFIRST(header);
		/* Find the entry best suited to be pushed into EA block */
		entry = NULL;
		for (; !IS_LAST_ENTRY(last); last = MOCKFS_XATTR_NEXT(last)) {
			total_size =
			MOCKFS_XATTR_SIZE(le32_to_cpu(last->e_value_size)) +
					MOCKFS_XATTR_LEN(last->e_name_len);
			if (total_size <= free && total_size < min_total_size) {
				if (total_size < new_extra_isize) {
					small_entry = last;
				} else {
					entry = last;
					min_total_size = total_size;
				}
			}
		}

		if (entry == NULL) {
			if (small_entry) {
				entry = small_entry;
			} else {
				if (!tried_min_extra_isize &&
				    s_min_extra_isize) {
					tried_min_extra_isize++;
					new_extra_isize = s_min_extra_isize;
					kfree(is); is = NULL;
					kfree(bs); bs = NULL;
					brelse(bh);
					goto retry;
				}
				error = -1;
				goto cleanup;
			}
		}
		offs = le16_to_cpu(entry->e_value_offs);
		size = le32_to_cpu(entry->e_value_size);
		entry_size = MOCKFS_XATTR_LEN(entry->e_name_len);
		i.name_index = entry->e_name_index,
		buffer = kmalloc(MOCKFS_XATTR_SIZE(size), GFP_NOFS);
		b_entry_name = kmalloc(entry->e_name_len + 1, GFP_NOFS);
		if (!buffer || !b_entry_name) {
			error = -ENOMEM;
			goto cleanup;
		}
		/* Save the entry name and the entry value */
		memcpy(buffer, (void *)IFIRST(header) + offs,
		       MOCKFS_XATTR_SIZE(size));
		memcpy(b_entry_name, entry->e_name, entry->e_name_len);
		b_entry_name[entry->e_name_len] = '\0';
		i.name = b_entry_name;

		error = mockfs_get_inode_loc(inode, &is->iloc);
		if (error)
			goto cleanup;

		error = mockfs_xattr_ibody_find(inode, &i, is);
		if (error)
			goto cleanup;

		/* Remove the chosen entry from the inode */
		error = mockfs_xattr_ibody_set(handle, inode, &i, is);
		if (error)
			goto cleanup;

		entry = IFIRST(header);
		if (entry_size + MOCKFS_XATTR_SIZE(size) >= new_extra_isize)
			shift_bytes = new_extra_isize;
		else
			shift_bytes = entry_size + size;
		/* Adjust the offsets and shift the remaining entries ahead */
		mockfs_xattr_shift_entries(entry, MOCKFS_I(inode)->i_extra_isize -
			shift_bytes, (void *)raw_inode +
			MOCKFS_GOOD_OLD_INODE_SIZE + extra_isize + shift_bytes,
			(void *)header, total_ino - entry_size,
			inode->i_sb->s_blocksize);

		extra_isize += shift_bytes;
		new_extra_isize -= shift_bytes;
		MOCKFS_I(inode)->i_extra_isize = extra_isize;

		i.name = b_entry_name;
		i.value = buffer;
		i.value_len = size;
		error = mockfs_xattr_block_find(inode, &i, bs);
		if (error)
			goto cleanup;

		/* Add entry which was removed from the inode into the block */
		error = mockfs_xattr_block_set(handle, inode, &i, bs);
		if (error)
			goto cleanup;
		kfree(b_entry_name);
		kfree(buffer);
		b_entry_name = NULL;
		buffer = NULL;
		brelse(is->iloc.bh);
		kfree(is);
		kfree(bs);
	}
	brelse(bh);
	up_write(&MOCKFS_I(inode)->xattr_sem);
	return 0;

cleanup:
	kfree(b_entry_name);
	kfree(buffer);
	if (is)
		brelse(is->iloc.bh);
	kfree(is);
	kfree(bs);
	brelse(bh);
	up_write(&MOCKFS_I(inode)->xattr_sem);
	return error;
}



/*
 * mockfs_xattr_delete_inode()
 *
 * Free extended attribute resources associated with this inode. This
 * is called immediately before an inode is freed. We have exclusive
 * access to the inode.
 */
void
mockfs_xattr_delete_inode(handle_t *handle, struct inode *inode)
{
	struct buffer_head *bh = NULL;

	if (!MOCKFS_I(inode)->i_file_acl)
		goto cleanup;
	bh = sb_bread(inode->i_sb, MOCKFS_I(inode)->i_file_acl);
	if (!bh) {
		MOCKFS_ERROR_INODE(inode, "block %llu read error",
				 MOCKFS_I(inode)->i_file_acl);
		goto cleanup;
	}
	if (BHDR(bh)->h_magic != cpu_to_le32(MOCKFS_XATTR_MAGIC) ||
	    BHDR(bh)->h_blocks != cpu_to_le32(1)) {
		MOCKFS_ERROR_INODE(inode, "bad block %llu",
				 MOCKFS_I(inode)->i_file_acl);
		goto cleanup;
	}
	mockfs_xattr_release_block(handle, inode, bh);
	MOCKFS_I(inode)->i_file_acl = 0;

cleanup:
	brelse(bh);
}

/*
 * mockfs_xattr_cache_insert()
 *
 * Create a new entry in the extended attribute cache, and insert
 * it unless such an entry is already in the cache.
 *
 * Returns 0, or a negative error number on failure.
 */
static void
mockfs_xattr_cache_insert(struct mb_cache *mockfs_mb_cache, struct buffer_head *bh)
{
	struct mockfs_xattr_header *header = BHDR(bh);
	__u32 hash = le32_to_cpu(header->h_hash);
	int reusable = le32_to_cpu(header->h_refcount) <
		       MOCKFS_XATTR_REFCOUNT_MAX;
	int error;

	error = mb_cache_entry_create(mockfs_mb_cache, GFP_NOFS, hash,
				      bh->b_blocknr, reusable);
	if (error) {
		if (error == -EBUSY)
			ea_bdebug(bh, "already in cache");
	} else
		ea_bdebug(bh, "inserting [%x]", (int)hash);
}

/*
 * mockfs_xattr_cmp()
 *
 * Compare two extended attribute blocks for equality.
 *
 * Returns 0 if the blocks are equal, 1 if they differ, and
 * a negative error number on errors.
 */
static int
mockfs_xattr_cmp(struct mockfs_xattr_header *header1,
	       struct mockfs_xattr_header *header2)
{
	struct mockfs_xattr_entry *entry1, *entry2;

	entry1 = ENTRY(header1+1);
	entry2 = ENTRY(header2+1);
	while (!IS_LAST_ENTRY(entry1)) {
		if (IS_LAST_ENTRY(entry2))
			return 1;
		if (entry1->e_hash != entry2->e_hash ||
		    entry1->e_name_index != entry2->e_name_index ||
		    entry1->e_name_len != entry2->e_name_len ||
		    entry1->e_value_size != entry2->e_value_size ||
		    memcmp(entry1->e_name, entry2->e_name, entry1->e_name_len))
			return 1;
		if (entry1->e_value_block != 0 || entry2->e_value_block != 0)
			return -EFSCORRUPTED;
		if (memcmp((char *)header1 + le16_to_cpu(entry1->e_value_offs),
			   (char *)header2 + le16_to_cpu(entry2->e_value_offs),
			   le32_to_cpu(entry1->e_value_size)))
			return 1;

		entry1 = MOCKFS_XATTR_NEXT(entry1);
		entry2 = MOCKFS_XATTR_NEXT(entry2);
	}
	if (!IS_LAST_ENTRY(entry2))
		return 1;
	return 0;
}

/*
 * mockfs_xattr_cache_find()
 *
 * Find an identical extended attribute block.
 *
 * Returns a pointer to the block found, or NULL if such a block was
 * not found or an error occurred.
 */
static struct buffer_head *
mockfs_xattr_cache_find(struct inode *inode, struct mockfs_xattr_header *header,
		      struct mb_cache_entry **pce)
{
	__u32 hash = le32_to_cpu(header->h_hash);
	struct mb_cache_entry *ce;
	struct mb_cache *mockfs_mb_cache = MOCKFS_GET_MB_CACHE(inode);

	if (!header->h_hash)
		return NULL;  /* never share */
	ea_idebug(inode, "looking for cached blocks [%x]", (int)hash);
	ce = mb_cache_entry_find_first(mockfs_mb_cache, hash);
	while (ce) {
		struct buffer_head *bh;

		bh = sb_bread(inode->i_sb, ce->e_block);
		if (!bh) {
			MOCKFS_ERROR_INODE(inode, "block %lu read error",
					 (unsigned long) ce->e_block);
		} else if (mockfs_xattr_cmp(header, BHDR(bh)) == 0) {
			*pce = ce;
			return bh;
		}
		brelse(bh);
		ce = mb_cache_entry_find_next(mockfs_mb_cache, ce);
	}
	return NULL;
}

#define NAME_HASH_SHIFT 5
#define VALUE_HASH_SHIFT 16

/*
 * mockfs_xattr_hash_entry()
 *
 * Compute the hash of an extended attribute.
 */
static inline void mockfs_xattr_hash_entry(struct mockfs_xattr_header *header,
					 struct mockfs_xattr_entry *entry)
{
	__u32 hash = 0;
	char *name = entry->e_name;
	int n;

	for (n = 0; n < entry->e_name_len; n++) {
		hash = (hash << NAME_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - NAME_HASH_SHIFT)) ^
		       *name++;
	}

	if (entry->e_value_block == 0 && entry->e_value_size != 0) {
		__le32 *value = (__le32 *)((char *)header +
			le16_to_cpu(entry->e_value_offs));
		for (n = (le32_to_cpu(entry->e_value_size) +
		     MOCKFS_XATTR_ROUND) >> MOCKFS_XATTR_PAD_BITS; n; n--) {
			hash = (hash << VALUE_HASH_SHIFT) ^
			       (hash >> (8*sizeof(hash) - VALUE_HASH_SHIFT)) ^
			       le32_to_cpu(*value++);
		}
	}
	entry->e_hash = cpu_to_le32(hash);
}

#undef NAME_HASH_SHIFT
#undef VALUE_HASH_SHIFT

#define BLOCK_HASH_SHIFT 16

/*
 * mockfs_xattr_rehash()
 *
 * Re-compute the extended attribute hash value after an entry has changed.
 */
static void mockfs_xattr_rehash(struct mockfs_xattr_header *header,
			      struct mockfs_xattr_entry *entry)
{
	struct mockfs_xattr_entry *here;
	__u32 hash = 0;

	mockfs_xattr_hash_entry(header, entry);
	here = ENTRY(header+1);
	while (!IS_LAST_ENTRY(here)) {
		if (!here->e_hash) {
			/* Block is not shared if an entry's hash value == 0 */
			hash = 0;
			break;
		}
		hash = (hash << BLOCK_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - BLOCK_HASH_SHIFT)) ^
		       le32_to_cpu(here->e_hash);
		here = MOCKFS_XATTR_NEXT(here);
	}
	header->h_hash = cpu_to_le32(hash);
}

#undef BLOCK_HASH_SHIFT

#define	HASH_BUCKET_BITS	10

struct mb_cache *
mockfs_xattr_create_cache(void)
{
	return mb_cache_create(HASH_BUCKET_BITS);
}

void mockfs_xattr_destroy_cache(struct mb_cache *cache)
{
	if (cache)
		mb_cache_destroy(cache);
}

