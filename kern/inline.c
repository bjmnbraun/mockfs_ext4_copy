/*
 * Copyright (c) 2012 Taobao.
 * Written by Tao Ma <boyu.mt@taobao.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/fiemap.h>

#include "mockfs_jbd2.h"
#include "mockfs.h"
#include "xattr.h"
#include "truncate.h"

#define MOCKFS_XATTR_SYSTEM_DATA	"data"
#define MOCKFS_MIN_INLINE_DATA_SIZE	((sizeof(__le32) * MOCKFS_N_BLOCKS))
#define MOCKFS_INLINE_DOTDOT_OFFSET	2
#define MOCKFS_INLINE_DOTDOT_SIZE		4

static int mockfs_get_inline_size(struct inode *inode)
{
	if (MOCKFS_I(inode)->i_inline_off)
		return MOCKFS_I(inode)->i_inline_size;

	return 0;
}

static int get_max_inline_xattr_value_size(struct inode *inode,
					   struct mockfs_iloc *iloc)
{
	struct mockfs_xattr_ibody_header *header;
	struct mockfs_xattr_entry *entry;
	struct mockfs_inode *raw_inode;
	int free, min_offs;

	min_offs = MOCKFS_SB(inode->i_sb)->s_inode_size -
			MOCKFS_GOOD_OLD_INODE_SIZE -
			MOCKFS_I(inode)->i_extra_isize -
			sizeof(struct mockfs_xattr_ibody_header);

	/*
	 * We need to subtract another sizeof(__u32) since an in-inode xattr
	 * needs an empty 4 bytes to indicate the gap between the xattr entry
	 * and the name/value pair.
	 */
	if (!mockfs_test_inode_state(inode, MOCKFS_STATE_XATTR))
		return MOCKFS_XATTR_SIZE(min_offs -
			MOCKFS_XATTR_LEN(strlen(MOCKFS_XATTR_SYSTEM_DATA)) -
			MOCKFS_XATTR_ROUND - sizeof(__u32));

	raw_inode = mockfs_raw_inode(iloc);
	header = IHDR(inode, raw_inode);
	entry = IFIRST(header);

	/* Compute min_offs. */
	for (; !IS_LAST_ENTRY(entry); entry = MOCKFS_XATTR_NEXT(entry)) {
		if (!entry->e_value_block && entry->e_value_size) {
			size_t offs = le16_to_cpu(entry->e_value_offs);
			if (offs < min_offs)
				min_offs = offs;
		}
	}
	free = min_offs -
		((void *)entry - (void *)IFIRST(header)) - sizeof(__u32);

	if (MOCKFS_I(inode)->i_inline_off) {
		entry = (struct mockfs_xattr_entry *)
			((void *)raw_inode + MOCKFS_I(inode)->i_inline_off);

		free += MOCKFS_XATTR_SIZE(le32_to_cpu(entry->e_value_size));
		goto out;
	}

	free -= MOCKFS_XATTR_LEN(strlen(MOCKFS_XATTR_SYSTEM_DATA));

	if (free > MOCKFS_XATTR_ROUND)
		free = MOCKFS_XATTR_SIZE(free - MOCKFS_XATTR_ROUND);
	else
		free = 0;

out:
	return free;
}

/*
 * Get the maximum size we now can store in an inode.
 * If we can't find the space for a xattr entry, don't use the space
 * of the extents since we have no space to indicate the inline data.
 */
int mockfs_get_max_inline_size(struct inode *inode)
{
	int error, max_inline_size;
	struct mockfs_iloc iloc;

	if (MOCKFS_I(inode)->i_extra_isize == 0)
		return 0;

	error = mockfs_get_inode_loc(inode, &iloc);
	if (error) {
		mockfs_error_inode(inode, __func__, __LINE__, 0,
				 "can't get inode location %lu",
				 inode->i_ino);
		return 0;
	}

	down_read(&MOCKFS_I(inode)->xattr_sem);
	max_inline_size = get_max_inline_xattr_value_size(inode, &iloc);
	up_read(&MOCKFS_I(inode)->xattr_sem);

	brelse(iloc.bh);

	if (!max_inline_size)
		return 0;

	return max_inline_size + MOCKFS_MIN_INLINE_DATA_SIZE;
}

/*
 * this function does not take xattr_sem, which is OK because it is
 * currently only used in a code path coming form mockfs_iget, before
 * the new inode has been unlocked
 */
int mockfs_find_inline_data_nolock(struct inode *inode)
{
	struct mockfs_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct mockfs_xattr_info i = {
		.name_index = MOCKFS_XATTR_INDEX_SYSTEM,
		.name = MOCKFS_XATTR_SYSTEM_DATA,
	};
	int error;

	if (MOCKFS_I(inode)->i_extra_isize == 0)
		return 0;

	error = mockfs_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = mockfs_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	if (!is.s.not_found) {
		MOCKFS_I(inode)->i_inline_off = (u16)((void *)is.s.here -
					(void *)mockfs_raw_inode(&is.iloc));
		MOCKFS_I(inode)->i_inline_size = MOCKFS_MIN_INLINE_DATA_SIZE +
				le32_to_cpu(is.s.here->e_value_size);
		mockfs_set_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA);
	}
out:
	brelse(is.iloc.bh);
	return error;
}

static int mockfs_read_inline_data(struct inode *inode, void *buffer,
				 unsigned int len,
				 struct mockfs_iloc *iloc)
{
	struct mockfs_xattr_entry *entry;
	struct mockfs_xattr_ibody_header *header;
	int cp_len = 0;
	struct mockfs_inode *raw_inode;

	if (!len)
		return 0;

	BUG_ON(len > MOCKFS_I(inode)->i_inline_size);

	cp_len = len < MOCKFS_MIN_INLINE_DATA_SIZE ?
			len : MOCKFS_MIN_INLINE_DATA_SIZE;

	raw_inode = mockfs_raw_inode(iloc);
	memcpy(buffer, (void *)(raw_inode->i_block), cp_len);

	len -= cp_len;
	buffer += cp_len;

	if (!len)
		goto out;

	header = IHDR(inode, raw_inode);
	entry = (struct mockfs_xattr_entry *)((void *)raw_inode +
					    MOCKFS_I(inode)->i_inline_off);
	len = min_t(unsigned int, len,
		    (unsigned int)le32_to_cpu(entry->e_value_size));

	memcpy(buffer,
	       (void *)IFIRST(header) + le16_to_cpu(entry->e_value_offs), len);
	cp_len += len;

out:
	return cp_len;
}

/*
 * write the buffer to the inline inode.
 * If 'create' is set, we don't need to do the extra copy in the xattr
 * value since it is already handled by mockfs_xattr_ibody_inline_set.
 * That saves us one memcpy.
 */
static void mockfs_write_inline_data(struct inode *inode, struct mockfs_iloc *iloc,
				   void *buffer, loff_t pos, unsigned int len)
{
	struct mockfs_xattr_entry *entry;
	struct mockfs_xattr_ibody_header *header;
	struct mockfs_inode *raw_inode;
	int cp_len = 0;

	BUG_ON(!MOCKFS_I(inode)->i_inline_off);
	BUG_ON(pos + len > MOCKFS_I(inode)->i_inline_size);

	raw_inode = mockfs_raw_inode(iloc);
	buffer += pos;

	if (pos < MOCKFS_MIN_INLINE_DATA_SIZE) {
		cp_len = pos + len > MOCKFS_MIN_INLINE_DATA_SIZE ?
			 MOCKFS_MIN_INLINE_DATA_SIZE - pos : len;
		memcpy((void *)raw_inode->i_block + pos, buffer, cp_len);

		len -= cp_len;
		buffer += cp_len;
		pos += cp_len;
	}

	if (!len)
		return;

	pos -= MOCKFS_MIN_INLINE_DATA_SIZE;
	header = IHDR(inode, raw_inode);
	entry = (struct mockfs_xattr_entry *)((void *)raw_inode +
					    MOCKFS_I(inode)->i_inline_off);

	memcpy((void *)IFIRST(header) + le16_to_cpu(entry->e_value_offs) + pos,
	       buffer, len);
}

static int mockfs_create_inline_data(handle_t *handle,
				   struct inode *inode, unsigned len)
{
	int error;
	void *value = NULL;
	struct mockfs_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct mockfs_xattr_info i = {
		.name_index = MOCKFS_XATTR_INDEX_SYSTEM,
		.name = MOCKFS_XATTR_SYSTEM_DATA,
	};

	error = mockfs_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	BUFFER_TRACE(is.iloc.bh, "get_write_access");
	error = mockfs_journal_get_write_access(handle, is.iloc.bh);
	if (error)
		goto out;

	if (len > MOCKFS_MIN_INLINE_DATA_SIZE) {
		value = MOCKFS_ZERO_XATTR_VALUE;
		len -= MOCKFS_MIN_INLINE_DATA_SIZE;
	} else {
		value = "";
		len = 0;
	}

	/* Insert the the xttr entry. */
	i.value = value;
	i.value_len = len;

	error = mockfs_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	BUG_ON(!is.s.not_found);

	error = mockfs_xattr_ibody_inline_set(handle, inode, &i, &is);
	if (error) {
		if (error == -ENOSPC)
			mockfs_clear_inode_state(inode,
					       MOCKFS_STATE_MAY_INLINE_DATA);
		goto out;
	}

	memset((void *)mockfs_raw_inode(&is.iloc)->i_block,
		0, MOCKFS_MIN_INLINE_DATA_SIZE);

	MOCKFS_I(inode)->i_inline_off = (u16)((void *)is.s.here -
				      (void *)mockfs_raw_inode(&is.iloc));
	MOCKFS_I(inode)->i_inline_size = len + MOCKFS_MIN_INLINE_DATA_SIZE;
	mockfs_clear_inode_flag(inode, MOCKFS_INODE_EXTENTS);
	mockfs_set_inode_flag(inode, MOCKFS_INODE_INLINE_DATA);
	get_bh(is.iloc.bh);
	error = mockfs_mark_iloc_dirty(handle, inode, &is.iloc);

out:
	brelse(is.iloc.bh);
	return error;
}

static int mockfs_update_inline_data(handle_t *handle, struct inode *inode,
				   unsigned int len)
{
	int error;
	void *value = NULL;
	struct mockfs_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct mockfs_xattr_info i = {
		.name_index = MOCKFS_XATTR_INDEX_SYSTEM,
		.name = MOCKFS_XATTR_SYSTEM_DATA,
	};

	/* If the old space is ok, write the data directly. */
	if (len <= MOCKFS_I(inode)->i_inline_size)
		return 0;

	error = mockfs_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = mockfs_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	BUG_ON(is.s.not_found);

	len -= MOCKFS_MIN_INLINE_DATA_SIZE;
	value = kzalloc(len, GFP_NOFS);
	if (!value)
		goto out;

	error = mockfs_xattr_ibody_get(inode, i.name_index, i.name,
				     value, len);
	if (error == -ENODATA)
		goto out;

	BUFFER_TRACE(is.iloc.bh, "get_write_access");
	error = mockfs_journal_get_write_access(handle, is.iloc.bh);
	if (error)
		goto out;

	/* Update the xttr entry. */
	i.value = value;
	i.value_len = len;

	error = mockfs_xattr_ibody_inline_set(handle, inode, &i, &is);
	if (error)
		goto out;

	MOCKFS_I(inode)->i_inline_off = (u16)((void *)is.s.here -
				      (void *)mockfs_raw_inode(&is.iloc));
	MOCKFS_I(inode)->i_inline_size = MOCKFS_MIN_INLINE_DATA_SIZE +
				le32_to_cpu(is.s.here->e_value_size);
	mockfs_set_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA);
	get_bh(is.iloc.bh);
	error = mockfs_mark_iloc_dirty(handle, inode, &is.iloc);

out:
	kfree(value);
	brelse(is.iloc.bh);
	return error;
}

static int mockfs_prepare_inline_data(handle_t *handle, struct inode *inode,
				    unsigned int len)
{
	int ret, size;
	struct mockfs_inode_info *ei = MOCKFS_I(inode);

	if (!mockfs_test_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA))
		return -ENOSPC;

	size = mockfs_get_max_inline_size(inode);
	if (size < len)
		return -ENOSPC;

	down_write(&MOCKFS_I(inode)->xattr_sem);

	if (ei->i_inline_off)
		ret = mockfs_update_inline_data(handle, inode, len);
	else
		ret = mockfs_create_inline_data(handle, inode, len);

	up_write(&MOCKFS_I(inode)->xattr_sem);

	return ret;
}

static int mockfs_destroy_inline_data_nolock(handle_t *handle,
					   struct inode *inode)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	struct mockfs_xattr_ibody_find is = {
		.s = { .not_found = 0, },
	};
	struct mockfs_xattr_info i = {
		.name_index = MOCKFS_XATTR_INDEX_SYSTEM,
		.name = MOCKFS_XATTR_SYSTEM_DATA,
		.value = NULL,
		.value_len = 0,
	};
	int error;

	if (!ei->i_inline_off)
		return 0;

	error = mockfs_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = mockfs_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	BUFFER_TRACE(is.iloc.bh, "get_write_access");
	error = mockfs_journal_get_write_access(handle, is.iloc.bh);
	if (error)
		goto out;

	error = mockfs_xattr_ibody_inline_set(handle, inode, &i, &is);
	if (error)
		goto out;

	memset((void *)mockfs_raw_inode(&is.iloc)->i_block,
		0, MOCKFS_MIN_INLINE_DATA_SIZE);

	if (mockfs_has_feature_extents(inode->i_sb)) {
		if (S_ISDIR(inode->i_mode) ||
		    S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)) {
			mockfs_set_inode_flag(inode, MOCKFS_INODE_EXTENTS);
			mockfs_ext_tree_init(handle, inode);
		}
	}
	mockfs_clear_inode_flag(inode, MOCKFS_INODE_INLINE_DATA);

	get_bh(is.iloc.bh);
	error = mockfs_mark_iloc_dirty(handle, inode, &is.iloc);

	MOCKFS_I(inode)->i_inline_off = 0;
	MOCKFS_I(inode)->i_inline_size = 0;
	mockfs_clear_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA);
out:
	brelse(is.iloc.bh);
	if (error == -ENODATA)
		error = 0;
	return error;
}

static int mockfs_read_inline_page(struct inode *inode, struct page *page)
{
	void *kaddr;
	int ret = 0;
	size_t len;
	struct mockfs_iloc iloc;

	BUG_ON(!PageLocked(page));
	BUG_ON(!mockfs_has_inline_data(inode));
	BUG_ON(page->index);

	if (!MOCKFS_I(inode)->i_inline_off) {
		mockfs_warning(inode->i_sb, "inode %lu doesn't have inline data.",
			     inode->i_ino);
		goto out;
	}

	ret = mockfs_get_inode_loc(inode, &iloc);
	if (ret)
		goto out;

	len = min_t(size_t, mockfs_get_inline_size(inode), i_size_read(inode));
	kaddr = kmap_atomic(page);
	ret = mockfs_read_inline_data(inode, kaddr, len, &iloc);
	flush_dcache_page(page);
	kunmap_atomic(kaddr);
	zero_user_segment(page, len, PAGE_SIZE);
	SetPageUptodate(page);
	brelse(iloc.bh);

out:
	return ret;
}

int mockfs_readpage_inline(struct inode *inode, struct page *page)
{
	int ret = 0;

	down_read(&MOCKFS_I(inode)->xattr_sem);
	if (!mockfs_has_inline_data(inode)) {
		up_read(&MOCKFS_I(inode)->xattr_sem);
		return -EAGAIN;
	}

	/*
	 * Current inline data can only exist in the 1st page,
	 * So for all the other pages, just set them uptodate.
	 */
	if (!page->index)
		ret = mockfs_read_inline_page(inode, page);
	else if (!PageUptodate(page)) {
		zero_user_segment(page, 0, PAGE_SIZE);
		SetPageUptodate(page);
	}

	up_read(&MOCKFS_I(inode)->xattr_sem);

	unlock_page(page);
	return ret >= 0 ? 0 : ret;
}

static int mockfs_convert_inline_data_to_extent(struct address_space *mapping,
					      struct inode *inode,
					      unsigned flags)
{
	int ret, needed_blocks;
	handle_t *handle = NULL;
	int retries = 0, sem_held = 0;
	struct page *page = NULL;
	unsigned from, to;
	struct mockfs_iloc iloc;

	if (!mockfs_has_inline_data(inode)) {
		/*
		 * clear the flag so that no new write
		 * will trap here again.
		 */
		mockfs_clear_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA);
		return 0;
	}

	needed_blocks = mockfs_writepage_trans_blocks(inode);

	ret = mockfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

retry:
	handle = mockfs_journal_start(inode, MOCKFS_HT_WRITE_PAGE, needed_blocks);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		handle = NULL;
		goto out;
	}

	/* We cannot recurse into the filesystem as the transaction is already
	 * started */
	flags |= AOP_FLAG_NOFS;

	page = grab_cache_page_write_begin(mapping, 0, flags);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	down_write(&MOCKFS_I(inode)->xattr_sem);
	sem_held = 1;
	/* If some one has already done this for us, just exit. */
	if (!mockfs_has_inline_data(inode)) {
		ret = 0;
		goto out;
	}

	from = 0;
	to = mockfs_get_inline_size(inode);
	if (!PageUptodate(page)) {
		ret = mockfs_read_inline_page(inode, page);
		if (ret < 0)
			goto out;
	}

	ret = mockfs_destroy_inline_data_nolock(handle, inode);
	if (ret)
		goto out;

	if (mockfs_should_dioread_nolock(inode)) {
		ret = __block_write_begin(page, from, to,
					  mockfs_get_block_unwritten);
	} else
		ret = __block_write_begin(page, from, to, mockfs_get_block);

	if (!ret && mockfs_should_journal_data(inode)) {
		ret = mockfs_walk_page_buffers(handle, page_buffers(page),
					     from, to, NULL,
					     do_journal_get_write_access);
	}

	if (ret) {
		unlock_page(page);
		put_page(page);
		page = NULL;
		mockfs_orphan_add(handle, inode);
		up_write(&MOCKFS_I(inode)->xattr_sem);
		sem_held = 0;
		mockfs_journal_stop(handle);
		handle = NULL;
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

	if (ret == -ENOSPC && mockfs_should_retry_alloc(inode->i_sb, &retries))
		goto retry;

	if (page)
		block_commit_write(page, from, to);
out:
	if (page) {
		unlock_page(page);
		put_page(page);
	}
	if (sem_held)
		up_write(&MOCKFS_I(inode)->xattr_sem);
	if (handle)
		mockfs_journal_stop(handle);
	brelse(iloc.bh);
	return ret;
}

/*
 * Try to write data in the inode.
 * If the inode has inline data, check whether the new write can be
 * in the inode also. If not, create the page the handle, move the data
 * to the page make it update and let the later codes create extent for it.
 */
int mockfs_try_to_write_inline_data(struct address_space *mapping,
				  struct inode *inode,
				  loff_t pos, unsigned len,
				  unsigned flags,
				  struct page **pagep)
{
	int ret;
	handle_t *handle;
	struct page *page;
	struct mockfs_iloc iloc;

	if (pos + len > mockfs_get_max_inline_size(inode))
		goto convert;

	ret = mockfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	/*
	 * The possible write could happen in the inode,
	 * so try to reserve the space in inode first.
	 */
	handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		handle = NULL;
		goto out;
	}

	ret = mockfs_prepare_inline_data(handle, inode, pos + len);
	if (ret && ret != -ENOSPC)
		goto out;

	/* We don't have space in inline inode, so convert it to extent. */
	if (ret == -ENOSPC) {
		mockfs_journal_stop(handle);
		brelse(iloc.bh);
		goto convert;
	}

	flags |= AOP_FLAG_NOFS;

	page = grab_cache_page_write_begin(mapping, 0, flags);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	*pagep = page;
	down_read(&MOCKFS_I(inode)->xattr_sem);
	if (!mockfs_has_inline_data(inode)) {
		ret = 0;
		unlock_page(page);
		put_page(page);
		goto out_up_read;
	}

	if (!PageUptodate(page)) {
		ret = mockfs_read_inline_page(inode, page);
		if (ret < 0)
			goto out_up_read;
	}

	ret = 1;
	handle = NULL;
out_up_read:
	up_read(&MOCKFS_I(inode)->xattr_sem);
out:
	if (handle)
		mockfs_journal_stop(handle);
	brelse(iloc.bh);
	return ret;
convert:
	return mockfs_convert_inline_data_to_extent(mapping,
						  inode, flags);
}

int mockfs_write_inline_data_end(struct inode *inode, loff_t pos, unsigned len,
			       unsigned copied, struct page *page)
{
	int ret;
	void *kaddr;
	struct mockfs_iloc iloc;

	if (unlikely(copied < len)) {
		if (!PageUptodate(page)) {
			copied = 0;
			goto out;
		}
	}

	ret = mockfs_get_inode_loc(inode, &iloc);
	if (ret) {
		mockfs_std_error(inode->i_sb, ret);
		copied = 0;
		goto out;
	}

	down_write(&MOCKFS_I(inode)->xattr_sem);
	BUG_ON(!mockfs_has_inline_data(inode));

	kaddr = kmap_atomic(page);
	mockfs_write_inline_data(inode, &iloc, kaddr, pos, len);
	kunmap_atomic(kaddr);
	SetPageUptodate(page);
	/* clear page dirty so that writepages wouldn't work for us. */
	ClearPageDirty(page);

	up_write(&MOCKFS_I(inode)->xattr_sem);
	brelse(iloc.bh);
out:
	return copied;
}

struct buffer_head *
mockfs_journalled_write_inline_data(struct inode *inode,
				  unsigned len,
				  struct page *page)
{
	int ret;
	void *kaddr;
	struct mockfs_iloc iloc;

	ret = mockfs_get_inode_loc(inode, &iloc);
	if (ret) {
		mockfs_std_error(inode->i_sb, ret);
		return NULL;
	}

	down_write(&MOCKFS_I(inode)->xattr_sem);
	kaddr = kmap_atomic(page);
	mockfs_write_inline_data(inode, &iloc, kaddr, 0, len);
	kunmap_atomic(kaddr);
	up_write(&MOCKFS_I(inode)->xattr_sem);

	return iloc.bh;
}

/*
 * Try to make the page cache and handle ready for the inline data case.
 * We can call this function in 2 cases:
 * 1. The inode is created and the first write exceeds inline size. We can
 *    clear the inode state safely.
 * 2. The inode has inline data, then we need to read the data, make it
 *    update and dirty so that mockfs_da_writepages can handle it. We don't
 *    need to start the journal since the file's metatdata isn't changed now.
 */
static int mockfs_da_convert_inline_data_to_extent(struct address_space *mapping,
						 struct inode *inode,
						 unsigned flags,
						 void **fsdata)
{
	int ret = 0, inline_size;
	struct page *page;

	page = grab_cache_page_write_begin(mapping, 0, flags);
	if (!page)
		return -ENOMEM;

	down_read(&MOCKFS_I(inode)->xattr_sem);
	if (!mockfs_has_inline_data(inode)) {
		mockfs_clear_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA);
		goto out;
	}

	inline_size = mockfs_get_inline_size(inode);

	if (!PageUptodate(page)) {
		ret = mockfs_read_inline_page(inode, page);
		if (ret < 0)
			goto out;
	}

	ret = __block_write_begin(page, 0, inline_size,
				  mockfs_da_get_block_prep);
	if (ret) {
		up_read(&MOCKFS_I(inode)->xattr_sem);
		unlock_page(page);
		put_page(page);
		mockfs_truncate_failed_write(inode);
		return ret;
	}

	SetPageDirty(page);
	SetPageUptodate(page);
	mockfs_clear_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA);
	*fsdata = (void *)CONVERT_INLINE_DATA;

out:
	up_read(&MOCKFS_I(inode)->xattr_sem);
	if (page) {
		unlock_page(page);
		put_page(page);
	}
	return ret;
}

/*
 * Prepare the write for the inline data.
 * If the the data can be written into the inode, we just read
 * the page and make it uptodate, and start the journal.
 * Otherwise read the page, makes it dirty so that it can be
 * handle in writepages(the i_disksize update is left to the
 * normal mockfs_da_write_end).
 */
int mockfs_da_write_inline_data_begin(struct address_space *mapping,
				    struct inode *inode,
				    loff_t pos, unsigned len,
				    unsigned flags,
				    struct page **pagep,
				    void **fsdata)
{
	int ret, inline_size;
	handle_t *handle;
	struct page *page;
	struct mockfs_iloc iloc;
	int retries;

	ret = mockfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

retry_journal:
	handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out;
	}

	inline_size = mockfs_get_max_inline_size(inode);

	ret = -ENOSPC;
	if (inline_size >= pos + len) {
		ret = mockfs_prepare_inline_data(handle, inode, pos + len);
		if (ret && ret != -ENOSPC)
			goto out_journal;
	}

	/*
	 * We cannot recurse into the filesystem as the transaction
	 * is already started.
	 */
	flags |= AOP_FLAG_NOFS;

	if (ret == -ENOSPC) {
		ret = mockfs_da_convert_inline_data_to_extent(mapping,
							    inode,
							    flags,
							    fsdata);
		mockfs_journal_stop(handle);
		if (ret == -ENOSPC &&
		    mockfs_should_retry_alloc(inode->i_sb, &retries))
			goto retry_journal;
		goto out;
	}


	page = grab_cache_page_write_begin(mapping, 0, flags);
	if (!page) {
		ret = -ENOMEM;
		goto out_journal;
	}

	down_read(&MOCKFS_I(inode)->xattr_sem);
	if (!mockfs_has_inline_data(inode)) {
		ret = 0;
		goto out_release_page;
	}

	if (!PageUptodate(page)) {
		ret = mockfs_read_inline_page(inode, page);
		if (ret < 0)
			goto out_release_page;
	}

	up_read(&MOCKFS_I(inode)->xattr_sem);
	*pagep = page;
	brelse(iloc.bh);
	return 1;
out_release_page:
	up_read(&MOCKFS_I(inode)->xattr_sem);
	unlock_page(page);
	put_page(page);
out_journal:
	mockfs_journal_stop(handle);
out:
	brelse(iloc.bh);
	return ret;
}

int mockfs_da_write_inline_data_end(struct inode *inode, loff_t pos,
				  unsigned len, unsigned copied,
				  struct page *page)
{
	int i_size_changed = 0;

	copied = mockfs_write_inline_data_end(inode, pos, len, copied, page);

	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold i_mutex.
	 *
	 * But it's important to update i_size while still holding page lock:
	 * page writeout could otherwise come in and zero beyond i_size.
	 */
	if (pos+copied > inode->i_size) {
		i_size_write(inode, pos+copied);
		i_size_changed = 1;
	}
	unlock_page(page);
	put_page(page);

	/*
	 * Don't mark the inode dirty under page lock. First, it unnecessarily
	 * makes the holding time of page lock longer. Second, it forces lock
	 * ordering of page lock and transaction start for journaling
	 * filesystems.
	 */
	if (i_size_changed)
		mark_inode_dirty(inode);

	return copied;
}

#ifdef INLINE_DIR_DEBUG
void mockfs_show_inline_dir(struct inode *dir, struct buffer_head *bh,
			  void *inline_start, int inline_size)
{
	int offset;
	unsigned short de_len;
	struct mockfs_dir_entry_2 *de = inline_start;
	void *dlimit = inline_start + inline_size;

	trace_printk("inode %lu\n", dir->i_ino);
	offset = 0;
	while ((void *)de < dlimit) {
		de_len = mockfs_rec_len_from_disk(de->rec_len, inline_size);
		trace_printk("de: off %u rlen %u name %.*s nlen %u ino %u\n",
			     offset, de_len, de->name_len, de->name,
			     de->name_len, le32_to_cpu(de->inode));
		if (mockfs_check_dir_entry(dir, NULL, de, bh,
					 inline_start, inline_size, offset))
			BUG();

		offset += de_len;
		de = (struct mockfs_dir_entry_2 *) ((char *) de + de_len);
	}
}
#else
#define mockfs_show_inline_dir(dir, bh, inline_start, inline_size)
#endif

/*
 * Add a new entry into a inline dir.
 * It will return -ENOSPC if no space is available, and -EIO
 * and -EEXIST if directory entry already exists.
 */
static int mockfs_add_dirent_to_inline(handle_t *handle,
				     struct mockfs_filename *fname,
				     struct inode *dir,
				     struct inode *inode,
				     struct mockfs_iloc *iloc,
				     void *inline_start, int inline_size)
{
	int		err;
	struct mockfs_dir_entry_2 *de;

	err = mockfs_find_dest_de(dir, inode, iloc->bh, inline_start,
				inline_size, fname, &de);
	if (err)
		return err;

	BUFFER_TRACE(iloc->bh, "get_write_access");
	err = mockfs_journal_get_write_access(handle, iloc->bh);
	if (err)
		return err;
	mockfs_insert_dentry(dir, inode, de, inline_size, fname);

	mockfs_show_inline_dir(dir, iloc->bh, inline_start, inline_size);

	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 *
	 * XXX similarly, too many callers depend on
	 * mockfs_new_inode() setting the times, but error
	 * recovery deletes the inode, so the worst that can
	 * happen is that the times are slightly out of date
	 * and/or different from the directory change time.
	 */
	dir->i_mtime = dir->i_ctime = mockfs_current_time(dir);
	mockfs_update_dx_flag(dir);
	dir->i_version++;
	mockfs_mark_inode_dirty(handle, dir);
	return 1;
}

static void *mockfs_get_inline_xattr_pos(struct inode *inode,
				       struct mockfs_iloc *iloc)
{
	struct mockfs_xattr_entry *entry;
	struct mockfs_xattr_ibody_header *header;

	BUG_ON(!MOCKFS_I(inode)->i_inline_off);

	header = IHDR(inode, mockfs_raw_inode(iloc));
	entry = (struct mockfs_xattr_entry *)((void *)mockfs_raw_inode(iloc) +
					    MOCKFS_I(inode)->i_inline_off);

	return (void *)IFIRST(header) + le16_to_cpu(entry->e_value_offs);
}

/* Set the final de to cover the whole block. */
static void mockfs_update_final_de(void *de_buf, int old_size, int new_size)
{
	struct mockfs_dir_entry_2 *de, *prev_de;
	void *limit;
	int de_len;

	de = (struct mockfs_dir_entry_2 *)de_buf;
	if (old_size) {
		limit = de_buf + old_size;
		do {
			prev_de = de;
			de_len = mockfs_rec_len_from_disk(de->rec_len, old_size);
			de_buf += de_len;
			de = (struct mockfs_dir_entry_2 *)de_buf;
		} while (de_buf < limit);

		prev_de->rec_len = mockfs_rec_len_to_disk(de_len + new_size -
							old_size, new_size);
	} else {
		/* this is just created, so create an empty entry. */
		de->inode = 0;
		de->rec_len = mockfs_rec_len_to_disk(new_size, new_size);
	}
}

static int mockfs_update_inline_dir(handle_t *handle, struct inode *dir,
				  struct mockfs_iloc *iloc)
{
	int ret;
	int old_size = MOCKFS_I(dir)->i_inline_size - MOCKFS_MIN_INLINE_DATA_SIZE;
	int new_size = get_max_inline_xattr_value_size(dir, iloc);

	if (new_size - old_size <= MOCKFS_DIR_REC_LEN(1))
		return -ENOSPC;

	ret = mockfs_update_inline_data(handle, dir,
				      new_size + MOCKFS_MIN_INLINE_DATA_SIZE);
	if (ret)
		return ret;

	mockfs_update_final_de(mockfs_get_inline_xattr_pos(dir, iloc), old_size,
			     MOCKFS_I(dir)->i_inline_size -
						MOCKFS_MIN_INLINE_DATA_SIZE);
	dir->i_size = MOCKFS_I(dir)->i_disksize = MOCKFS_I(dir)->i_inline_size;
	return 0;
}

static void mockfs_restore_inline_data(handle_t *handle, struct inode *inode,
				     struct mockfs_iloc *iloc,
				     void *buf, int inline_size)
{
	mockfs_create_inline_data(handle, inode, inline_size);
	mockfs_write_inline_data(inode, iloc, buf, 0, inline_size);
	mockfs_set_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA);
}

static int mockfs_finish_convert_inline_dir(handle_t *handle,
					  struct inode *inode,
					  struct buffer_head *dir_block,
					  void *buf,
					  int inline_size)
{
	int err, csum_size = 0, header_size = 0;
	struct mockfs_dir_entry_2 *de;
	struct mockfs_dir_entry_tail *t;
	void *target = dir_block->b_data;

	/*
	 * First create "." and ".." and then copy the dir information
	 * back to the block.
	 */
	de = (struct mockfs_dir_entry_2 *)target;
	de = mockfs_init_dot_dotdot(inode, de,
		inode->i_sb->s_blocksize, csum_size,
		le32_to_cpu(((struct mockfs_dir_entry_2 *)buf)->inode), 1);
	header_size = (void *)de - target;

	memcpy((void *)de, buf + MOCKFS_INLINE_DOTDOT_SIZE,
		inline_size - MOCKFS_INLINE_DOTDOT_SIZE);

	if (mockfs_has_metadata_csum(inode->i_sb))
		csum_size = sizeof(struct mockfs_dir_entry_tail);

	inode->i_size = inode->i_sb->s_blocksize;
	i_size_write(inode, inode->i_sb->s_blocksize);
	MOCKFS_I(inode)->i_disksize = inode->i_sb->s_blocksize;
	mockfs_update_final_de(dir_block->b_data,
			inline_size - MOCKFS_INLINE_DOTDOT_SIZE + header_size,
			inode->i_sb->s_blocksize - csum_size);

	if (csum_size) {
		t = MOCKFS_DIRENT_TAIL(dir_block->b_data,
				     inode->i_sb->s_blocksize);
		initialize_dirent_tail(t, inode->i_sb->s_blocksize);
	}
	set_buffer_uptodate(dir_block);
	err = mockfs_handle_dirty_dirent_node(handle, inode, dir_block);
	if (err)
		goto out;
	set_buffer_verified(dir_block);
out:
	return err;
}

static int mockfs_convert_inline_data_nolock(handle_t *handle,
					   struct inode *inode,
					   struct mockfs_iloc *iloc)
{
	int error;
	void *buf = NULL;
	struct buffer_head *data_bh = NULL;
	struct mockfs_map_blocks map;
	int inline_size;

	inline_size = mockfs_get_inline_size(inode);
	buf = kmalloc(inline_size, GFP_NOFS);
	if (!buf) {
		error = -ENOMEM;
		goto out;
	}

	error = mockfs_read_inline_data(inode, buf, inline_size, iloc);
	if (error < 0)
		goto out;

	/*
	 * Make sure the inline directory entries pass checks before we try to
	 * convert them, so that we avoid touching stuff that needs fsck.
	 */
	if (S_ISDIR(inode->i_mode)) {
		error = mockfs_check_all_de(inode, iloc->bh,
					buf + MOCKFS_INLINE_DOTDOT_SIZE,
					inline_size - MOCKFS_INLINE_DOTDOT_SIZE);
		if (error)
			goto out;
	}

	error = mockfs_destroy_inline_data_nolock(handle, inode);
	if (error)
		goto out;

	map.m_lblk = 0;
	map.m_len = 1;
	map.m_flags = 0;
	error = mockfs_map_blocks(handle, inode, &map, MOCKFS_GET_BLOCKS_CREATE);
	if (error < 0)
		goto out_restore;
	if (!(map.m_flags & MOCKFS_MAP_MAPPED)) {
		error = -EIO;
		goto out_restore;
	}

	data_bh = sb_getblk(inode->i_sb, map.m_pblk);
	if (!data_bh) {
		error = -ENOMEM;
		goto out_restore;
	}

	lock_buffer(data_bh);
	error = mockfs_journal_get_create_access(handle, data_bh);
	if (error) {
		unlock_buffer(data_bh);
		error = -EIO;
		goto out_restore;
	}
	memset(data_bh->b_data, 0, inode->i_sb->s_blocksize);

	if (!S_ISDIR(inode->i_mode)) {
		memcpy(data_bh->b_data, buf, inline_size);
		set_buffer_uptodate(data_bh);
		error = mockfs_handle_dirty_metadata(handle,
						   inode, data_bh);
	} else {
		error = mockfs_finish_convert_inline_dir(handle, inode, data_bh,
						       buf, inline_size);
	}

	unlock_buffer(data_bh);
out_restore:
	if (error)
		mockfs_restore_inline_data(handle, inode, iloc, buf, inline_size);

out:
	brelse(data_bh);
	kfree(buf);
	return error;
}

/*
 * Try to add the new entry to the inline data.
 * If succeeds, return 0. If not, extended the inline dir and copied data to
 * the new created block.
 */
int mockfs_try_add_inline_entry(handle_t *handle, struct mockfs_filename *fname,
			      struct inode *dir, struct inode *inode)
{
	int ret, inline_size;
	void *inline_start;
	struct mockfs_iloc iloc;

	ret = mockfs_get_inode_loc(dir, &iloc);
	if (ret)
		return ret;

	down_write(&MOCKFS_I(dir)->xattr_sem);
	if (!mockfs_has_inline_data(dir))
		goto out;

	inline_start = (void *)mockfs_raw_inode(&iloc)->i_block +
						 MOCKFS_INLINE_DOTDOT_SIZE;
	inline_size = MOCKFS_MIN_INLINE_DATA_SIZE - MOCKFS_INLINE_DOTDOT_SIZE;

	ret = mockfs_add_dirent_to_inline(handle, fname, dir, inode, &iloc,
					inline_start, inline_size);
	if (ret != -ENOSPC)
		goto out;

	/* check whether it can be inserted to inline xattr space. */
	inline_size = MOCKFS_I(dir)->i_inline_size -
			MOCKFS_MIN_INLINE_DATA_SIZE;
	if (!inline_size) {
		/* Try to use the xattr space.*/
		ret = mockfs_update_inline_dir(handle, dir, &iloc);
		if (ret && ret != -ENOSPC)
			goto out;

		inline_size = MOCKFS_I(dir)->i_inline_size -
				MOCKFS_MIN_INLINE_DATA_SIZE;
	}

	if (inline_size) {
		inline_start = mockfs_get_inline_xattr_pos(dir, &iloc);

		ret = mockfs_add_dirent_to_inline(handle, fname, dir,
						inode, &iloc, inline_start,
						inline_size);

		if (ret != -ENOSPC)
			goto out;
	}

	/*
	 * The inline space is filled up, so create a new block for it.
	 * As the extent tree will be created, we have to save the inline
	 * dir first.
	 */
	ret = mockfs_convert_inline_data_nolock(handle, dir, &iloc);

out:
	mockfs_mark_inode_dirty(handle, dir);
	up_write(&MOCKFS_I(dir)->xattr_sem);
	brelse(iloc.bh);
	return ret;
}

/*
 * This function fills a red-black tree with information from an
 * inlined dir.  It returns the number directory entries loaded
 * into the tree.  If there is an error it is returned in err.
 */
int htree_inlinedir_to_tree(struct file *dir_file,
			    struct inode *dir, mockfs_lblk_t block,
			    struct dx_hash_info *hinfo,
			    __u32 start_hash, __u32 start_minor_hash,
			    int *has_inline_data)
{
	int err = 0, count = 0;
	unsigned int parent_ino;
	int pos;
	struct mockfs_dir_entry_2 *de;
	struct inode *inode = file_inode(dir_file);
	int ret, inline_size = 0;
	struct mockfs_iloc iloc;
	void *dir_buf = NULL;
	struct mockfs_dir_entry_2 fake;
	struct mockfs_str tmp_str;

	ret = mockfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	down_read(&MOCKFS_I(inode)->xattr_sem);
	if (!mockfs_has_inline_data(inode)) {
		up_read(&MOCKFS_I(inode)->xattr_sem);
		*has_inline_data = 0;
		goto out;
	}

	inline_size = mockfs_get_inline_size(inode);
	dir_buf = kmalloc(inline_size, GFP_NOFS);
	if (!dir_buf) {
		ret = -ENOMEM;
		up_read(&MOCKFS_I(inode)->xattr_sem);
		goto out;
	}

	ret = mockfs_read_inline_data(inode, dir_buf, inline_size, &iloc);
	up_read(&MOCKFS_I(inode)->xattr_sem);
	if (ret < 0)
		goto out;

	pos = 0;
	parent_ino = le32_to_cpu(((struct mockfs_dir_entry_2 *)dir_buf)->inode);
	while (pos < inline_size) {
		/*
		 * As inlined dir doesn't store any information about '.' and
		 * only the inode number of '..' is stored, we have to handle
		 * them differently.
		 */
		if (pos == 0) {
			fake.inode = cpu_to_le32(inode->i_ino);
			fake.name_len = 1;
			strcpy(fake.name, ".");
			fake.rec_len = mockfs_rec_len_to_disk(
						MOCKFS_DIR_REC_LEN(fake.name_len),
						inline_size);
			mockfs_set_de_type(inode->i_sb, &fake, S_IFDIR);
			de = &fake;
			pos = MOCKFS_INLINE_DOTDOT_OFFSET;
		} else if (pos == MOCKFS_INLINE_DOTDOT_OFFSET) {
			fake.inode = cpu_to_le32(parent_ino);
			fake.name_len = 2;
			strcpy(fake.name, "..");
			fake.rec_len = mockfs_rec_len_to_disk(
						MOCKFS_DIR_REC_LEN(fake.name_len),
						inline_size);
			mockfs_set_de_type(inode->i_sb, &fake, S_IFDIR);
			de = &fake;
			pos = MOCKFS_INLINE_DOTDOT_SIZE;
		} else {
			de = (struct mockfs_dir_entry_2 *)(dir_buf + pos);
			pos += mockfs_rec_len_from_disk(de->rec_len, inline_size);
			if (mockfs_check_dir_entry(inode, dir_file, de,
					 iloc.bh, dir_buf,
					 inline_size, pos)) {
				ret = count;
				goto out;
			}
		}

		mockfsfs_dirhash(de->name, de->name_len, hinfo);
		if ((hinfo->hash < start_hash) ||
		    ((hinfo->hash == start_hash) &&
		     (hinfo->minor_hash < start_minor_hash)))
			continue;
		if (de->inode == 0)
			continue;
		tmp_str.name = de->name;
		tmp_str.len = de->name_len;
		err = mockfs_htree_store_dirent(dir_file, hinfo->hash,
					      hinfo->minor_hash, de, &tmp_str);
		if (err) {
			count = err;
			goto out;
		}
		count++;
	}
	ret = count;
out:
	kfree(dir_buf);
	brelse(iloc.bh);
	return ret;
}

/*
 * So this function is called when the volume is mkfsed with
 * dir_index disabled. In order to keep f_pos persistent
 * after we convert from an inlined dir to a blocked based,
 * we just pretend that we are a normal dir and return the
 * offset as if '.' and '..' really take place.
 *
 */
int mockfs_read_inline_dir(struct file *file,
			 struct dir_context *ctx,
			 int *has_inline_data)
{
	unsigned int offset, parent_ino;
	int i;
	struct mockfs_dir_entry_2 *de;
	struct super_block *sb;
	struct inode *inode = file_inode(file);
	int ret, inline_size = 0;
	struct mockfs_iloc iloc;
	void *dir_buf = NULL;
	int dotdot_offset, dotdot_size, extra_offset, extra_size;

	ret = mockfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	down_read(&MOCKFS_I(inode)->xattr_sem);
	if (!mockfs_has_inline_data(inode)) {
		up_read(&MOCKFS_I(inode)->xattr_sem);
		*has_inline_data = 0;
		goto out;
	}

	inline_size = mockfs_get_inline_size(inode);
	dir_buf = kmalloc(inline_size, GFP_NOFS);
	if (!dir_buf) {
		ret = -ENOMEM;
		up_read(&MOCKFS_I(inode)->xattr_sem);
		goto out;
	}

	ret = mockfs_read_inline_data(inode, dir_buf, inline_size, &iloc);
	up_read(&MOCKFS_I(inode)->xattr_sem);
	if (ret < 0)
		goto out;

	ret = 0;
	sb = inode->i_sb;
	parent_ino = le32_to_cpu(((struct mockfs_dir_entry_2 *)dir_buf)->inode);
	offset = ctx->pos;

	/*
	 * dotdot_offset and dotdot_size is the real offset and
	 * size for ".." and "." if the dir is block based while
	 * the real size for them are only MOCKFS_INLINE_DOTDOT_SIZE.
	 * So we will use extra_offset and extra_size to indicate them
	 * during the inline dir iteration.
	 */
	dotdot_offset = MOCKFS_DIR_REC_LEN(1);
	dotdot_size = dotdot_offset + MOCKFS_DIR_REC_LEN(2);
	extra_offset = dotdot_size - MOCKFS_INLINE_DOTDOT_SIZE;
	extra_size = extra_offset + inline_size;

	/*
	 * If the version has changed since the last call to
	 * readdir(2), then we might be pointing to an invalid
	 * dirent right now.  Scan from the start of the inline
	 * dir to make sure.
	 */
	if (file->f_version != inode->i_version) {
		for (i = 0; i < extra_size && i < offset;) {
			/*
			 * "." is with offset 0 and
			 * ".." is dotdot_offset.
			 */
			if (!i) {
				i = dotdot_offset;
				continue;
			} else if (i == dotdot_offset) {
				i = dotdot_size;
				continue;
			}
			/* for other entry, the real offset in
			 * the buf has to be tuned accordingly.
			 */
			de = (struct mockfs_dir_entry_2 *)
				(dir_buf + i - extra_offset);
			/* It's too expensive to do a full
			 * dirent test each time round this
			 * loop, but we do have to test at
			 * least that it is non-zero.  A
			 * failure will be detected in the
			 * dirent test below. */
			if (mockfs_rec_len_from_disk(de->rec_len, extra_size)
				< MOCKFS_DIR_REC_LEN(1))
				break;
			i += mockfs_rec_len_from_disk(de->rec_len,
						    extra_size);
		}
		offset = i;
		ctx->pos = offset;
		file->f_version = inode->i_version;
	}

	while (ctx->pos < extra_size) {
		if (ctx->pos == 0) {
			if (!dir_emit(ctx, ".", 1, inode->i_ino, DT_DIR))
				goto out;
			ctx->pos = dotdot_offset;
			continue;
		}

		if (ctx->pos == dotdot_offset) {
			if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR))
				goto out;
			ctx->pos = dotdot_size;
			continue;
		}

		de = (struct mockfs_dir_entry_2 *)
			(dir_buf + ctx->pos - extra_offset);
		if (mockfs_check_dir_entry(inode, file, de, iloc.bh, dir_buf,
					 extra_size, ctx->pos))
			goto out;
		if (le32_to_cpu(de->inode)) {
			if (!dir_emit(ctx, de->name, de->name_len,
				      le32_to_cpu(de->inode),
				      get_dtype(sb, de->file_type)))
				goto out;
		}
		ctx->pos += mockfs_rec_len_from_disk(de->rec_len, extra_size);
	}
out:
	kfree(dir_buf);
	brelse(iloc.bh);
	return ret;
}

struct buffer_head *mockfs_get_first_inline_block(struct inode *inode,
					struct mockfs_dir_entry_2 **parent_de,
					int *retval)
{
	struct mockfs_iloc iloc;

	*retval = mockfs_get_inode_loc(inode, &iloc);
	if (*retval)
		return NULL;

	*parent_de = (struct mockfs_dir_entry_2 *)mockfs_raw_inode(&iloc)->i_block;

	return iloc.bh;
}

/*
 * Try to create the inline data for the new dir.
 * If it succeeds, return 0, otherwise return the error.
 * In case of ENOSPC, the caller should create the normal disk layout dir.
 */
int mockfs_try_create_inline_dir(handle_t *handle, struct inode *parent,
			       struct inode *inode)
{
	int ret, inline_size = MOCKFS_MIN_INLINE_DATA_SIZE;
	struct mockfs_iloc iloc;
	struct mockfs_dir_entry_2 *de;

	ret = mockfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	ret = mockfs_prepare_inline_data(handle, inode, inline_size);
	if (ret)
		goto out;

	/*
	 * For inline dir, we only save the inode information for the ".."
	 * and create a fake dentry to cover the left space.
	 */
	de = (struct mockfs_dir_entry_2 *)mockfs_raw_inode(&iloc)->i_block;
	de->inode = cpu_to_le32(parent->i_ino);
	de = (struct mockfs_dir_entry_2 *)((void *)de + MOCKFS_INLINE_DOTDOT_SIZE);
	de->inode = 0;
	de->rec_len = mockfs_rec_len_to_disk(
				inline_size - MOCKFS_INLINE_DOTDOT_SIZE,
				inline_size);
	set_nlink(inode, 2);
	inode->i_size = MOCKFS_I(inode)->i_disksize = inline_size;
out:
	brelse(iloc.bh);
	return ret;
}

struct buffer_head *mockfs_find_inline_entry(struct inode *dir,
					struct mockfs_filename *fname,
					const struct qstr *d_name,
					struct mockfs_dir_entry_2 **res_dir,
					int *has_inline_data)
{
	int ret;
	struct mockfs_iloc iloc;
	void *inline_start;
	int inline_size;

	if (mockfs_get_inode_loc(dir, &iloc))
		return NULL;

	down_read(&MOCKFS_I(dir)->xattr_sem);
	if (!mockfs_has_inline_data(dir)) {
		*has_inline_data = 0;
		goto out;
	}

	inline_start = (void *)mockfs_raw_inode(&iloc)->i_block +
						MOCKFS_INLINE_DOTDOT_SIZE;
	inline_size = MOCKFS_MIN_INLINE_DATA_SIZE - MOCKFS_INLINE_DOTDOT_SIZE;
	ret = mockfs_search_dir(iloc.bh, inline_start, inline_size,
			      dir, fname, d_name, 0, res_dir);
	if (ret == 1)
		goto out_find;
	if (ret < 0)
		goto out;

	if (mockfs_get_inline_size(dir) == MOCKFS_MIN_INLINE_DATA_SIZE)
		goto out;

	inline_start = mockfs_get_inline_xattr_pos(dir, &iloc);
	inline_size = mockfs_get_inline_size(dir) - MOCKFS_MIN_INLINE_DATA_SIZE;

	ret = mockfs_search_dir(iloc.bh, inline_start, inline_size,
			      dir, fname, d_name, 0, res_dir);
	if (ret == 1)
		goto out_find;

out:
	brelse(iloc.bh);
	iloc.bh = NULL;
out_find:
	up_read(&MOCKFS_I(dir)->xattr_sem);
	return iloc.bh;
}

int mockfs_delete_inline_entry(handle_t *handle,
			     struct inode *dir,
			     struct mockfs_dir_entry_2 *de_del,
			     struct buffer_head *bh,
			     int *has_inline_data)
{
	int err, inline_size;
	struct mockfs_iloc iloc;
	void *inline_start;

	err = mockfs_get_inode_loc(dir, &iloc);
	if (err)
		return err;

	down_write(&MOCKFS_I(dir)->xattr_sem);
	if (!mockfs_has_inline_data(dir)) {
		*has_inline_data = 0;
		goto out;
	}

	if ((void *)de_del - ((void *)mockfs_raw_inode(&iloc)->i_block) <
		MOCKFS_MIN_INLINE_DATA_SIZE) {
		inline_start = (void *)mockfs_raw_inode(&iloc)->i_block +
					MOCKFS_INLINE_DOTDOT_SIZE;
		inline_size = MOCKFS_MIN_INLINE_DATA_SIZE -
				MOCKFS_INLINE_DOTDOT_SIZE;
	} else {
		inline_start = mockfs_get_inline_xattr_pos(dir, &iloc);
		inline_size = mockfs_get_inline_size(dir) -
				MOCKFS_MIN_INLINE_DATA_SIZE;
	}

	BUFFER_TRACE(bh, "get_write_access");
	err = mockfs_journal_get_write_access(handle, bh);
	if (err)
		goto out;

	err = mockfs_generic_delete_entry(handle, dir, de_del, bh,
					inline_start, inline_size, 0);
	if (err)
		goto out;

	err = mockfs_mark_inode_dirty(handle, dir);
	if (unlikely(err))
		goto out;

	mockfs_show_inline_dir(dir, iloc.bh, inline_start, inline_size);
out:
	up_write(&MOCKFS_I(dir)->xattr_sem);
	brelse(iloc.bh);
	if (err != -ENOENT)
		mockfs_std_error(dir->i_sb, err);
	return err;
}

/*
 * Get the inline dentry at offset.
 */
static inline struct mockfs_dir_entry_2 *
mockfs_get_inline_entry(struct inode *inode,
		      struct mockfs_iloc *iloc,
		      unsigned int offset,
		      void **inline_start,
		      int *inline_size)
{
	void *inline_pos;

	BUG_ON(offset > mockfs_get_inline_size(inode));

	if (offset < MOCKFS_MIN_INLINE_DATA_SIZE) {
		inline_pos = (void *)mockfs_raw_inode(iloc)->i_block;
		*inline_size = MOCKFS_MIN_INLINE_DATA_SIZE;
	} else {
		inline_pos = mockfs_get_inline_xattr_pos(inode, iloc);
		offset -= MOCKFS_MIN_INLINE_DATA_SIZE;
		*inline_size = mockfs_get_inline_size(inode) -
				MOCKFS_MIN_INLINE_DATA_SIZE;
	}

	if (inline_start)
		*inline_start = inline_pos;
	return (struct mockfs_dir_entry_2 *)(inline_pos + offset);
}

int empty_inline_dir(struct inode *dir, int *has_inline_data)
{
	int err, inline_size;
	struct mockfs_iloc iloc;
	void *inline_pos;
	unsigned int offset;
	struct mockfs_dir_entry_2 *de;
	int ret = 1;

	err = mockfs_get_inode_loc(dir, &iloc);
	if (err) {
		MOCKFS_ERROR_INODE(dir, "error %d getting inode %lu block",
				 err, dir->i_ino);
		return 1;
	}

	down_read(&MOCKFS_I(dir)->xattr_sem);
	if (!mockfs_has_inline_data(dir)) {
		*has_inline_data = 0;
		goto out;
	}

	de = (struct mockfs_dir_entry_2 *)mockfs_raw_inode(&iloc)->i_block;
	if (!le32_to_cpu(de->inode)) {
		mockfs_warning(dir->i_sb,
			     "bad inline directory (dir #%lu) - no `..'",
			     dir->i_ino);
		ret = 1;
		goto out;
	}

	offset = MOCKFS_INLINE_DOTDOT_SIZE;
	while (offset < dir->i_size) {
		de = mockfs_get_inline_entry(dir, &iloc, offset,
					   &inline_pos, &inline_size);
		if (mockfs_check_dir_entry(dir, NULL, de,
					 iloc.bh, inline_pos,
					 inline_size, offset)) {
			mockfs_warning(dir->i_sb,
				     "bad inline directory (dir #%lu) - "
				     "inode %u, rec_len %u, name_len %d"
				     "inline size %d\n",
				     dir->i_ino, le32_to_cpu(de->inode),
				     le16_to_cpu(de->rec_len), de->name_len,
				     inline_size);
			ret = 1;
			goto out;
		}
		if (le32_to_cpu(de->inode)) {
			ret = 0;
			goto out;
		}
		offset += mockfs_rec_len_from_disk(de->rec_len, inline_size);
	}

out:
	up_read(&MOCKFS_I(dir)->xattr_sem);
	brelse(iloc.bh);
	return ret;
}

int mockfs_destroy_inline_data(handle_t *handle, struct inode *inode)
{
	int ret;

	down_write(&MOCKFS_I(inode)->xattr_sem);
	ret = mockfs_destroy_inline_data_nolock(handle, inode);
	up_write(&MOCKFS_I(inode)->xattr_sem);

	return ret;
}

int mockfs_inline_data_fiemap(struct inode *inode,
			    struct fiemap_extent_info *fieinfo,
			    int *has_inline, __u64 start, __u64 len)
{
	__u64 physical = 0;
	__u64 inline_len;
	__u32 flags = FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_NOT_ALIGNED |
		FIEMAP_EXTENT_LAST;
	int error = 0;
	struct mockfs_iloc iloc;

	down_read(&MOCKFS_I(inode)->xattr_sem);
	if (!mockfs_has_inline_data(inode)) {
		*has_inline = 0;
		goto out;
	}
	inline_len = min_t(size_t, mockfs_get_inline_size(inode),
			   i_size_read(inode));
	if (start >= inline_len)
		goto out;
	if (start + len < inline_len)
		inline_len = start + len;
	inline_len -= start;

	error = mockfs_get_inode_loc(inode, &iloc);
	if (error)
		goto out;

	physical = (__u64)iloc.bh->b_blocknr << inode->i_sb->s_blocksize_bits;
	physical += (char *)mockfs_raw_inode(&iloc) - iloc.bh->b_data;
	physical += offsetof(struct mockfs_inode, i_block);

	if (physical)
		error = fiemap_fill_next_extent(fieinfo, start, physical,
						inline_len, flags);
	brelse(iloc.bh);
out:
	up_read(&MOCKFS_I(inode)->xattr_sem);
	return (error < 0 ? error : 0);
}

/*
 * Called during xattr set, and if we can sparse space 'needed',
 * just create the extent tree evict the data to the outer block.
 *
 * We use jbd2 instead of page cache to move data to the 1st block
 * so that the whole transaction can be committed as a whole and
 * the data isn't lost because of the delayed page cache write.
 */
int mockfs_try_to_evict_inline_data(handle_t *handle,
				  struct inode *inode,
				  int needed)
{
	int error;
	struct mockfs_xattr_entry *entry;
	struct mockfs_inode *raw_inode;
	struct mockfs_iloc iloc;

	error = mockfs_get_inode_loc(inode, &iloc);
	if (error)
		return error;

	raw_inode = mockfs_raw_inode(&iloc);
	entry = (struct mockfs_xattr_entry *)((void *)raw_inode +
					    MOCKFS_I(inode)->i_inline_off);
	if (MOCKFS_XATTR_LEN(entry->e_name_len) +
	    MOCKFS_XATTR_SIZE(le32_to_cpu(entry->e_value_size)) < needed) {
		error = -ENOSPC;
		goto out;
	}

	error = mockfs_convert_inline_data_nolock(handle, inode, &iloc);
out:
	brelse(iloc.bh);
	return error;
}

void mockfs_inline_data_truncate(struct inode *inode, int *has_inline)
{
	handle_t *handle;
	int inline_size, value_len, needed_blocks;
	size_t i_size;
	void *value = NULL;
	struct mockfs_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct mockfs_xattr_info i = {
		.name_index = MOCKFS_XATTR_INDEX_SYSTEM,
		.name = MOCKFS_XATTR_SYSTEM_DATA,
	};


	needed_blocks = mockfs_writepage_trans_blocks(inode);
	handle = mockfs_journal_start(inode, MOCKFS_HT_INODE, needed_blocks);
	if (IS_ERR(handle))
		return;

	down_write(&MOCKFS_I(inode)->xattr_sem);
	if (!mockfs_has_inline_data(inode)) {
		*has_inline = 0;
		mockfs_journal_stop(handle);
		return;
	}

	if (mockfs_orphan_add(handle, inode))
		goto out;

	if (mockfs_get_inode_loc(inode, &is.iloc))
		goto out;

	down_write(&MOCKFS_I(inode)->i_data_sem);
	i_size = inode->i_size;
	inline_size = mockfs_get_inline_size(inode);
	MOCKFS_I(inode)->i_disksize = i_size;

	if (i_size < inline_size) {
		/* Clear the content in the xattr space. */
		if (inline_size > MOCKFS_MIN_INLINE_DATA_SIZE) {
			if (mockfs_xattr_ibody_find(inode, &i, &is))
				goto out_error;

			BUG_ON(is.s.not_found);

			value_len = le32_to_cpu(is.s.here->e_value_size);
			value = kmalloc(value_len, GFP_NOFS);
			if (!value)
				goto out_error;

			if (mockfs_xattr_ibody_get(inode, i.name_index, i.name,
						value, value_len))
				goto out_error;

			i.value = value;
			i.value_len = i_size > MOCKFS_MIN_INLINE_DATA_SIZE ?
					i_size - MOCKFS_MIN_INLINE_DATA_SIZE : 0;
			if (mockfs_xattr_ibody_inline_set(handle, inode, &i, &is))
				goto out_error;
		}

		/* Clear the content within i_blocks. */
		if (i_size < MOCKFS_MIN_INLINE_DATA_SIZE) {
			void *p = (void *) mockfs_raw_inode(&is.iloc)->i_block;
			memset(p + i_size, 0,
			       MOCKFS_MIN_INLINE_DATA_SIZE - i_size);
		}

		MOCKFS_I(inode)->i_inline_size = i_size <
					MOCKFS_MIN_INLINE_DATA_SIZE ?
					MOCKFS_MIN_INLINE_DATA_SIZE : i_size;
	}

out_error:
	up_write(&MOCKFS_I(inode)->i_data_sem);
out:
	brelse(is.iloc.bh);
	up_write(&MOCKFS_I(inode)->xattr_sem);
	kfree(value);
	if (inode->i_nlink)
		mockfs_orphan_del(handle, inode);

	inode->i_mtime = inode->i_ctime = mockfs_current_time(inode);
	mockfs_mark_inode_dirty(handle, inode);
	if (IS_SYNC(inode))
		mockfs_handle_sync(handle);

	mockfs_journal_stop(handle);
	return;
}

int mockfs_convert_inline_data(struct inode *inode)
{
	int error, needed_blocks;
	handle_t *handle;
	struct mockfs_iloc iloc;

	if (!mockfs_has_inline_data(inode)) {
		mockfs_clear_inode_state(inode, MOCKFS_STATE_MAY_INLINE_DATA);
		return 0;
	}

	needed_blocks = mockfs_writepage_trans_blocks(inode);

	iloc.bh = NULL;
	error = mockfs_get_inode_loc(inode, &iloc);
	if (error)
		return error;

	handle = mockfs_journal_start(inode, MOCKFS_HT_WRITE_PAGE, needed_blocks);
	if (IS_ERR(handle)) {
		error = PTR_ERR(handle);
		goto out_free;
	}

	down_write(&MOCKFS_I(inode)->xattr_sem);
	if (!mockfs_has_inline_data(inode)) {
		up_write(&MOCKFS_I(inode)->xattr_sem);
		goto out;
	}

	error = mockfs_convert_inline_data_nolock(handle, inode, &iloc);
	up_write(&MOCKFS_I(inode)->xattr_sem);
out:
	mockfs_journal_stop(handle);
out_free:
	brelse(iloc.bh);
	return error;
}
