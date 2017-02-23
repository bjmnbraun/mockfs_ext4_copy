/*
 *  linux/fs/mockfs/symlink.c
 *
 * Only fast symlinks left here - the rest is done by generic code. AV, 1999
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  mockfs symlink handling code
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include "mockfs.h"
#include "xattr.h"

#ifdef CONFIG_MOCKFS_FS_ENCRYPTION
static const char *mockfs_encrypted_get_link(struct dentry *dentry,
					   struct inode *inode,
					   struct delayed_call *done)
{
	struct page *cpage = NULL;
	char *caddr, *paddr = NULL;
	struct mockfs_str cstr, pstr;
	struct mockfs_encrypted_symlink_data *sd;
	loff_t size = min_t(loff_t, i_size_read(inode), PAGE_SIZE - 1);
	int res;
	u32 plen, max_size = inode->i_sb->s_blocksize;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	res = mockfs_get_encryption_info(inode);
	if (res)
		return ERR_PTR(res);

	if (mockfs_inode_is_fast_symlink(inode)) {
		caddr = (char *) MOCKFS_I(inode)->i_data;
		max_size = sizeof(MOCKFS_I(inode)->i_data);
	} else {
		cpage = read_mapping_page(inode->i_mapping, 0, NULL);
		if (IS_ERR(cpage))
			return ERR_CAST(cpage);
		caddr = page_address(cpage);
		caddr[size] = 0;
	}

	/* Symlink is encrypted */
	sd = (struct mockfs_encrypted_symlink_data *)caddr;
	cstr.name = sd->encrypted_path;
	cstr.len  = le16_to_cpu(sd->len);
	if ((cstr.len +
	     sizeof(struct mockfs_encrypted_symlink_data) - 1) >
	    max_size) {
		/* Symlink data on the disk is corrupted */
		res = -EFSCORRUPTED;
		goto errout;
	}
	plen = (cstr.len < MOCKFS_FNAME_CRYPTO_DIGEST_SIZE*2) ?
		MOCKFS_FNAME_CRYPTO_DIGEST_SIZE*2 : cstr.len;
	paddr = kmalloc(plen + 1, GFP_NOFS);
	if (!paddr) {
		res = -ENOMEM;
		goto errout;
	}
	pstr.name = paddr;
	pstr.len = plen;
	res = _mockfs_fname_disk_to_usr(inode, NULL, &cstr, &pstr);
	if (res < 0)
		goto errout;
	/* Null-terminate the name */
	if (res <= plen)
		paddr[res] = '\0';
	if (cpage)
		put_page(cpage);
	set_delayed_call(done, kfree_link, paddr);
	return paddr;
errout:
	if (cpage)
		put_page(cpage);
	kfree(paddr);
	return ERR_PTR(res);
}

const struct inode_operations mockfs_encrypted_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.get_link	= mockfs_encrypted_get_link,
	.setattr	= mockfs_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= mockfs_listxattr,
	.removexattr	= generic_removexattr,
};
#endif

const struct inode_operations mockfs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.get_link	= page_get_link,
	.setattr	= mockfs_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= mockfs_listxattr,
	.removexattr	= generic_removexattr,
};

const struct inode_operations mockfs_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.get_link	= simple_get_link,
	.setattr	= mockfs_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= mockfs_listxattr,
	.removexattr	= generic_removexattr,
};
