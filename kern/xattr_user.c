/*
 * linux/fs/mockfs/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/fs.h>
#include "mockfs_jbd2.h"
#include "mockfs.h"
#include "xattr.h"

static bool
mockfs_xattr_user_list(struct dentry *dentry)
{
	return test_opt(dentry->d_sb, XATTR_USER);
}

static int
mockfs_xattr_user_get(const struct xattr_handler *handler,
		    struct dentry *dentry, const char *name,
		    void *buffer, size_t size)
{
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return mockfs_xattr_get(d_inode(dentry), MOCKFS_XATTR_INDEX_USER,
			      name, buffer, size);
}

static int
mockfs_xattr_user_set(const struct xattr_handler *handler,
		    struct dentry *dentry, const char *name,
		    const void *value, size_t size, int flags)
{
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return mockfs_xattr_set(d_inode(dentry), MOCKFS_XATTR_INDEX_USER,
			      name, value, size, flags);
}

const struct xattr_handler mockfs_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= mockfs_xattr_user_list,
	.get	= mockfs_xattr_user_get,
	.set	= mockfs_xattr_user_set,
};
