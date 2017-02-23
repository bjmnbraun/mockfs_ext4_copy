/*
 * linux/fs/mockfs/xattr_trusted.c
 * Handler for trusted extended attributes.
 *
 * Copyright (C) 2003 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include "mockfs_jbd2.h"
#include "mockfs.h"
#include "xattr.h"

static bool
mockfs_xattr_trusted_list(struct dentry *dentry)
{
	return capable(CAP_SYS_ADMIN);
}

static int
mockfs_xattr_trusted_get(const struct xattr_handler *handler,
		       struct dentry *dentry, const char *name, void *buffer,
		       size_t size)
{
	return mockfs_xattr_get(d_inode(dentry), MOCKFS_XATTR_INDEX_TRUSTED,
			      name, buffer, size);
}

static int
mockfs_xattr_trusted_set(const struct xattr_handler *handler,
		       struct dentry *dentry, const char *name,
		       const void *value, size_t size, int flags)
{
	return mockfs_xattr_set(d_inode(dentry), MOCKFS_XATTR_INDEX_TRUSTED,
			      name, value, size, flags);
}

const struct xattr_handler mockfs_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= mockfs_xattr_trusted_list,
	.get	= mockfs_xattr_trusted_get,
	.set	= mockfs_xattr_trusted_set,
};
