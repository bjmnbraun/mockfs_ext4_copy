/*
 * linux/fs/mockfs/xattr_security.c
 * Handler for storing security labels as extended attributes.
 */

#include <linux/string.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/slab.h>
#include "mockfs_jbd2.h"
#include "mockfs.h"
#include "xattr.h"

static int
mockfs_xattr_security_get(const struct xattr_handler *handler,
			struct dentry *dentry, const char *name,
			void *buffer, size_t size)
{
	return mockfs_xattr_get(d_inode(dentry), MOCKFS_XATTR_INDEX_SECURITY,
			      name, buffer, size);
}

static int
mockfs_xattr_security_set(const struct xattr_handler *handler,
			struct dentry *dentry, const char *name,
			const void *value, size_t size, int flags)
{
	return mockfs_xattr_set(d_inode(dentry), MOCKFS_XATTR_INDEX_SECURITY,
			      name, value, size, flags);
}

static int
mockfs_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		void *fs_info)
{
	const struct xattr *xattr;
	handle_t *handle = fs_info;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = mockfs_xattr_set_handle(handle, inode,
					    MOCKFS_XATTR_INDEX_SECURITY,
					    xattr->name, xattr->value,
					    xattr->value_len, 0);
		if (err < 0)
			break;
	}
	return err;
}

int
mockfs_init_security(handle_t *handle, struct inode *inode, struct inode *dir,
		   const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					    &mockfs_initxattrs, handle);
}

const struct xattr_handler mockfs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= mockfs_xattr_security_get,
	.set	= mockfs_xattr_security_set,
};
