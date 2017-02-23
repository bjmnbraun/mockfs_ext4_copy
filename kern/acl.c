/*
 * linux/fs/mockfs/acl.c
 *
 * Copyright (C) 2001-2003 Andreas Gruenbacher, <agruen@suse.de>
 */

#include "mockfs_jbd2.h"
#include "mockfs.h"
#include "xattr.h"
#include "acl.h"

/*
 * Convert from filesystem to in-memory representation.
 */
static struct posix_acl *
mockfs_acl_from_disk(const void *value, size_t size)
{
	const char *end = (char *)value + size;
	int n, count;
	struct posix_acl *acl;

	if (!value)
		return NULL;
	if (size < sizeof(mockfs_acl_header))
		 return ERR_PTR(-EINVAL);
	if (((mockfs_acl_header *)value)->a_version !=
	    cpu_to_le32(MOCKFS_ACL_VERSION))
		return ERR_PTR(-EINVAL);
	value = (char *)value + sizeof(mockfs_acl_header);
	count = mockfs_acl_count(size);
	if (count < 0)
		return ERR_PTR(-EINVAL);
	if (count == 0)
		return NULL;
	acl = posix_acl_alloc(count, GFP_NOFS);
	if (!acl)
		return ERR_PTR(-ENOMEM);
	for (n = 0; n < count; n++) {
		mockfs_acl_entry *entry =
			(mockfs_acl_entry *)value;
		if ((char *)value + sizeof(mockfs_acl_entry_short) > end)
			goto fail;
		acl->a_entries[n].e_tag  = le16_to_cpu(entry->e_tag);
		acl->a_entries[n].e_perm = le16_to_cpu(entry->e_perm);

		switch (acl->a_entries[n].e_tag) {
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			value = (char *)value +
				sizeof(mockfs_acl_entry_short);
			break;

		case ACL_USER:
			value = (char *)value + sizeof(mockfs_acl_entry);
			if ((char *)value > end)
				goto fail;
			acl->a_entries[n].e_uid =
				make_kuid(&init_user_ns,
					  le32_to_cpu(entry->e_id));
			break;
		case ACL_GROUP:
			value = (char *)value + sizeof(mockfs_acl_entry);
			if ((char *)value > end)
				goto fail;
			acl->a_entries[n].e_gid =
				make_kgid(&init_user_ns,
					  le32_to_cpu(entry->e_id));
			break;

		default:
			goto fail;
		}
	}
	if (value != end)
		goto fail;
	return acl;

fail:
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}

/*
 * Convert from in-memory to filesystem representation.
 */
static void *
mockfs_acl_to_disk(const struct posix_acl *acl, size_t *size)
{
	mockfs_acl_header *ext_acl;
	char *e;
	size_t n;

	*size = mockfs_acl_size(acl->a_count);
	ext_acl = kmalloc(sizeof(mockfs_acl_header) + acl->a_count *
			sizeof(mockfs_acl_entry), GFP_NOFS);
	if (!ext_acl)
		return ERR_PTR(-ENOMEM);
	ext_acl->a_version = cpu_to_le32(MOCKFS_ACL_VERSION);
	e = (char *)ext_acl + sizeof(mockfs_acl_header);
	for (n = 0; n < acl->a_count; n++) {
		const struct posix_acl_entry *acl_e = &acl->a_entries[n];
		mockfs_acl_entry *entry = (mockfs_acl_entry *)e;
		entry->e_tag  = cpu_to_le16(acl_e->e_tag);
		entry->e_perm = cpu_to_le16(acl_e->e_perm);
		switch (acl_e->e_tag) {
		case ACL_USER:
			entry->e_id = cpu_to_le32(
				from_kuid(&init_user_ns, acl_e->e_uid));
			e += sizeof(mockfs_acl_entry);
			break;
		case ACL_GROUP:
			entry->e_id = cpu_to_le32(
				from_kgid(&init_user_ns, acl_e->e_gid));
			e += sizeof(mockfs_acl_entry);
			break;

		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			e += sizeof(mockfs_acl_entry_short);
			break;

		default:
			goto fail;
		}
	}
	return (char *)ext_acl;

fail:
	kfree(ext_acl);
	return ERR_PTR(-EINVAL);
}

/*
 * Inode operation get_posix_acl().
 *
 * inode->i_mutex: don't care
 */
struct posix_acl *
mockfs_get_acl(struct inode *inode, int type)
{
	int name_index;
	char *value = NULL;
	struct posix_acl *acl;
	int retval;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = MOCKFS_XATTR_INDEX_POSIX_ACL_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name_index = MOCKFS_XATTR_INDEX_POSIX_ACL_DEFAULT;
		break;
	default:
		BUG();
	}
	retval = mockfs_xattr_get(inode, name_index, "", NULL, 0);
	if (retval > 0) {
		value = kmalloc(retval, GFP_NOFS);
		if (!value)
			return ERR_PTR(-ENOMEM);
		retval = mockfs_xattr_get(inode, name_index, "", value, retval);
	}
	if (retval > 0)
		acl = mockfs_acl_from_disk(value, retval);
	else if (retval == -ENODATA || retval == -ENOSYS)
		acl = NULL;
	else
		acl = ERR_PTR(retval);
	kfree(value);

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	return acl;
}

/*
 * Set the access or default ACL of an inode.
 *
 * inode->i_mutex: down unless called from mockfs_new_inode
 */
static int
__mockfs_set_acl(handle_t *handle, struct inode *inode, int type,
	     struct posix_acl *acl)
{
	int name_index;
	void *value = NULL;
	size_t size = 0;
	int error;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = MOCKFS_XATTR_INDEX_POSIX_ACL_ACCESS;
		if (acl) {
			error = posix_acl_equiv_mode(acl, &inode->i_mode);
			if (error < 0)
				return error;
			else {
				inode->i_ctime = mockfs_current_time(inode);
				mockfs_mark_inode_dirty(handle, inode);
				if (error == 0)
					acl = NULL;
			}
		}
		break;

	case ACL_TYPE_DEFAULT:
		name_index = MOCKFS_XATTR_INDEX_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;

	default:
		return -EINVAL;
	}
	if (acl) {
		value = mockfs_acl_to_disk(acl, &size);
		if (IS_ERR(value))
			return (int)PTR_ERR(value);
	}

	error = mockfs_xattr_set_handle(handle, inode, name_index, "",
				      value, size, 0);

	kfree(value);
	if (!error)
		set_cached_acl(inode, type, acl);

	return error;
}

int
mockfs_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	handle_t *handle;
	int error, retries = 0;

retry:
	handle = mockfs_journal_start(inode, MOCKFS_HT_XATTR,
				    mockfs_jbd2_credits_xattr(inode));
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	error = __mockfs_set_acl(handle, inode, type, acl);
	mockfs_journal_stop(handle);
	if (error == -ENOSPC && mockfs_should_retry_alloc(inode->i_sb, &retries))
		goto retry;
	return error;
}

/*
 * Initialize the ACLs of a new inode. Called from mockfs_new_inode.
 *
 * dir->i_mutex: down
 * inode->i_mutex: up (access to inode is still exclusive)
 */
int
mockfs_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int error;

	error = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (error)
		return error;

	if (default_acl) {
		error = __mockfs_set_acl(handle, inode, ACL_TYPE_DEFAULT,
				       default_acl);
		posix_acl_release(default_acl);
	}
	if (acl) {
		if (!error)
			error = __mockfs_set_acl(handle, inode, ACL_TYPE_ACCESS,
					       acl);
		posix_acl_release(acl);
	}
	return error;
}
