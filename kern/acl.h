/*
  File: fs/mockfs/acl.h

  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#include <linux/posix_acl_xattr.h>

#define MOCKFS_ACL_VERSION	0x0001

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} mockfs_acl_entry;

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} mockfs_acl_entry_short;

typedef struct {
	__le32		a_version;
} mockfs_acl_header;

static inline size_t mockfs_acl_size(int count)
{
	if (count <= 4) {
		return sizeof(mockfs_acl_header) +
		       count * sizeof(mockfs_acl_entry_short);
	} else {
		return sizeof(mockfs_acl_header) +
		       4 * sizeof(mockfs_acl_entry_short) +
		       (count - 4) * sizeof(mockfs_acl_entry);
	}
}

static inline int mockfs_acl_count(size_t size)
{
	ssize_t s;
	size -= sizeof(mockfs_acl_header);
	s = size - 4 * sizeof(mockfs_acl_entry_short);
	if (s < 0) {
		if (size % sizeof(mockfs_acl_entry_short))
			return -1;
		return size / sizeof(mockfs_acl_entry_short);
	} else {
		if (s % sizeof(mockfs_acl_entry))
			return -1;
		return s / sizeof(mockfs_acl_entry) + 4;
	}
}

#ifdef CONFIG_MOCKFS_FS_POSIX_ACL

/* acl.c */
struct posix_acl *mockfs_get_acl(struct inode *inode, int type);
int mockfs_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern int mockfs_init_acl(handle_t *, struct inode *, struct inode *);

#else  /* CONFIG_MOCKFS_FS_POSIX_ACL */
#include <linux/sched.h>
#define mockfs_get_acl NULL
#define mockfs_set_acl NULL

static inline int
mockfs_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	return 0;
}
#endif  /* CONFIG_MOCKFS_FS_POSIX_ACL */

