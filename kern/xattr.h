/*
  File: fs/mockfs/xattr.h

  On-disk format of extended attributes for the mockfs filesystem.

  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#include <linux/xattr.h>

/* Magic value in attribute blocks */
#define MOCKFS_XATTR_MAGIC		0xEA020000

/* Maximum number of references to one attribute block */
#define MOCKFS_XATTR_REFCOUNT_MAX		1024

/* Name indexes */
#define MOCKFS_XATTR_INDEX_USER			1
#define MOCKFS_XATTR_INDEX_POSIX_ACL_ACCESS	2
#define MOCKFS_XATTR_INDEX_POSIX_ACL_DEFAULT	3
#define MOCKFS_XATTR_INDEX_TRUSTED		4
#define	MOCKFS_XATTR_INDEX_LUSTRE			5
#define MOCKFS_XATTR_INDEX_SECURITY	        6
#define MOCKFS_XATTR_INDEX_SYSTEM			7
#define MOCKFS_XATTR_INDEX_RICHACL		8
#define MOCKFS_XATTR_INDEX_ENCRYPTION		9

struct mockfs_xattr_header {
	__le32	h_magic;	/* magic number for identification */
	__le32	h_refcount;	/* reference count */
	__le32	h_blocks;	/* number of disk blocks used */
	__le32	h_hash;		/* hash value of all attributes */
	__le32	h_checksum;	/* crc32c(uuid+id+xattrblock) */
				/* id = inum if refcount=1, blknum otherwise */
	__u32	h_reserved[3];	/* zero right now */
};

struct mockfs_xattr_ibody_header {
	__le32	h_magic;	/* magic number for identification */
};

struct mockfs_xattr_entry {
	__u8	e_name_len;	/* length of name */
	__u8	e_name_index;	/* attribute name index */
	__le16	e_value_offs;	/* offset in disk block of value */
	__le32	e_value_block;	/* disk block attribute is stored on (n/i) */
	__le32	e_value_size;	/* size of attribute value */
	__le32	e_hash;		/* hash value of name and value */
	char	e_name[0];	/* attribute name */
};

#define MOCKFS_XATTR_PAD_BITS		2
#define MOCKFS_XATTR_PAD		(1<<MOCKFS_XATTR_PAD_BITS)
#define MOCKFS_XATTR_ROUND		(MOCKFS_XATTR_PAD-1)
#define MOCKFS_XATTR_LEN(name_len) \
	(((name_len) + MOCKFS_XATTR_ROUND + \
	sizeof(struct mockfs_xattr_entry)) & ~MOCKFS_XATTR_ROUND)
#define MOCKFS_XATTR_NEXT(entry) \
	((struct mockfs_xattr_entry *)( \
	 (char *)(entry) + MOCKFS_XATTR_LEN((entry)->e_name_len)))
#define MOCKFS_XATTR_SIZE(size) \
	(((size) + MOCKFS_XATTR_ROUND) & ~MOCKFS_XATTR_ROUND)

#define IHDR(inode, raw_inode) \
	((struct mockfs_xattr_ibody_header *) \
		((void *)raw_inode + \
		MOCKFS_GOOD_OLD_INODE_SIZE + \
		MOCKFS_I(inode)->i_extra_isize))
#define IFIRST(hdr) ((struct mockfs_xattr_entry *)((hdr)+1))

#define BHDR(bh) ((struct mockfs_xattr_header *)((bh)->b_data))
#define ENTRY(ptr) ((struct mockfs_xattr_entry *)(ptr))
#define BFIRST(bh) ENTRY(BHDR(bh)+1)
#define IS_LAST_ENTRY(entry) (*(__u32 *)(entry) == 0)

#define MOCKFS_ZERO_XATTR_VALUE ((void *)-1)

struct mockfs_xattr_info {
	int name_index;
	const char *name;
	const void *value;
	size_t value_len;
};

struct mockfs_xattr_search {
	struct mockfs_xattr_entry *first;
	void *base;
	void *end;
	struct mockfs_xattr_entry *here;
	int not_found;
};

struct mockfs_xattr_ibody_find {
	struct mockfs_xattr_search s;
	struct mockfs_iloc iloc;
};

extern const struct xattr_handler mockfs_xattr_user_handler;
extern const struct xattr_handler mockfs_xattr_trusted_handler;
extern const struct xattr_handler mockfs_xattr_security_handler;

#define MOCKFS_XATTR_NAME_ENCRYPTION_CONTEXT "c"

extern ssize_t mockfs_listxattr(struct dentry *, char *, size_t);

extern int mockfs_xattr_get(struct inode *, int, const char *, void *, size_t);
extern int mockfs_xattr_set(struct inode *, int, const char *, const void *, size_t, int);
extern int mockfs_xattr_set_handle(handle_t *, struct inode *, int, const char *, const void *, size_t, int);

extern void mockfs_xattr_delete_inode(handle_t *, struct inode *);

extern int mockfs_expand_extra_isize_ea(struct inode *inode, int new_extra_isize,
			    struct mockfs_inode *raw_inode, handle_t *handle);

extern const struct xattr_handler *mockfs_xattr_handlers[];

extern int mockfs_xattr_ibody_find(struct inode *inode, struct mockfs_xattr_info *i,
				 struct mockfs_xattr_ibody_find *is);
extern int mockfs_xattr_ibody_get(struct inode *inode, int name_index,
				const char *name,
				void *buffer, size_t buffer_size);
extern int mockfs_xattr_ibody_inline_set(handle_t *handle, struct inode *inode,
				       struct mockfs_xattr_info *i,
				       struct mockfs_xattr_ibody_find *is);

extern struct mb_cache *mockfs_xattr_create_cache(void);
extern void mockfs_xattr_destroy_cache(struct mb_cache *);

#ifdef CONFIG_MOCKFS_FS_SECURITY
extern int mockfs_init_security(handle_t *handle, struct inode *inode,
			      struct inode *dir, const struct qstr *qstr);
#else
static inline int mockfs_init_security(handle_t *handle, struct inode *inode,
				     struct inode *dir, const struct qstr *qstr)
{
	return 0;
}
#endif
