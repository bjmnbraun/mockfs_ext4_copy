/*
 * linux/fs/mockfs/mockfs_crypto.h
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption header content for mockfs
 *
 * Written by Michael Halcrow, 2015.
 */

#ifndef _MOCKFS_CRYPTO_H
#define _MOCKFS_CRYPTO_H

#include <linux/fs.h>

#define MOCKFS_KEY_DESCRIPTOR_SIZE 8

/* Policy provided via an ioctl on the topmost directory */
struct mockfs_encryption_policy {
	char version;
	char contents_encryption_mode;
	char filenames_encryption_mode;
	char flags;
	char master_key_descriptor[MOCKFS_KEY_DESCRIPTOR_SIZE];
} __attribute__((__packed__));

#define MOCKFS_ENCRYPTION_CONTEXT_FORMAT_V1 1
#define MOCKFS_KEY_DERIVATION_NONCE_SIZE 16

#define MOCKFS_POLICY_FLAGS_PAD_4		0x00
#define MOCKFS_POLICY_FLAGS_PAD_8		0x01
#define MOCKFS_POLICY_FLAGS_PAD_16	0x02
#define MOCKFS_POLICY_FLAGS_PAD_32	0x03
#define MOCKFS_POLICY_FLAGS_PAD_MASK	0x03
#define MOCKFS_POLICY_FLAGS_VALID		0x03

/**
 * Encryption context for inode
 *
 * Protector format:
 *  1 byte: Protector format (1 = this version)
 *  1 byte: File contents encryption mode
 *  1 byte: File names encryption mode
 *  1 byte: Reserved
 *  8 bytes: Master Key descriptor
 *  16 bytes: Encryption Key derivation nonce
 */
struct mockfs_encryption_context {
	char format;
	char contents_encryption_mode;
	char filenames_encryption_mode;
	char flags;
	char master_key_descriptor[MOCKFS_KEY_DESCRIPTOR_SIZE];
	char nonce[MOCKFS_KEY_DERIVATION_NONCE_SIZE];
} __attribute__((__packed__));

/* Encryption parameters */
#define MOCKFS_XTS_TWEAK_SIZE 16
#define MOCKFS_AES_128_ECB_KEY_SIZE 16
#define MOCKFS_AES_256_GCM_KEY_SIZE 32
#define MOCKFS_AES_256_CBC_KEY_SIZE 32
#define MOCKFS_AES_256_CTS_KEY_SIZE 32
#define MOCKFS_AES_256_XTS_KEY_SIZE 64
#define MOCKFS_MAX_KEY_SIZE 64

#define MOCKFS_KEY_DESC_PREFIX "mockfs:"
#define MOCKFS_KEY_DESC_PREFIX_SIZE 5

/* This is passed in from userspace into the kernel keyring */
struct mockfs_encryption_key {
        __u32 mode;
        char raw[MOCKFS_MAX_KEY_SIZE];
        __u32 size;
} __attribute__((__packed__));

struct mockfs_crypt_info {
	char		ci_data_mode;
	char		ci_filename_mode;
	char		ci_flags;
	struct crypto_skcipher *ci_ctfm;
	struct key	*ci_keyring_key;
	char		ci_master_key[MOCKFS_KEY_DESCRIPTOR_SIZE];
};

#define MOCKFS_CTX_REQUIRES_FREE_ENCRYPT_FL             0x00000001
#define MOCKFS_WRITE_PATH_FL			      0x00000002

struct mockfs_crypto_ctx {
	union {
		struct {
			struct page *bounce_page;       /* Ciphertext page */
			struct page *control_page;      /* Original page  */
		} w;
		struct {
			struct bio *bio;
			struct work_struct work;
		} r;
		struct list_head free_list;     /* Free list */
	};
	char flags;                      /* Flags */
	char mode;                       /* Encryption mode for tfm */
};

struct mockfs_completion_result {
	struct completion completion;
	int res;
};

#define DECLARE_MOCKFS_COMPLETION_RESULT(ecr) \
	struct mockfs_completion_result ecr = { \
		COMPLETION_INITIALIZER((ecr).completion), 0 }

static inline int mockfs_encryption_key_size(int mode)
{
	switch (mode) {
	case MOCKFS_ENCRYPTION_MODE_AES_256_XTS:
		return MOCKFS_AES_256_XTS_KEY_SIZE;
	case MOCKFS_ENCRYPTION_MODE_AES_256_GCM:
		return MOCKFS_AES_256_GCM_KEY_SIZE;
	case MOCKFS_ENCRYPTION_MODE_AES_256_CBC:
		return MOCKFS_AES_256_CBC_KEY_SIZE;
	case MOCKFS_ENCRYPTION_MODE_AES_256_CTS:
		return MOCKFS_AES_256_CTS_KEY_SIZE;
	default:
		BUG();
	}
	return 0;
}

#define MOCKFS_FNAME_NUM_SCATTER_ENTRIES	4
#define MOCKFS_CRYPTO_BLOCK_SIZE		16
#define MOCKFS_FNAME_CRYPTO_DIGEST_SIZE	32

struct mockfs_str {
	unsigned char *name;
	u32 len;
};

/**
 * For encrypted symlinks, the ciphertext length is stored at the beginning
 * of the string in little-endian format.
 */
struct mockfs_encrypted_symlink_data {
	__le16 len;
	char encrypted_path[1];
} __attribute__((__packed__));

/**
 * This function is used to calculate the disk space required to
 * store a filename of length l in encrypted symlink format.
 */
static inline u32 encrypted_symlink_data_len(u32 l)
{
	if (l < MOCKFS_CRYPTO_BLOCK_SIZE)
		l = MOCKFS_CRYPTO_BLOCK_SIZE;
	return (l + sizeof(struct mockfs_encrypted_symlink_data) - 1);
}

#endif	/* _MOCKFS_CRYPTO_H */
