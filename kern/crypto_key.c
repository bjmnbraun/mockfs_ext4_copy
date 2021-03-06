/*
 * linux/fs/mockfs/crypto_key.c
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption key functions for mockfs
 *
 * Written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar, 2015.
 */

#include <crypto/skcipher.h>
#include <keys/encrypted-type.h>
#include <keys/user-type.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <uapi/linux/keyctl.h>

#include "mockfs.h"
#include "xattr.h"

static void derive_crypt_complete(struct crypto_async_request *req, int rc)
{
	struct mockfs_completion_result *ecr = req->data;

	if (rc == -EINPROGRESS)
		return;

	ecr->res = rc;
	complete(&ecr->completion);
}

/**
 * mockfs_derive_key_aes() - Derive a key using AES-128-ECB
 * @deriving_key: Encryption key used for derivation.
 * @source_key:   Source key to which to apply derivation.
 * @derived_key:  Derived key.
 *
 * Return: Zero on success; non-zero otherwise.
 */
static int mockfs_derive_key_aes(char deriving_key[MOCKFS_AES_128_ECB_KEY_SIZE],
			       char source_key[MOCKFS_AES_256_XTS_KEY_SIZE],
			       char derived_key[MOCKFS_AES_256_XTS_KEY_SIZE])
{
	int res = 0;
	struct skcipher_request *req = NULL;
	DECLARE_MOCKFS_COMPLETION_RESULT(ecr);
	struct scatterlist src_sg, dst_sg;
	struct crypto_skcipher *tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);

	if (IS_ERR(tfm)) {
		res = PTR_ERR(tfm);
		tfm = NULL;
		goto out;
	}
	crypto_skcipher_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	req = skcipher_request_alloc(tfm, GFP_NOFS);
	if (!req) {
		res = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req,
			CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			derive_crypt_complete, &ecr);
	res = crypto_skcipher_setkey(tfm, deriving_key,
				     MOCKFS_AES_128_ECB_KEY_SIZE);
	if (res < 0)
		goto out;
	sg_init_one(&src_sg, source_key, MOCKFS_AES_256_XTS_KEY_SIZE);
	sg_init_one(&dst_sg, derived_key, MOCKFS_AES_256_XTS_KEY_SIZE);
	skcipher_request_set_crypt(req, &src_sg, &dst_sg,
				   MOCKFS_AES_256_XTS_KEY_SIZE, NULL);
	res = crypto_skcipher_encrypt(req);
	if (res == -EINPROGRESS || res == -EBUSY) {
		wait_for_completion(&ecr.completion);
		res = ecr.res;
	}

out:
	skcipher_request_free(req);
	crypto_free_skcipher(tfm);
	return res;
}

void mockfs_free_crypt_info(struct mockfs_crypt_info *ci)
{
	if (!ci)
		return;

	if (ci->ci_keyring_key)
		key_put(ci->ci_keyring_key);
	crypto_free_skcipher(ci->ci_ctfm);
	kmem_cache_free(mockfs_crypt_info_cachep, ci);
}

void mockfs_free_encryption_info(struct inode *inode,
			       struct mockfs_crypt_info *ci)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	struct mockfs_crypt_info *prev;

	if (ci == NULL)
		ci = ACCESS_ONCE(ei->i_crypt_info);
	if (ci == NULL)
		return;
	prev = cmpxchg(&ei->i_crypt_info, ci, NULL);
	if (prev != ci)
		return;

	mockfs_free_crypt_info(ci);
}

int _mockfs_get_encryption_info(struct inode *inode)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);
	struct mockfs_crypt_info *crypt_info;
	char full_key_descriptor[MOCKFS_KEY_DESC_PREFIX_SIZE +
				 (MOCKFS_KEY_DESCRIPTOR_SIZE * 2) + 1];
	struct key *keyring_key = NULL;
	struct mockfs_encryption_key *master_key;
	struct mockfs_encryption_context ctx;
	const struct user_key_payload *ukp;
	struct mockfs_sb_info *sbi = MOCKFS_SB(inode->i_sb);
	struct crypto_skcipher *ctfm;
	const char *cipher_str;
	char raw_key[MOCKFS_MAX_KEY_SIZE];
	char mode;
	int res;

	if (!mockfs_read_workqueue) {
		res = mockfs_init_crypto();
		if (res)
			return res;
	}

retry:
	crypt_info = ACCESS_ONCE(ei->i_crypt_info);
	if (crypt_info) {
		if (!crypt_info->ci_keyring_key ||
		    key_validate(crypt_info->ci_keyring_key) == 0)
			return 0;
		mockfs_free_encryption_info(inode, crypt_info);
		goto retry;
	}

	res = mockfs_xattr_get(inode, MOCKFS_XATTR_INDEX_ENCRYPTION,
				 MOCKFS_XATTR_NAME_ENCRYPTION_CONTEXT,
				 &ctx, sizeof(ctx));
	if (res < 0) {
		if (!DUMMY_ENCRYPTION_ENABLED(sbi))
			return res;
		ctx.contents_encryption_mode = MOCKFS_ENCRYPTION_MODE_AES_256_XTS;
		ctx.filenames_encryption_mode =
			MOCKFS_ENCRYPTION_MODE_AES_256_CTS;
		ctx.flags = 0;
	} else if (res != sizeof(ctx))
		return -EINVAL;
	res = 0;

	crypt_info = kmem_cache_alloc(mockfs_crypt_info_cachep, GFP_KERNEL);
	if (!crypt_info)
		return -ENOMEM;

	crypt_info->ci_flags = ctx.flags;
	crypt_info->ci_data_mode = ctx.contents_encryption_mode;
	crypt_info->ci_filename_mode = ctx.filenames_encryption_mode;
	crypt_info->ci_ctfm = NULL;
	crypt_info->ci_keyring_key = NULL;
	memcpy(crypt_info->ci_master_key, ctx.master_key_descriptor,
	       sizeof(crypt_info->ci_master_key));
	if (S_ISREG(inode->i_mode))
		mode = crypt_info->ci_data_mode;
	else if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode))
		mode = crypt_info->ci_filename_mode;
	else
		BUG();
	switch (mode) {
	case MOCKFS_ENCRYPTION_MODE_AES_256_XTS:
		cipher_str = "xts(aes)";
		break;
	case MOCKFS_ENCRYPTION_MODE_AES_256_CTS:
		cipher_str = "cts(cbc(aes))";
		break;
	default:
		printk_once(KERN_WARNING
			    "mockfs: unsupported key mode %d (ino %u)\n",
			    mode, (unsigned) inode->i_ino);
		res = -ENOKEY;
		goto out;
	}
	if (DUMMY_ENCRYPTION_ENABLED(sbi)) {
		memset(raw_key, 0x42, MOCKFS_AES_256_XTS_KEY_SIZE);
		goto got_key;
	}
	memcpy(full_key_descriptor, MOCKFS_KEY_DESC_PREFIX,
	       MOCKFS_KEY_DESC_PREFIX_SIZE);
	sprintf(full_key_descriptor + MOCKFS_KEY_DESC_PREFIX_SIZE,
		"%*phN", MOCKFS_KEY_DESCRIPTOR_SIZE,
		ctx.master_key_descriptor);
	full_key_descriptor[MOCKFS_KEY_DESC_PREFIX_SIZE +
			    (2 * MOCKFS_KEY_DESCRIPTOR_SIZE)] = '\0';
	keyring_key = request_key(&key_type_logon, full_key_descriptor, NULL);
	if (IS_ERR(keyring_key)) {
		res = PTR_ERR(keyring_key);
		keyring_key = NULL;
		goto out;
	}
	crypt_info->ci_keyring_key = keyring_key;
	if (keyring_key->type != &key_type_logon) {
		printk_once(KERN_WARNING
			    "mockfs: key type must be logon\n");
		res = -ENOKEY;
		goto out;
	}
	down_read(&keyring_key->sem);
	ukp = user_key_payload(keyring_key);
	if (ukp->datalen != sizeof(struct mockfs_encryption_key)) {
		res = -EINVAL;
		up_read(&keyring_key->sem);
		goto out;
	}
	master_key = (struct mockfs_encryption_key *)ukp->data;
	BUILD_BUG_ON(MOCKFS_AES_128_ECB_KEY_SIZE !=
		     MOCKFS_KEY_DERIVATION_NONCE_SIZE);
	if (master_key->size != MOCKFS_AES_256_XTS_KEY_SIZE) {
		printk_once(KERN_WARNING
			    "mockfs: key size incorrect: %d\n",
			    master_key->size);
		res = -ENOKEY;
		up_read(&keyring_key->sem);
		goto out;
	}
	res = mockfs_derive_key_aes(ctx.nonce, master_key->raw,
				  raw_key);
	up_read(&keyring_key->sem);
	if (res)
		goto out;
got_key:
	ctfm = crypto_alloc_skcipher(cipher_str, 0, 0);
	if (!ctfm || IS_ERR(ctfm)) {
		res = ctfm ? PTR_ERR(ctfm) : -ENOMEM;
		printk(KERN_DEBUG
		       "%s: error %d (inode %u) allocating crypto tfm\n",
		       __func__, res, (unsigned) inode->i_ino);
		goto out;
	}
	crypt_info->ci_ctfm = ctfm;
	crypto_skcipher_clear_flags(ctfm, ~0);
	crypto_tfm_set_flags(crypto_skcipher_tfm(ctfm),
			     CRYPTO_TFM_REQ_WEAK_KEY);
	res = crypto_skcipher_setkey(ctfm, raw_key,
				     mockfs_encryption_key_size(mode));
	if (res)
		goto out;
	memzero_explicit(raw_key, sizeof(raw_key));
	if (cmpxchg(&ei->i_crypt_info, NULL, crypt_info) != NULL) {
		mockfs_free_crypt_info(crypt_info);
		goto retry;
	}
	return 0;

out:
	if (res == -ENOKEY)
		res = 0;
	mockfs_free_crypt_info(crypt_info);
	memzero_explicit(raw_key, sizeof(raw_key));
	return res;
}

int mockfs_has_encryption_key(struct inode *inode)
{
	struct mockfs_inode_info *ei = MOCKFS_I(inode);

	return (ei->i_crypt_info != NULL);
}
