/*
 * linux/fs/mockfs/crypto_policy.c
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption policy functions for mockfs
 *
 * Written by Michael Halcrow, 2015.
 */

#include <linux/random.h>
#include <linux/string.h>
#include <linux/types.h>

#include "mockfs_jbd2.h"
#include "mockfs.h"
#include "xattr.h"

static int mockfs_inode_has_encryption_context(struct inode *inode)
{
	int res = mockfs_xattr_get(inode, MOCKFS_XATTR_INDEX_ENCRYPTION,
				 MOCKFS_XATTR_NAME_ENCRYPTION_CONTEXT, NULL, 0);
	return (res > 0);
}

/*
 * check whether the policy is consistent with the encryption context
 * for the inode
 */
static int mockfs_is_encryption_context_consistent_with_policy(
	struct inode *inode, const struct mockfs_encryption_policy *policy)
{
	struct mockfs_encryption_context ctx;
	int res = mockfs_xattr_get(inode, MOCKFS_XATTR_INDEX_ENCRYPTION,
				 MOCKFS_XATTR_NAME_ENCRYPTION_CONTEXT, &ctx,
				 sizeof(ctx));
	if (res != sizeof(ctx))
		return 0;
	return (memcmp(ctx.master_key_descriptor, policy->master_key_descriptor,
			MOCKFS_KEY_DESCRIPTOR_SIZE) == 0 &&
		(ctx.flags ==
		 policy->flags) &&
		(ctx.contents_encryption_mode ==
		 policy->contents_encryption_mode) &&
		(ctx.filenames_encryption_mode ==
		 policy->filenames_encryption_mode));
}

static int mockfs_create_encryption_context_from_policy(
	struct inode *inode, const struct mockfs_encryption_policy *policy)
{
	struct mockfs_encryption_context ctx;
	handle_t *handle;
	int res, res2;

	res = mockfs_convert_inline_data(inode);
	if (res)
		return res;

	ctx.format = MOCKFS_ENCRYPTION_CONTEXT_FORMAT_V1;
	memcpy(ctx.master_key_descriptor, policy->master_key_descriptor,
	       MOCKFS_KEY_DESCRIPTOR_SIZE);
	if (!mockfs_valid_contents_enc_mode(policy->contents_encryption_mode)) {
		printk(KERN_WARNING
		       "%s: Invalid contents encryption mode %d\n", __func__,
			policy->contents_encryption_mode);
		return -EINVAL;
	}
	if (!mockfs_valid_filenames_enc_mode(policy->filenames_encryption_mode)) {
		printk(KERN_WARNING
		       "%s: Invalid filenames encryption mode %d\n", __func__,
			policy->filenames_encryption_mode);
		return -EINVAL;
	}
	if (policy->flags & ~MOCKFS_POLICY_FLAGS_VALID)
		return -EINVAL;
	ctx.contents_encryption_mode = policy->contents_encryption_mode;
	ctx.filenames_encryption_mode = policy->filenames_encryption_mode;
	ctx.flags = policy->flags;
	BUILD_BUG_ON(sizeof(ctx.nonce) != MOCKFS_KEY_DERIVATION_NONCE_SIZE);
	get_random_bytes(ctx.nonce, MOCKFS_KEY_DERIVATION_NONCE_SIZE);

	handle = mockfs_journal_start(inode, MOCKFS_HT_MISC,
				    mockfs_jbd2_credits_xattr(inode));
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	res = mockfs_xattr_set(inode, MOCKFS_XATTR_INDEX_ENCRYPTION,
			     MOCKFS_XATTR_NAME_ENCRYPTION_CONTEXT, &ctx,
			     sizeof(ctx), 0);
	if (!res) {
		mockfs_set_inode_flag(inode, MOCKFS_INODE_ENCRYPT);
		res = mockfs_mark_inode_dirty(handle, inode);
		if (res)
			MOCKFS_ERROR_INODE(inode, "Failed to mark inode dirty");
	}
	res2 = mockfs_journal_stop(handle);
	if (!res)
		res = res2;
	return res;
}

int mockfs_process_policy(const struct mockfs_encryption_policy *policy,
			struct inode *inode)
{
	if (policy->version != 0)
		return -EINVAL;

	if (!mockfs_inode_has_encryption_context(inode)) {
		if (!S_ISDIR(inode->i_mode))
			return -EINVAL;
		if (!mockfs_empty_dir(inode))
			return -ENOTEMPTY;
		return mockfs_create_encryption_context_from_policy(inode,
								  policy);
	}

	if (mockfs_is_encryption_context_consistent_with_policy(inode, policy))
		return 0;

	printk(KERN_WARNING "%s: Policy inconsistent with encryption context\n",
	       __func__);
	return -EINVAL;
}

int mockfs_get_policy(struct inode *inode, struct mockfs_encryption_policy *policy)
{
	struct mockfs_encryption_context ctx;

	int res = mockfs_xattr_get(inode, MOCKFS_XATTR_INDEX_ENCRYPTION,
				 MOCKFS_XATTR_NAME_ENCRYPTION_CONTEXT,
				 &ctx, sizeof(ctx));
	if (res != sizeof(ctx))
		return -ENOENT;
	if (ctx.format != MOCKFS_ENCRYPTION_CONTEXT_FORMAT_V1)
		return -EINVAL;
	policy->version = 0;
	policy->contents_encryption_mode = ctx.contents_encryption_mode;
	policy->filenames_encryption_mode = ctx.filenames_encryption_mode;
	policy->flags = ctx.flags;
	memcpy(&policy->master_key_descriptor, ctx.master_key_descriptor,
	       MOCKFS_KEY_DESCRIPTOR_SIZE);
	return 0;
}

int mockfs_is_child_context_consistent_with_parent(struct inode *parent,
						 struct inode *child)
{
	struct mockfs_crypt_info *parent_ci, *child_ci;
	int res;

	if ((parent == NULL) || (child == NULL)) {
		pr_err("parent %p child %p\n", parent, child);
		WARN_ON(1);	/* Should never happen */
		return 0;
	}
	/* no restrictions if the parent directory is not encrypted */
	if (!mockfs_encrypted_inode(parent))
		return 1;
	/* if the child directory is not encrypted, this is always a problem */
	if (!mockfs_encrypted_inode(child))
		return 0;
	res = mockfs_get_encryption_info(parent);
	if (res)
		return 0;
	res = mockfs_get_encryption_info(child);
	if (res)
		return 0;
	parent_ci = MOCKFS_I(parent)->i_crypt_info;
	child_ci = MOCKFS_I(child)->i_crypt_info;
	if (!parent_ci && !child_ci)
		return 1;
	if (!parent_ci || !child_ci)
		return 0;

	return (memcmp(parent_ci->ci_master_key,
		       child_ci->ci_master_key,
		       MOCKFS_KEY_DESCRIPTOR_SIZE) == 0 &&
		(parent_ci->ci_data_mode == child_ci->ci_data_mode) &&
		(parent_ci->ci_filename_mode == child_ci->ci_filename_mode) &&
		(parent_ci->ci_flags == child_ci->ci_flags));
}

/**
 * mockfs_inherit_context() - Sets a child context from its parent
 * @parent: Parent inode from which the context is inherited.
 * @child:  Child inode that inherits the context from @parent.
 *
 * Return: Zero on success, non-zero otherwise
 */
int mockfs_inherit_context(struct inode *parent, struct inode *child)
{
	struct mockfs_encryption_context ctx;
	struct mockfs_crypt_info *ci;
	int res;

	res = mockfs_get_encryption_info(parent);
	if (res < 0)
		return res;
	ci = MOCKFS_I(parent)->i_crypt_info;
	if (ci == NULL)
		return -ENOKEY;

	ctx.format = MOCKFS_ENCRYPTION_CONTEXT_FORMAT_V1;
	if (DUMMY_ENCRYPTION_ENABLED(MOCKFS_SB(parent->i_sb))) {
		ctx.contents_encryption_mode = MOCKFS_ENCRYPTION_MODE_AES_256_XTS;
		ctx.filenames_encryption_mode =
			MOCKFS_ENCRYPTION_MODE_AES_256_CTS;
		ctx.flags = 0;
		memset(ctx.master_key_descriptor, 0x42,
		       MOCKFS_KEY_DESCRIPTOR_SIZE);
		res = 0;
	} else {
		ctx.contents_encryption_mode = ci->ci_data_mode;
		ctx.filenames_encryption_mode = ci->ci_filename_mode;
		ctx.flags = ci->ci_flags;
		memcpy(ctx.master_key_descriptor, ci->ci_master_key,
		       MOCKFS_KEY_DESCRIPTOR_SIZE);
	}
	get_random_bytes(ctx.nonce, MOCKFS_KEY_DERIVATION_NONCE_SIZE);
	res = mockfs_xattr_set(child, MOCKFS_XATTR_INDEX_ENCRYPTION,
			     MOCKFS_XATTR_NAME_ENCRYPTION_CONTEXT, &ctx,
			     sizeof(ctx), 0);
	if (!res) {
		mockfs_set_inode_flag(child, MOCKFS_INODE_ENCRYPT);
		mockfs_clear_inode_state(child, MOCKFS_STATE_MAY_INLINE_DATA);
		res = mockfs_get_encryption_info(child);
	}
	return res;
}
