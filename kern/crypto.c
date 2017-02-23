/*
 * linux/fs/mockfs/crypto.c
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption functions for mockfs
 *
 * Written by Michael Halcrow, 2014.
 *
 * Filename encryption additions
 *	Uday Savagaonkar, 2014
 * Encryption policy handling additions
 *	Ildar Muslukhov, 2014
 *
 * This has not yet undergone a rigorous security audit.
 *
 * The usage of AES-XTS should conform to recommendations in NIST
 * Special Publication 800-38E and IEEE P1619/D16.
 */

#include <crypto/skcipher.h>
#include <keys/user-type.h>
#include <keys/encrypted-type.h>
#include <linux/ecryptfs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/key.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/spinlock_types.h>
#include <linux/namei.h>

#include "mockfs_extents.h"
#include "xattr.h"

/* Encryption added and removed here! (L: */

static unsigned int num_prealloc_crypto_pages = 32;
static unsigned int num_prealloc_crypto_ctxs = 128;

module_param(num_prealloc_crypto_pages, uint, 0444);
MODULE_PARM_DESC(num_prealloc_crypto_pages,
		 "Number of crypto pages to preallocate");
module_param(num_prealloc_crypto_ctxs, uint, 0444);
MODULE_PARM_DESC(num_prealloc_crypto_ctxs,
		 "Number of crypto contexts to preallocate");

static mempool_t *mockfs_bounce_page_pool;

static LIST_HEAD(mockfs_free_crypto_ctxs);
static DEFINE_SPINLOCK(mockfs_crypto_ctx_lock);

static struct kmem_cache *mockfs_crypto_ctx_cachep;
struct kmem_cache *mockfs_crypt_info_cachep;

/**
 * mockfs_release_crypto_ctx() - Releases an encryption context
 * @ctx: The encryption context to release.
 *
 * If the encryption context was allocated from the pre-allocated pool, returns
 * it to that pool. Else, frees it.
 *
 * If there's a bounce page in the context, this frees that.
 */
void mockfs_release_crypto_ctx(struct mockfs_crypto_ctx *ctx)
{
	unsigned long flags;

	if (ctx->flags & MOCKFS_WRITE_PATH_FL && ctx->w.bounce_page)
		mempool_free(ctx->w.bounce_page, mockfs_bounce_page_pool);
	ctx->w.bounce_page = NULL;
	ctx->w.control_page = NULL;
	if (ctx->flags & MOCKFS_CTX_REQUIRES_FREE_ENCRYPT_FL) {
		kmem_cache_free(mockfs_crypto_ctx_cachep, ctx);
	} else {
		spin_lock_irqsave(&mockfs_crypto_ctx_lock, flags);
		list_add(&ctx->free_list, &mockfs_free_crypto_ctxs);
		spin_unlock_irqrestore(&mockfs_crypto_ctx_lock, flags);
	}
}

/**
 * mockfs_get_crypto_ctx() - Gets an encryption context
 * @inode:       The inode for which we are doing the crypto
 *
 * Allocates and initializes an encryption context.
 *
 * Return: An allocated and initialized encryption context on success; error
 * value or NULL otherwise.
 */
struct mockfs_crypto_ctx *mockfs_get_crypto_ctx(struct inode *inode,
					    gfp_t gfp_flags)
{
	struct mockfs_crypto_ctx *ctx = NULL;
	int res = 0;
	unsigned long flags;
	struct mockfs_crypt_info *ci = MOCKFS_I(inode)->i_crypt_info;

	if (ci == NULL)
		return ERR_PTR(-ENOKEY);

	/*
	 * We first try getting the ctx from a free list because in
	 * the common case the ctx will have an allocated and
	 * initialized crypto tfm, so it's probably a worthwhile
	 * optimization. For the bounce page, we first try getting it
	 * from the kernel allocator because that's just about as fast
	 * as getting it from a list and because a cache of free pages
	 * should generally be a "last resort" option for a filesystem
	 * to be able to do its job.
	 */
	spin_lock_irqsave(&mockfs_crypto_ctx_lock, flags);
	ctx = list_first_entry_or_null(&mockfs_free_crypto_ctxs,
				       struct mockfs_crypto_ctx, free_list);
	if (ctx)
		list_del(&ctx->free_list);
	spin_unlock_irqrestore(&mockfs_crypto_ctx_lock, flags);
	if (!ctx) {
		ctx = kmem_cache_zalloc(mockfs_crypto_ctx_cachep, gfp_flags);
		if (!ctx) {
			res = -ENOMEM;
			goto out;
		}
		ctx->flags |= MOCKFS_CTX_REQUIRES_FREE_ENCRYPT_FL;
	} else {
		ctx->flags &= ~MOCKFS_CTX_REQUIRES_FREE_ENCRYPT_FL;
	}
	ctx->flags &= ~MOCKFS_WRITE_PATH_FL;

out:
	if (res) {
		if (!IS_ERR_OR_NULL(ctx))
			mockfs_release_crypto_ctx(ctx);
		ctx = ERR_PTR(res);
	}
	return ctx;
}

struct workqueue_struct *mockfs_read_workqueue;
static DEFINE_MUTEX(crypto_init);

/**
 * mockfs_exit_crypto() - Shutdown the mockfs encryption system
 */
void mockfs_exit_crypto(void)
{
	struct mockfs_crypto_ctx *pos, *n;

	list_for_each_entry_safe(pos, n, &mockfs_free_crypto_ctxs, free_list)
		kmem_cache_free(mockfs_crypto_ctx_cachep, pos);
	INIT_LIST_HEAD(&mockfs_free_crypto_ctxs);
	if (mockfs_bounce_page_pool)
		mempool_destroy(mockfs_bounce_page_pool);
	mockfs_bounce_page_pool = NULL;
	if (mockfs_read_workqueue)
		destroy_workqueue(mockfs_read_workqueue);
	mockfs_read_workqueue = NULL;
	if (mockfs_crypto_ctx_cachep)
		kmem_cache_destroy(mockfs_crypto_ctx_cachep);
	mockfs_crypto_ctx_cachep = NULL;
	if (mockfs_crypt_info_cachep)
		kmem_cache_destroy(mockfs_crypt_info_cachep);
	mockfs_crypt_info_cachep = NULL;
}

/**
 * mockfs_init_crypto() - Set up for mockfs encryption.
 *
 * We only call this when we start accessing encrypted files, since it
 * results in memory getting allocated that wouldn't otherwise be used.
 *
 * Return: Zero on success, non-zero otherwise.
 */
int mockfs_init_crypto(void)
{
	int i, res = -ENOMEM;

	mutex_lock(&crypto_init);
	if (mockfs_read_workqueue)
		goto already_initialized;
	mockfs_read_workqueue = alloc_workqueue("mockfs_crypto", WQ_HIGHPRI, 0);
	if (!mockfs_read_workqueue)
		goto fail;

	mockfs_crypto_ctx_cachep = KMEM_CACHE(mockfs_crypto_ctx,
					    SLAB_RECLAIM_ACCOUNT);
	if (!mockfs_crypto_ctx_cachep)
		goto fail;

	mockfs_crypt_info_cachep = KMEM_CACHE(mockfs_crypt_info,
					    SLAB_RECLAIM_ACCOUNT);
	if (!mockfs_crypt_info_cachep)
		goto fail;

	for (i = 0; i < num_prealloc_crypto_ctxs; i++) {
		struct mockfs_crypto_ctx *ctx;

		ctx = kmem_cache_zalloc(mockfs_crypto_ctx_cachep, GFP_NOFS);
		if (!ctx) {
			res = -ENOMEM;
			goto fail;
		}
		list_add(&ctx->free_list, &mockfs_free_crypto_ctxs);
	}

	mockfs_bounce_page_pool =
		mempool_create_page_pool(num_prealloc_crypto_pages, 0);
	if (!mockfs_bounce_page_pool) {
		res = -ENOMEM;
		goto fail;
	}
already_initialized:
	mutex_unlock(&crypto_init);
	return 0;
fail:
	mockfs_exit_crypto();
	mutex_unlock(&crypto_init);
	return res;
}

void mockfs_restore_control_page(struct page *data_page)
{
	struct mockfs_crypto_ctx *ctx =
		(struct mockfs_crypto_ctx *)page_private(data_page);

	set_page_private(data_page, (unsigned long)NULL);
	ClearPagePrivate(data_page);
	unlock_page(data_page);
	mockfs_release_crypto_ctx(ctx);
}

/**
 * mockfs_crypt_complete() - The completion callback for page encryption
 * @req: The asynchronous encryption request context
 * @res: The result of the encryption operation
 */
static void mockfs_crypt_complete(struct crypto_async_request *req, int res)
{
	struct mockfs_completion_result *ecr = req->data;

	if (res == -EINPROGRESS)
		return;
	ecr->res = res;
	complete(&ecr->completion);
}

typedef enum {
	MOCKFS_DECRYPT = 0,
	MOCKFS_ENCRYPT,
} mockfs_direction_t;

static int mockfs_page_crypto(struct inode *inode,
			    mockfs_direction_t rw,
			    pgoff_t index,
			    struct page *src_page,
			    struct page *dest_page,
			    gfp_t gfp_flags)

{
	u8 xts_tweak[MOCKFS_XTS_TWEAK_SIZE];
	struct skcipher_request *req = NULL;
	DECLARE_MOCKFS_COMPLETION_RESULT(ecr);
	struct scatterlist dst, src;
	struct mockfs_crypt_info *ci = MOCKFS_I(inode)->i_crypt_info;
	struct crypto_skcipher *tfm = ci->ci_ctfm;
	int res = 0;

	req = skcipher_request_alloc(tfm, gfp_flags);
	if (!req) {
		printk_ratelimited(KERN_ERR
				   "%s: crypto_request_alloc() failed\n",
				   __func__);
		return -ENOMEM;
	}
	skcipher_request_set_callback(
		req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		mockfs_crypt_complete, &ecr);

	BUILD_BUG_ON(MOCKFS_XTS_TWEAK_SIZE < sizeof(index));
	memcpy(xts_tweak, &index, sizeof(index));
	memset(&xts_tweak[sizeof(index)], 0,
	       MOCKFS_XTS_TWEAK_SIZE - sizeof(index));

	sg_init_table(&dst, 1);
	sg_set_page(&dst, dest_page, PAGE_SIZE, 0);
	sg_init_table(&src, 1);
	sg_set_page(&src, src_page, PAGE_SIZE, 0);
	skcipher_request_set_crypt(req, &src, &dst, PAGE_SIZE,
				   xts_tweak);
	if (rw == MOCKFS_DECRYPT)
		res = crypto_skcipher_decrypt(req);
	else
		res = crypto_skcipher_encrypt(req);
	if (res == -EINPROGRESS || res == -EBUSY) {
		wait_for_completion(&ecr.completion);
		res = ecr.res;
	}
	skcipher_request_free(req);
	if (res) {
		printk_ratelimited(
			KERN_ERR
			"%s: crypto_skcipher_encrypt() returned %d\n",
			__func__, res);
		return res;
	}
	return 0;
}

static struct page *alloc_bounce_page(struct mockfs_crypto_ctx *ctx,
				      gfp_t gfp_flags)
{
	ctx->w.bounce_page = mempool_alloc(mockfs_bounce_page_pool, gfp_flags);
	if (ctx->w.bounce_page == NULL)
		return ERR_PTR(-ENOMEM);
	ctx->flags |= MOCKFS_WRITE_PATH_FL;
	return ctx->w.bounce_page;
}

/**
 * mockfs_encrypt() - Encrypts a page
 * @inode:          The inode for which the encryption should take place
 * @plaintext_page: The page to encrypt. Must be locked.
 *
 * Allocates a ciphertext page and encrypts plaintext_page into it using the ctx
 * encryption context.
 *
 * Called on the page write path.  The caller must call
 * mockfs_restore_control_page() on the returned ciphertext page to
 * release the bounce buffer and the encryption context.
 *
 * Return: An allocated page with the encrypted content on success. Else, an
 * error value or NULL.
 */
struct page *mockfs_encrypt(struct inode *inode,
			  struct page *plaintext_page,
			  gfp_t gfp_flags)
{
	struct mockfs_crypto_ctx *ctx;
	struct page *ciphertext_page = NULL;
	int err;

	BUG_ON(!PageLocked(plaintext_page));

	ctx = mockfs_get_crypto_ctx(inode, gfp_flags);
	if (IS_ERR(ctx))
		return (struct page *) ctx;

	/* The encryption operation will require a bounce page. */
	ciphertext_page = alloc_bounce_page(ctx, gfp_flags);
	if (IS_ERR(ciphertext_page))
		goto errout;
	ctx->w.control_page = plaintext_page;
	err = mockfs_page_crypto(inode, MOCKFS_ENCRYPT, plaintext_page->index,
			       plaintext_page, ciphertext_page, gfp_flags);
	if (err) {
		ciphertext_page = ERR_PTR(err);
	errout:
		mockfs_release_crypto_ctx(ctx);
		return ciphertext_page;
	}
	SetPagePrivate(ciphertext_page);
	set_page_private(ciphertext_page, (unsigned long)ctx);
	lock_page(ciphertext_page);
	return ciphertext_page;
}

/**
 * mockfs_decrypt() - Decrypts a page in-place
 * @ctx:  The encryption context.
 * @page: The page to decrypt. Must be locked.
 *
 * Decrypts page in-place using the ctx encryption context.
 *
 * Called from the read completion callback.
 *
 * Return: Zero on success, non-zero otherwise.
 */
int mockfs_decrypt(struct page *page)
{
	BUG_ON(!PageLocked(page));

	return mockfs_page_crypto(page->mapping->host, MOCKFS_DECRYPT,
				page->index, page, page, GFP_NOFS);
}

int mockfs_encrypted_zeroout(struct inode *inode, mockfs_lblk_t lblk,
			   mockfs_fsblk_t pblk, mockfs_lblk_t len)
{
	struct mockfs_crypto_ctx	*ctx;
	struct page		*ciphertext_page = NULL;
	struct bio		*bio;
	int			ret, err = 0;

#if 0
	mockfs_msg(inode->i_sb, KERN_CRIT,
		 "mockfs_encrypted_zeroout ino %lu lblk %u len %u",
		 (unsigned long) inode->i_ino, lblk, len);
#endif

	BUG_ON(inode->i_sb->s_blocksize != PAGE_SIZE);

	ctx = mockfs_get_crypto_ctx(inode, GFP_NOFS);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	ciphertext_page = alloc_bounce_page(ctx, GFP_NOWAIT);
	if (IS_ERR(ciphertext_page)) {
		err = PTR_ERR(ciphertext_page);
		goto errout;
	}

	while (len--) {
		err = mockfs_page_crypto(inode, MOCKFS_ENCRYPT, lblk,
				       ZERO_PAGE(0), ciphertext_page,
				       GFP_NOFS);
		if (err)
			goto errout;

		bio = bio_alloc(GFP_NOWAIT, 1);
		if (!bio) {
			err = -ENOMEM;
			goto errout;
		}
		bio->bi_bdev = inode->i_sb->s_bdev;
		bio->bi_iter.bi_sector =
			pblk << (inode->i_sb->s_blocksize_bits - 9);
		ret = bio_add_page(bio, ciphertext_page,
				   inode->i_sb->s_blocksize, 0);
		if (ret != inode->i_sb->s_blocksize) {
			/* should never happen! */
			mockfs_msg(inode->i_sb, KERN_ERR,
				 "bio_add_page failed: %d", ret);
			WARN_ON(1);
			bio_put(bio);
			err = -EIO;
			goto errout;
		}
		err = submit_bio_wait(WRITE, bio);
		if ((err == 0) && bio->bi_error)
			err = -EIO;
		bio_put(bio);
		if (err)
			goto errout;
		lblk++; pblk++;
	}
	err = 0;
errout:
	mockfs_release_crypto_ctx(ctx);
	return err;
}

bool mockfs_valid_contents_enc_mode(uint32_t mode)
{
	return (mode == MOCKFS_ENCRYPTION_MODE_AES_256_XTS);
}

/**
 * mockfs_validate_encryption_key_size() - Validate the encryption key size
 * @mode: The key mode.
 * @size: The key size to validate.
 *
 * Return: The validated key size for @mode. Zero if invalid.
 */
uint32_t mockfs_validate_encryption_key_size(uint32_t mode, uint32_t size)
{
	if (size == mockfs_encryption_key_size(mode))
		return size;
	return 0;
}

/*
 * Validate dentries for encrypted directories to make sure we aren't
 * potentially caching stale data after a key has been added or
 * removed.
 */
static int mockfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *dir;
	struct mockfs_crypt_info *ci;
	int dir_has_key, cached_with_key;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	dir = dget_parent(dentry);
	if (!mockfs_encrypted_inode(d_inode(dir))) {
		dput(dir);
		return 0;
	}
	ci = MOCKFS_I(d_inode(dir))->i_crypt_info;
	if (ci && ci->ci_keyring_key &&
	    (ci->ci_keyring_key->flags & ((1 << KEY_FLAG_INVALIDATED) |
					  (1 << KEY_FLAG_REVOKED) |
					  (1 << KEY_FLAG_DEAD))))
		ci = NULL;

	/* this should eventually be an flag in d_flags */
	cached_with_key = dentry->d_fsdata != NULL;
	dir_has_key = (ci != NULL);
	dput(dir);

	/*
	 * If the dentry was cached without the key, and it is a
	 * negative dentry, it might be a valid name.  We can't check
	 * if the key has since been made available due to locking
	 * reasons, so we fail the validation so mockfs_lookup() can do
	 * this check.
	 *
	 * We also fail the validation if the dentry was created with
	 * the key present, but we no longer have the key, or vice versa.
	 */
	if ((!cached_with_key && d_is_negative(dentry)) ||
	    (!cached_with_key && dir_has_key) ||
	    (cached_with_key && !dir_has_key)) {
#if 0				/* Revalidation debug */
		char buf[80];
		char *cp = simple_dname(dentry, buf, sizeof(buf));

		if (IS_ERR(cp))
			cp = (char *) "???";
		pr_err("revalidate: %s %p %d %d %d\n", cp, dentry->d_fsdata,
		       cached_with_key, d_is_negative(dentry),
		       dir_has_key);
#endif
		return 0;
	}
	return 1;
}

const struct dentry_operations mockfs_encrypted_d_ops = {
	.d_revalidate = mockfs_d_revalidate,
};
