// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Technology Innovation Institute (TII)
 * Copyright (c) 2017, EPAM Systems
 */

#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_defines.h>

#include "acipher_helpers.h"

#define ED25519_KEY_SIZE_BYTES UL(32)

TEE_Result crypto_acipher_alloc_ed25519_keypair(struct x25519_keypair *key,
					       size_t key_size)
{
	size_t key_size_bytes = key_size / 8;

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(key, 0, sizeof(*key));

	if (key_size_bytes != ED25519_KEY_SIZE_BYTES)
		return TEE_ERROR_BAD_PARAMETERS;

	key->priv = calloc(1, key_size_bytes);
	key->pub = calloc(1, key_size_bytes);

	if (!key->priv || !key->pub) {
		free(key->priv);
		free(key->pub);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_gen_ed25519_key(struct x25519_keypair *key,
					 size_t key_size)
{
	curve25519_key ltc_tmp_key = { };
	size_t key_size_bytes = key_size / 8;

	if (key_size_bytes != ED25519_KEY_SIZE_BYTES)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ed25519_make_key(NULL, find_prng("prng_crypto"), &ltc_tmp_key) !=
	    CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;

	if (key_size_bytes < sizeof(ltc_tmp_key.pub) ||
	    key_size_bytes < sizeof(ltc_tmp_key.priv))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(key->pub, ltc_tmp_key.pub, sizeof(ltc_tmp_key.pub));
	memcpy(key->priv, ltc_tmp_key.priv, sizeof(ltc_tmp_key.priv));
	memzero_explicit(&ltc_tmp_key, sizeof(ltc_tmp_key));

	return TEE_SUCCESS;
}
