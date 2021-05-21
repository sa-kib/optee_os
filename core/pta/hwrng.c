// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, Linaro Limited
 * Copyright (c) 2021, EPAM Systems. All rights reserved.
 *
 * Based on plat-synquacer/rng_pta.c
 *
 */

#include <kernel/pseudo_ta.h>
#include <rng_support.h>
#include <crypto/rng_pta_client.h>

#define PTA_NAME "rng.pta"
#ifndef CFG_RNG_RATE
	#define CFG_RNG_RATE 0 /* not rate-limited by default */
#endif

static TEE_Result rng_get_entropy(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *e = NULL;
	uint32_t i = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	e = (uint8_t *)params[0].memref.buffer;
	if (!e)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < params[0].memref.size; i++)
		e[i] = hw_get_random_byte();

	return TEE_SUCCESS;
}

static TEE_Result rng_get_info(uint32_t types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Output RNG rate (per second) */
	params[0].value.a = CFG_RNG_RATE;
	/* Quality/entropy per 1024 bit of output data */
	params[0].value.b = CFG_RNG_QUALITY;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	switch (nCommandID) {
	case PTA_CMD_GET_ENTROPY:
		return rng_get_entropy(nParamTypes, pParams);
	case PTA_CMD_GET_RNG_INFO:
		return rng_get_info(nParamTypes, pParams);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_RNG_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
