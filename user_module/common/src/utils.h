/*
 * Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef COMMON_UTILS_H_
#define COMMON_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <doca_log.h>

#define APP_EXIT(format, ...)					\
	do {							\
		DOCA_LOG_ERR(format "\n", ##__VA_ARGS__);	\
		exit(1);					\
	} while (0)

void sdk_version_callback(void *doca_config, void *param);

#endif /* COMMON_UTILS_H_ */
