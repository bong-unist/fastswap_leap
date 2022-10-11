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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <doca_version.h>

#include "utils.h"

void
sdk_version_callback(void *doca_config, void *param)
{
	printf("DOCA SDK     Version (Compilation): %s\n", doca_version());
	printf("DOCA Runtime Version (Runtime):     %s\n", doca_version_runtime());
	exit(0);
}
