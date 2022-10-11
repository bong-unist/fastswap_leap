#
# Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

app_dependencies += dependency('doca-argp')
app_dependencies += dependency('doca-dma')
app_dependencies += dependency('doca-common')
app_dependencies += dependency('ucx')
app_dependencies += dependency('glib-2.0')

app_srcs += [
	'prefetch_user.c',
	'prefetch_argp.c',
	'prefetch_mmap.c',
    'dma_remote_copy_sender.c',
	'dma_remote_copy_receiver.c',
    common_dir_path + '/dma_common.c',
	common_dir_path + '/utils.c'
]

executable(DOCA_PREFIX + APP_NAME, app_srcs,
	dependencies : app_dependencies,
	include_directories : app_inc_dirs,
	install: false)
