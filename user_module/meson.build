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

project('DOCA_APPLICATIONS', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'), files('VERSION'), check: true).stdout().strip(),
	license: 'BSD',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.56.0'
)

DOCA_PREFIX = 'user_'

# With enabling GPU support, languages variable will contain CUDA language
languages = ['c', 'cpp']

install_apps = false

base_cpp_args = [
	'-std=c++11'
]

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: languages)

# Ensure mlnx-dpdk will manage to find our libbsd
add_project_arguments('-D RTE_USE_LIBBSD', language: languages)

base_app_dependencies = []
base_app_dependencies += dependency('threads')
base_app_dependencies += dependency('json-c')
base_app_dependencies += dependency('libbsd')

common_path = 'common/src'
common_dir_path = '../../' + common_path
base_app_inc_dirs = [include_directories(common_path)]

# Add the relevant GPU stuff to have a successful compilation with GPU support.
apps_gpu_common_src = []
# With GPU support there is version limitation
base_app_dependencies += dependency('libdpdk')

source_path = 'src'
bin_path = 'bin'

app_list = [
	    'user_module',
]

fs = import('fs')

foreach APP_NAME : app_list
	# gRPC preparation (just in case)
	# Basic app definitions
	app_dependencies = base_app_dependencies
	app_inc_dirs = base_app_inc_dirs
	app_libs = []
	app_srcs = apps_gpu_common_src

	# Enter the application's directory
	subdir(APP_NAME + '/' + source_path)

endforeach
