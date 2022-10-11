#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <utils.h>
#include "prefetch_dma.h"

DOCA_LOG_REGISTER("prefetch_user_argp");

extern struct prefetch_user_config prefetch_user_config;
typedef enum ROLE {
	SERVER,
	CLIENT
} ROLE;
typedef enum MODE {
	SEND,
	RECV
} MODE;

static void
set_role_param(void *config, void *param)
{
	struct prefetch_user_config *prefetch_user_config = (struct prefetch_user_config *)config;
	const char *str = param;

	if(!strcmp(str, "server")) {
		prefetch_user_config->role = SERVER; 
		DOCA_LOG_INFO("%d", prefetch_user_config->role);
	}
	else if(!strcmp(str, "client")) prefetch_user_config->role = CLIENT;
	else APP_EXIT("unknown role %s was specified", str);
}

static void 
set_mode_param(void *config, void *param)
{
	struct prefetch_user_config *prefetch_user_config = (struct prefetch_user_config *)config;
	const char *str = param;

	if(!strcmp(str, "send")) prefetch_user_config->mode = SEND;
	else if(!strcmp(str, "recv")) prefetch_user_config->mode = RECV;
	else APP_EXIT("unknown mode %s was specified", str);
}

static void
set_dest_port_param(void *config, void *param)
{
	struct prefetch_user_config *prefetch_user_config = (struct prefetch_user_config *)config;

	prefetch_user_config->receiver_port = *(uint16_t *)param;
}

static void
set_listen_port_param(void *config, void *param)
{
	struct prefetch_user_config *prefetch_user_config = (struct prefetch_user_config *)config;

	prefetch_user_config->port = (char *) param;
    if (prefetch_user_config->port == NULL)
		APP_EXIT("unknown port = %s", (char *) param);
}

static void
set_dest_ip_param(void *config, void *param)
{
	struct prefetch_user_config *prefetch_user_config = (struct prefetch_user_config *)config;

	prefetch_user_config->receiver_ip = (char *) param;
    if (prefetch_user_config->receiver_ip == NULL)
		APP_EXIT("unknown ip = %s", (char *) param);
}

static void
set_bus_addr_param(void *config, void *param)
{
    struct prefetch_user_config *prefetch_user_config = (struct prefetch_user_config *)config;

    prefetch_user_config->bus_addr = *(uint8_t *)param;
}

static void
set_device_addr_param(void *config, void *param)
{
    struct prefetch_user_config *prefetch_user_config = (struct prefetch_user_config *)config;

    prefetch_user_config->device_addr = *(uint8_t *)param;
}

static void
set_function_addr_param(void *config, void *param)
{
    struct prefetch_user_config *prefetch_user_config = (struct prefetch_user_config *)config;

    prefetch_user_config->function_addr = *(uint8_t *)param;
}

void 
register_prefetch_user_params(void)
{
	struct doca_argp_param role_param = {
        .short_flag = "r",
        .long_flag = "role",
        .arguments = NULL,
        .description = "Run prefetch user process as: \"client\" or \"server\"",
        .callback = set_role_param,
        .arg_type = DOCA_ARGP_TYPE_STRING,
        .is_mandatory = true,
        .is_cli_only = false
    };
    /* This parameter has affect for client process */
    struct doca_argp_param mode_param = {
        .short_flag = "m",
        .long_flag = "mode",
        .arguments = "<mode>",
        .description = "send or recv",
        .callback = set_mode_param,
        .arg_type = DOCA_ARGP_TYPE_STRING,
        .is_mandatory = true,
        .is_cli_only = false
    };
    struct doca_argp_param dest_port_param = {
        .short_flag = "p",
        .long_flag = "port",
        .arguments = "<port>",
        .description = "Set connection port",
        .callback = set_dest_port_param,
        .arg_type = DOCA_ARGP_TYPE_INT,
        .is_mandatory = true,
        .is_cli_only = false
    };
    struct doca_argp_param dest_listen_port_param = {
        .short_flag = "t",
        .long_flag = "listen-port",
        .arguments = "<listen_port>",
        .description = "Set listening port",
        .callback = set_listen_port_param,
        .arg_type = DOCA_ARGP_TYPE_STRING,
        .is_mandatory = true,
        .is_cli_only = false
    };
	struct doca_argp_param dest_ip_param = {
		.short_flag = "i",
		.long_flag = "ip",
		.arguments = "<ip>",
		.description = "Set connection ip",
		.callback = set_dest_ip_param,
		.arg_type = DOCA_ARGP_TYPE_STRING,
		.is_mandatory = true,
		.is_cli_only = false
	};
	struct doca_argp_param bus_addr_param = {
        .short_flag = "b",
        .long_flag = "bus",
        .arguments = "<bus address>",
        .description = "Set bus address",
        .callback = set_bus_addr_param,
        .arg_type = DOCA_ARGP_TYPE_INT,
        .is_mandatory = true,
        .is_cli_only = false
    };
	struct doca_argp_param device_addr_param = {
        .short_flag = "d",
        .long_flag = "device",
        .arguments = "<device>",
        .description = "Set device address",
        .callback = set_device_addr_param,
        .arg_type = DOCA_ARGP_TYPE_INT,
        .is_mandatory = true,
        .is_cli_only = false
    };
	struct doca_argp_param function_addr_param = {
        .short_flag = "f",
        .long_flag = "function",
        .arguments = "<function>",
        .description = "Set function address",
        .callback = set_function_addr_param,
        .arg_type = DOCA_ARGP_TYPE_INT,
        .is_mandatory = true,
        .is_cli_only = false
    };
	
	
	doca_argp_register_param(&role_param);
	doca_argp_register_param(&mode_param);
	doca_argp_register_param(&dest_port_param);
	doca_argp_register_param(&dest_listen_port_param);
	doca_argp_register_param(&dest_ip_param);
	doca_argp_register_param(&bus_addr_param);
	doca_argp_register_param(&device_addr_param);
	doca_argp_register_param(&function_addr_param);
}
