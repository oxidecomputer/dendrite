#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#ifdef __linux__
#include <sys/ioctl.h>
#endif

#ifdef __sun
#include <strings.h>
#endif

#include <bf_rt/bf_rt_init.h>
#include <bf_rt/bf_rt_session.h>
#include <bf_switchd/bf_switchd.h>
#include <bf_pm/bf_pm_intf.h>
#include <port_mgr/bf_port_if.h>
#include <mc_mgr/mc_mgr_intf.h>
#include <pipe_mgr/pipe_mgr_intf.h>
#include <tofino/bf_pal/bf_pal_port_intf.h>

#include "bf_wrapper.h"

const char *
bfw_err_msg(bf_status_t err)
{
	return bf_err_str(err);
}

static bf_status_t
bf_rt_init(bfw_common_t *hdl) {
	int devid = hdl->dev_id;
	bf_status_t rval;
	bf_rt_info_hdl *info;
	int num_names;
	const char *name;
	const bf_rt_info_hdl *ihdl;
	bf_rt_session_hdl *shdl;

	// Quick sanity check that the only thing running on the switch is the
	// one program we expect to control.
	if ((rval = bf_rt_num_p4_names_get(devid, &num_names)) != BF_SUCCESS) {
		fprintf(stderr, "failed to get name count: %s\n",
				bf_err_str(rval));
		return rval;
	}
	if (num_names != 1) {
		fprintf(stderr, "switch running %d P4 programs\n", num_names);
		return BF_UNEXPECTED;
	}

	if ((rval = bf_rt_p4_names_get(devid, &name))!= BF_SUCCESS) {
		fprintf(stderr, "failed to get name: %s\n", bf_err_str(rval));
		return rval;
	}

	// Get a pointer to the runtime library's model of the switch state
	if ((rval = bf_rt_info_get(devid, name, &ihdl)) != BF_SUCCESS) {
		fprintf(stderr, "failed to get bf_rt_info handle: %s\n",
				bf_err_str(rval));
		return rval;
	}
	hdl->rt_info = ihdl;

	// Begin a session with the runtime
	if ((rval = bf_rt_session_create(&shdl)) != BF_SUCCESS) {
		fprintf(stderr, "failed to get bf_rt_session handle: %s\n",
				bf_err_str(rval));
		return rval;
	}
	hdl->rt_sess = shdl;

	return BF_SUCCESS;
}

int32_t
bfw_get_version(const char *devpath, uint32_t *major, uint32_t *minor,
    uint32_t *patch)
{
	struct driver_version version;
	int fd, rval;

	fd = open(devpath, O_RDONLY);

	if (fd < 0) {
		rval = errno;
	} else {
		if (ioctl(fd, VERSION_IOCTL, &version) == 0) {
			*major = version.major;
			*minor = version.minor;
			*patch = version.patch;
			rval = 0;
		} else {
			rval = errno;
		}
		close(fd);
	}

	return (rval);
}

int32_t
bfw_init_ctx(const char *devpath, const char *p4_dir,
    const char *sidecar_revision, bf_switchd_context_t *ctx)
{
	char *p4_name = getenv("P4_NAME");
	char *tofino_arch = getenv("TOFINO_ARCH");
	char *host = "127.0.0.1";
	int port = 8001;
	char *conffile, *install_path, msg;
	bf_status_t rval;
	struct stat sbuf;

	/*
	 * Populate the board revision from our arguments.
	 */
	bzero(ctx, sizeof (*ctx));
	ctx->sidecar_revision = strdup(sidecar_revision);
	if (ctx->sidecar_revision == NULL) {
		return (BF_NO_SPACE);
	}

	if ((ctx->install_dir = strdup(p4_dir)) == NULL) {
		fprintf(stderr, "unable to copy p4_dir name");
		return BF_NO_SPACE;
	}

	if (p4_name == NULL)
		p4_name = "sidecar";

	if (asprintf(&conffile, "%s/%s.conf", p4_dir, p4_name) < 0) {
		return (BF_UNEXPECTED);
	}
	if (stat(conffile, &sbuf) < 0) {
		fprintf(stderr, "failed to find p4 conf file at %s: %s\n",
			conffile, strerror(errno));
		return BF_OBJECT_NOT_FOUND;
	}
	ctx->conf_file = conffile;
	ctx->init_mode = BF_DEV_INIT_COLD;
	ctx->running_in_background = 1;;

	if (devpath != NULL) {
		ctx->kernel_pkt = 1;
	} else {
		perror("failed to find a tofino device");
	}

	char *h = getenv("TOFINO_HOST");
	if (h != NULL) {
		host = h;
	}
	const char *p = getenv("TOFINO_PORT");
	if (p != NULL) {
		port = atoi(p);
		if (port < 1 || port > 65535) {
			fprintf(stderr, "bad port number: %s\n", p);
			return (BF_INVALID_ARG);
		}
	}
	ctx->model_ip = host;
	ctx->tcp_port_base = port;
	return (BF_SUCCESS);
}

int32_t
bfw_init(const char *devpath, bfw_common_t *hdl)
{
	int32_t rval;

	if ((rval = bf_switchd_lib_init(hdl->switchd_ctx)) != BF_SUCCESS) {
		fprintf(stderr, "failed to initialize switch library: %s\n",
				bf_err_str(rval));
		return (rval);
	}

        if ((rval = bf_pm_init_platform(0)) != BF_SUCCESS) {
		fprintf(stderr, "bf_pm_init_platform() failed: %d", rval);
		return (rval);
	}

	return bf_rt_init(hdl);
}

void
bfw_fini(bfw_common_t *hdl) {
	bf_switchd_context_t *ctx = hdl->switchd_ctx;

	// As much as we would like to do an orderly, clean, complete
	// shutdown, the underlying SDE doesn't seem to be set up for it.
	// In particular, most (all?) of the threads being joined below
	// don't provide a mechanism to request that they exit, so the
	// joins will hang forever.
	exit(0);

	if (ctx != NULL) {
		pthread_join(ctx->tmr_t_id, NULL);
		pthread_join(ctx->dma_t_id, NULL);
		pthread_join(ctx->int_t_id, NULL);
		pthread_join(ctx->pkt_t_id, NULL);
		pthread_join(ctx->port_fsm_t_id, NULL);
		pthread_join(ctx->drusim_t_id, NULL);
		pthread_join(ctx->accton_diag_t_id, NULL);
		for (int id = 0; id < BF_SWITCHD_MAX_AGENTS; id++) {
			int tid;
			if ((tid = ctx->agent_t_id[id]) != 0) {
				pthread_join(tid, NULL);
			}
		}
		free(hdl);
	}

}
