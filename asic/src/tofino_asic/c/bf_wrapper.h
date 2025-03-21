#ifndef BF_WRAPPER_H
#define BF_WRAPPER_H

#include <bf_rt/bf_rt_session.h>
#include <bf_switchd/bf_switchd.h>
#include <port_mgr/bf_port_if.h>
#include <tofino/bf_pal/bf_pal_port_intf.h>

void port_dump();

typedef struct {
	bool is_sw_model;
	int32_t dev_id;
	bf_switchd_context_t *switchd_ctx;
	bf_mc_session_hdl_t mcast_hdl;
	const bf_rt_info_hdl *rt_info;
	const bf_rt_session_hdl *rt_sess;
	bf_drv_client_handle_t client_hdl;
} bfw_common_t;

int32_t bfw_init_ctx(const char *, const char *, const char *,
    bf_switchd_context_t *);
const char *bfw_err_msg(bf_status_t err);
int32_t bfw_get_version(const char *, uint32_t *major, uint32_t *minor,
    uint32_t *patch);
int32_t bfw_init(const char *, bfw_common_t *hdl);
int32_t bfw_register();
void bfw_fini(bfw_common_t *hdl);

/*
 * The SDE doesn't export this interface, so we define it here,
 */
bf_status_t bf_pm_serdes_tx_eq_override_set(                                                                 
  bf_dev_id_t dev_id, bf_pal_front_port_handle_t *port_hdl, bool override);

/*
 * XXX: Should eventually come from tofino.h
 */
#define VERSION_IOCTL 0x1d1c1002
struct driver_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patch;
};

#endif /* BF_WRAPPER_H */
