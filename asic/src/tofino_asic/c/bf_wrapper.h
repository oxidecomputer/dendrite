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
 * Memory test machinery
 */

typedef enum bf_diag_test_type_ {
  BF_DIAG_TEST_TYPE_PIO,
  BF_DIAG_TEST_TYPE_DMA,
} bf_diag_test_type_t;

typedef enum bf_diag_test_pattern_ {
  BF_DIAG_TEST_PATTERN_RANDOM,
  BF_DIAG_TEST_PATTERN_ZEROES,
  BF_DIAG_TEST_PATTERN_ONES,
  BF_DIAG_TEST_PATTERN_CHECKERBOARD,
  BF_DIAG_TEST_PATTERN_INV_CHECKERBOARD,
  BF_DIAG_TEST_PATTERN_PRBS,
  BF_DIAG_TEST_PATTERN_USER_DEFINED,
} bf_diag_test_pattern_t;

typedef struct bf_diag_mem_data_error_ {
  uint64_t addr;
  uint64_t exp_0;
  uint64_t exp_1;
  uint64_t data_0;
  uint64_t data_1;
  uint64_t mask_0;
  uint64_t mask_1;
} bf_diag_mem_data_error_t;

#define BF_DIAG_MEM_MAX_DATA_ERR 400
typedef struct bf_diag_mem_results_ {
  bool overall_success;
  bool ind_write_error;
  bool ind_read_error;
  bool write_list_error;
  bool write_block_error;
  uint64_t ind_write_error_addr;
  uint64_t ind_read_error_addr;
  uint32_t num_data_errors;
  bf_diag_mem_data_error_t data_error[BF_DIAG_MEM_MAX_DATA_ERR];
  uint32_t num_dma_msgs_sent;
  uint32_t num_dma_cmplts_rcvd;
} bf_diag_mem_results_t;

bf_status_t
bf_diag_mem_test_mau(
   bf_dev_id_t dev_id,
   bf_diag_test_type_t test_type,
   bool quick,
   uint32_t pipe_bmp,
   bf_diag_test_pattern_t pattern,
   uint64_t pattern_data0,
   uint64_t pattern_data1
 );

bf_status_t
bf_diag_mem_test_result_get(
  bf_dev_id_t dev_id,
  bf_diag_mem_results_t *results,
  bool *pass
);

pipe_status_t
pipe_mgr_tcam_scrub_timer_set(
  bf_dev_id_t dev,
  uint32_t msec_timer
);

uint32_t
pipe_mgr_tcam_scrub_timer_get(
  bf_dev_id_t dev
);

bf_status_t
lld_enable_all_ints(
  bf_dev_id_t dev_id,
  bf_subdev_id_t subdev_id
);

bf_status_t
lld_dump_new_ints(
  bf_dev_id_t dev_id,
  bf_subdev_id_t subdev_id
);

bf_status_t
lld_int_poll(
  bf_dev_id_t dev_id,
  bf_subdev_id_t subdev_id,
  bool all_ints
);

bf_status_t
bf_err_interrupt_handling_mode_set(
  bf_dev_id_t dev_id,
  bool enable
);

int
lld_write_register(
  bf_dev_id_t dev_id,
  uint32_t reg,
  uint32_t data
);

bool
pipe_mgr_is_device_locked(
  bf_dev_id_t dev_id
);


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
