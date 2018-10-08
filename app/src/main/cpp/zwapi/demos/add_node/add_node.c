/**
@file   add_node.c - Sample application to add a node into Z-wave network.

@author David Chow

@version    1.0 26-1-15  Initial release

@copyright � 2014 SIGMA DESIGNS, INC. THIS IS AN UNPUBLISHED WORK PROTECTED BY SIGMA DESIGNS, INC.
AS A TRADE SECRET, AND IS NOT TO BE USED OR DISCLOSED EXCEPT AS PROVIDED Z-WAVE CONTROLLER DEVELOPMENT KIT
LIMITED LICENSE AGREEMENT. ALL RIGHTS RESERVED.

NOTICE: ALL INFORMATION CONTAINED HEREIN IS CONFIDENTIAL AND/OR PROPRIETARY TO SIGMA DESIGNS
AND MAY BE COVERED BY U.S. AND FOREIGN PATENTS, PATENTS IN PROCESS, AND ARE PROTECTED BY TRADE SECRET
OR COPYRIGHT LAW. DISSEMINATION OR REPRODUCTION OF THE SOURCE CODE CONTAINED HEREIN IS EXPRESSLY FORBIDDEN
TO ANYONE EXCEPT LICENSEES OF SIGMA DESIGNS  WHO HAVE EXECUTED A SIGMA DESIGNS' Z-WAVE CONTROLLER DEVELOPMENT KIT
LIMITED LICENSE AGREEMENT. THE COPYRIGHT NOTICE ABOVE IS NOT EVIDENCE OF ANY ACTUAL OR INTENDED PUBLICATION OF
THE SOURCE CODE. THE RECEIPT OR POSSESSION OF  THIS SOURCE CODE AND/OR RELATED INFORMATION DOES NOT CONVEY OR
IMPLY ANY RIGHTS  TO REPRODUCE, DISCLOSE OR DISTRIBUTE ITS CONTENTS, OR TO MANUFACTURE, USE, OR SELL A PRODUCT
THAT IT  MAY DESCRIBE.


THE SIGMA PROGRAM AND ANY RELATED DOCUMENTATION OR TOOLS IS PROVIDED TO COMPANY "AS IS" AND "WITH ALL FAULTS",
WITHOUT WARRANTY OF ANY KIND FROM SIGMA. COMPANY ASSUMES ALL RISKS THAT LICENSED MATERIALS ARE SUITABLE OR ACCURATE
FOR COMPANY'S NEEDS AND COMPANY'S USE OF THE SIGMA PROGRAM IS AT COMPANY'S OWN DISCRETION AND RISK. SIGMA DOES NOT
GUARANTEE THAT THE USE OF THE SIGMA PROGRAM IN A THIRD PARTY SERVICE ENVIRONMENT OR CLOUD SERVICES ENVIRONMENT WILL BE:
(A) PERFORMED ERROR-FREE OR UNINTERRUPTED; (B) THAT SIGMA WILL CORRECT ANY THIRD PARTY SERVICE ENVIRONMENT OR
CLOUD SERVICE ENVIRONMENT ERRORS; (C) THE THIRD PARTY SERVICE ENVIRONMENT OR CLOUD SERVICE ENVIRONMENT WILL
OPERATE IN COMBINATION WITH COMPANY'S CONTENT OR COMPANY APPLICATIONS THAT UTILIZE THE SIGMA PROGRAM;
(D) OR WITH ANY OTHER HARDWARE, SOFTWARE, SYSTEMS, SERVICES OR DATA NOT PROVIDED BY SIGMA. COMPANY ACKNOWLEDGES
THAT SIGMA DOES NOT CONTROL THE TRANSFER OF DATA OVER COMMUNICATIONS FACILITIES, INCLUDING THE INTERNET, AND THAT
THE SERVICES MAY BE SUBJECT TO LIMITATIONS, DELAYS, AND OTHER PROBLEMS INHERENT IN THE USE OF SUCH COMMUNICATIONS
FACILITIES. SIGMA IS NOT RESPONSIBLE FOR ANY DELAYS, DELIVERY FAILURES, OR OTHER DAMAGE RESULTING FROM SUCH ISSUES.
SIGMA IS NOT RESPONSIBLE FOR ANY ISSUES RELATED TO THE PERFORMANCE, OPERATION OR SECURITY OF THE THIRD PARTY SERVICE
ENVIRONMENT OR CLOUD SERVICES ENVIRONMENT THAT ARISE FROM COMPANY CONTENT, COMPANY APPLICATIONS OR THIRD PARTY CONTENT.
SIGMA DOES NOT MAKE ANY REPRESENTATION OR WARRANTY REGARDING THE RELIABILITY, ACCURACY, COMPLETENESS, CORRECTNESS, OR
USEFULNESS OF THIRD PARTY CONTENT OR SERVICE OR THE SIGMA PROGRAM, AND DISCLAIMS ALL LIABILITIES ARISING FROM OR RELATED
TO THE SIGMA PROGRAM OR THIRD PARTY CONTENT OR SERVICES. TO THE EXTENT NOT PROHIBITED BY LAW, THESE WARRANTIES ARE EXCLUSIVE.
SIGMA OFFERS NO WARRANTY OF NON-INFRINGEMENT, TITLE, OR QUIET ENJOYMENT. NEITHER SIGMA NOR ITS SUPPLIERS OR LICENSORS
SHALL BE LIABLE FOR ANY INDIRECT, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES OR LOSS (INCLUDING DAMAGES FOR LOSS OF
BUSINESS, LOSS OF PROFITS, OR THE LIKE), ARISING OUT OF THIS AGREEMENT WHETHER BASED ON BREACH OF CONTRACT,
INTELLECTUAL PROPERTY INFRINGEMENT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY, PRODUCT LIABILITY OR OTHERWISE,
EVEN IF SIGMA OR ITS REPRESENTATIVES HAVE BEEN ADVISED OF OR OTHERWISE SHOULD KNOW ABOUT THE POSSIBILITY OF SUCH DAMAGES.
THERE ARE NO OTHER EXPRESS OR IMPLIED WARRANTIES OR CONDITIONS INCLUDING FOR SOFTWARE, HARDWARE, SYSTEMS, NETWORKS OR
ENVIRONMENTS OR FOR MERCHANTABILITY, NONINFRINGEMENT, SATISFACTORY QUALITY AND FITNESS FOR A PARTICULAR PURPOSE.

The Sigma Program  is not fault-tolerant and is not designed, manufactured or intended for use or resale as on-line control
equipment in hazardous environments requiring fail-safe performance, such as in the operation of nuclear facilities,
aircraft navigation or communication systems, air traffic control, direct life support machines, or weapons systems,
in which the failure of the Sigma Program, or Company Applications created using the Sigma Program, could lead directly
to death, personal injury, or severe physical or environmental damage ("High Risk Activities").  Sigma and its suppliers
specifically disclaim any express or implied warranty of fitness for High Risk Activities.Without limiting Sigma's obligation
of confidentiality as further described in the Z-Wave Controller Development Kit Limited License Agreement, Sigma has no
obligation to establish and maintain a data privacy and information security program with regard to Company's use of any
Third Party Service Environment or Cloud Service Environment. For the avoidance of doubt, Sigma shall not be responsible
for physical, technical, security, administrative, and/or organizational safeguards that are designed to ensure the
security and confidentiality of the Company Content or Company Application in any Third Party Service Environment or
Cloud Service Environment that Company chooses to utilize.
*/

#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "../../include/zip_api.h"

#define  MAX_DTLS_PSK       64                 //Maximum DTLS pre-shared key hex string length

#define ADD_NODE_STS_UNKNOWN    0   ///<Add node status: unknown
#define ADD_NODE_STS_PROGRESS   1   ///<Add node status: in progress
#define ADD_NODE_STS_DONE       2   ///<Add node status: done

#define     SEC2_ENTER_KEY_REQ  1   ///< Bit-mask for allowing S2 key request callback
#define     SEC2_ENTER_DSK      2   ///< Bit-mask for allowing S2 DSK callback

/// Container for different types of descriptor
typedef struct  _desc_cont
{
    struct  _desc_cont  *next;      ///< The next (same level) descriptor
    struct  _desc_cont  *down;      ///< The child (one lower level) descriptor
    uint32_t            id;         ///< Unique descriptor id
    uint32_t            type;       ///< The descriptor type in this container
    uint8_t             desc[1];    ///< Place holder for the descriptor

} desc_cont_t;

///
/// Test statistic
typedef struct
{
    uint32_t            rx_seq_num_err;     ///< Number of times received sequence number error
    uint32_t            rx_seq_num_frm;     ///< Number of sequence number frames received
    uint32_t            tx_seq_num_frm;     ///< Number of sequence number frames sent
    uint32_t            tx_multi_lvl_frm;   ///< Number of multi-level switch "set level" frames sent

} test_stat_t;


static void show_menu()
{
    printf("__________________________________________________________________________\n");
    printf("\n(1) Add node\n(2) Dump node info\n(3) Start learn mode\n(4)Association group get\n(x) Exit\n");
    printf("Select your choice:\n");
}
///
/// High-level application context
typedef struct
{
    volatile int    init_status;   ///< Network initialization status. 0=unknown; 1=done
    volatile int    add_status;
    volatile unsigned   sec2_cb_enter;///< Control security 2 callback entry bitmask, see SEC2_ENTER_XXX. bit set = allowed callback, 0 = not allowed
    volatile int    sec2_cb_exit;  ///< Security 2 callback status. 1 = exited callback, 0 = waiting or still in the callback
    uint8_t         sec2_add_node; ///< Flag to determine whether to use security 2 when adding node
    sec2_add_prm_t  sec2_add_prm;  ///< Add node with security 2 parameters

    int             use_ipv4;      ///< Flag to indicate whether to use IPv4 or IPv6. 1=IPv4; 0=IPv6
    zwnet_p         zwnet;         ///< Network handle
    uint8_t         zip_gw_ip[16]; ///< Z/IP gateway address in IPv4 or IPv6

    volatile    int32_t is_to_run_test;             ///< Flag to control the test thread to run test
    int32_t             port_number;                ///< The comm port number to use for communication with controller
    uint32_t            exp_seq_num;                ///< Expected received sequence number
    uint32_t            seq_num;                    ///< Sequence number to send
    uint32_t            home_id;                    ///< The Z-wave network home-id
    int32_t             (*stress_tst_func)(struct _hl_appl_ctx   *hl_appl);   ///< Pointer to the stress test function.
    int32_t             is_stress_tst_run;          ///< Flag to indicate whether stress test is running
    int32_t             is_ni_stress_tst_run;       ///< Flag to indicate whether node update stress test is running
    uint8_t             basis_api_ver[20];          ///< Basis API version
    uint32_t            dst_desc_id;                ///< The destination descriptor id where commands are sent
    uint32_t            suc_node_id;                ///< The SUC node id
    uint32_t            failed_node_id;             ///< The failed node id to be removed/replaced
    uint32_t            rep_desc_id;                ///< The report receiving interface descriptor id
    uint32_t            intf_desc_id;               ///< Interface descriptor id
    uint32_t            node_desc_id;               ///< Node descriptor id
    uint32_t            temp_desc;                  ///< Temporary descriptor id
    uint32_t            wkup_interval;              ///< Wake up interval in seconds
    uint32_t            ep_desc_id[5];              ///< Endpoint descriptor id
    uint32_t            desc_id;                    ///< Descriptor id
    uint8_t             lvl;                        ///< Multi-level value
    uint8_t             cap;                        ///< Capabilities of controller
    uint8_t             lib_type;                   ///< Library type of basis API
    uint8_t             mul_lvl_dur;                ///< Multi level dimming duration
    uint8_t             mul_lvl_dir;                ///< Multi level primary switch change direction
    uint8_t             mul_lvl_sec_dir;            ///< Multi level secondary switch change direction
    uint8_t             mul_lvl_sec_step;           ///< Multi level secondary switch step size
    uint8_t             mul_lvl_change_started;     ///< Flag to indicate whether multi level change started
    uint16_t            mul_lvl_val;                ///< Multi level set value
    uint16_t            cfg_range_start;            ///< Configuration parameter number range start
    uint16_t            cfg_range_end;              ///< Configuration parameter number range end
    uint8_t             cfg_param_mode;             ///< Configuration parameter number mode: 0 = single, 1=range
    uint8_t             cfg_param;                  ///< Configuration parameter number
    uint8_t             cfg_size;                   ///< Configuration parameter size
    uint8_t             cfg_value_default;          ///< Configuration parameter value flag: 1=use device default, 0=use cfg_value
    int32_t             cfg_value;                  ///< Configuration parameter value
    uint8_t             bin_state;                  ///< Binary switch state: 0 = off, 1 = on
    uint8_t             cmd_q_ctl;                  ///< Commmand queuing control: 0 = disable, 1 = enable
    uint16_t            basic_val;                  ///< Basic command value
    uint16_t            ind_val;                    ///< Indicator value
    uint8_t             local_prot;                 ///< Local protection state
    uint8_t             rf_prot;                    ///< RF protection state
    uint8_t             time;                       ///< Time
    uint8_t             mul_cmd_ctl;                ///< Multi Command Encapsulation control: 0 = off, 1 = on
    uint8_t             group_id;                   ///< Group id
    uint8_t             node_id;                    ///< Node id
    uint8_t             command[22];                ///< Command and parameters
    uint8_t             cmd_len;                    ///< Command length
    uint8_t             meter_unit;                 ///< Preferred meter reading unit
    uint8_t             usr_id;                     ///< User id for user code
    uint8_t             dlck_mode;                  ///< Door lock operation mode
    uint8_t             broadcast;                  ///< Flag to determine whether to transmit frame in broadcast mode
    uint8_t             alrm_vtype;                 ///< Vendor specific alarm type
    uint8_t             alrm_ztype;                 ///< Z-wave alarm type
    uint8_t             alrm_evt;                   ///< Z-wave alarm event
    uint8_t             alrm_sts;                   ///< Alarm status
    uint8_t             sensor_type;                ///< Sensor type
    uint8_t             sensor_unit;                ///< Sensor unit
    uint8_t             weekday;                    ///< Day of a week
    uint8_t             hour;                       ///< Hour (24 hours format)
    uint8_t             minute;                     ///< Minute
    uint8_t             thrmo_md;                   ///< Thermostat operating mode
    uint8_t             thrmo_fan_md;               ///< Thermostat fan operating mode
    uint8_t             thrmo_fan_off;              ///< Turn thermostat fan off (depend on thrmo_fan_off_cap)
    uint8_t             thrmo_fan_off_cap;          ///< Thermostat fan off mode capability: 0 = not supported, 1 = supported
    uint8_t             thrmo_setb_sta;             ///< Thermostat setback state
    uint8_t             thrmo_setb_typ;             ///< Thermostat setback type
    int8_t              thrmo_setb_deg;             ///< Thermostat setback in units of 1/10 degree
    uint8_t             thrmo_setp_typ;             ///< Thermostat setpoint type
    zwsetp_t            thrmo_setp_data;            ///< Thermostat setpoint data
    zwcc_shed_t         clmt_ctl_schd;              ///< Climate control schedule
    zwcc_shed_ovr_t     clmt_ctl_schd_ovr;          ///< Climate control schedule override
    zwdlck_cfg_t        dlck_config;                ///< Door lock configuration
    zwusrcod_t          usr_code;                   ///< User code
    test_stat_t         test_stat;                  ///< Test statistic
    zwnoded_t           node_updt_desc;             ///< Store the descriptor of the node pending for update info
    zwnoded_t           node_add_desc;              ///< Store the descriptor of the last added node
    zwnoded_t           node_rp_desc;               ///< Store the descriptor of the replaced node
    //appl_hci_cap_t      hci_cap;                    ///< HCI capabilities
    //appl_init_dat_t     init_dat;                   ///< Initialization data from the controller
    appl_layer_ctx_t    appl_ctx;                   ///< Z-wave HCI application layer context
    //zwnet_p             zwnet;                      ///< Z-wave network
    //zw_nameloc_t        nameloc;                    ///< The name location of a node
    char                meter_admin[ZW_ADMIN_STR_MAX + 1];    ///< Meter admin name
    desc_cont_t         *desc_cont_hd;              ///< Head of descriptor container
    void                *desc_cont_mtx;             ///< Mutex to access descriptor container
    char                node_info_file[200];        ///< file name of the node information file
    char                save_file[200];             ///< file name where the node information to be saved
    int                 load_ni_file;               ///< flag to determine whether to load node info file on init. 1=yes, 0=no
    int                 save_ni_file;               ///< flag to determine whether to save node info file on exit. 1=yes, 0=no
    int                 enable_rec_cmd;             ///< Flag to indicate whether to enable command recording
    void                *plt_ctx;                   ///< Platform context for printing of output text messages
    uint16_t            av_btn_down;                ///< Flag to indicate whether the AV button is down
    uint16_t            av_btn_ctl;                 ///< AV Button control code
    char                comm_port_name[80];         ///< Comm port name
    uint16_t            fw_vid;                     ///< Vendor/Manufacturer id
    uint16_t            fw_id;                      ///< Firmware id
    uint16_t            fw_frag_sz;                 ///< Meta data fragment size for firmware update
    uint16_t            hw_ver;                     ///< Hardware version the firmware is intended for; zero if inapplicable
    uint8_t             fw_tgt;                     ///< Firmware target to update
    uint8_t             poll_ctl;                   ///< Polling control: 0 = off, 1 = on
    zwpoll_req_t        poll_req;                   ///< Polling request
    uint32_t            poll_id;                    ///< Polling request identifier
    int                 poll_id_type;               ///< Polling request identifier type: 0=handle, 1=token
    uint8_t             pow_lvl;                    ///< Power level indicator value
    uint8_t             pow_lvl_timeout;            ///< Power level timeout value: 1-255
    uint8_t             pow_lvl_test_node_desc_id;      ///< Power level test node descriptor ID
    uint16_t            pow_lvl_test_wframcnt;      ///< Power level test frame count
#ifdef  USER_APPL_DEVICE_CFG
    dev_cfg_buf_t       dev_cfg_bufs[4];            ///< buffers that store an arrays of device specific configurations
                                                    ///< with the first buffer has the highest priority for device matching
#endif
    uint8_t            sw_color_lvl_change_started; ///< Flag to indicate whether switch color level change started

} hl_appl_ctx_t;

#define  DESC_TYPE_NODE     1
#define  DESC_TYPE_EP       2
#define  DESC_TYPE_INTF     3

static char *hl_class_str_get(uint16_t cls, uint8_t ver)
{
    switch (cls)
    {
            case COMMAND_CLASS_BASIC:
            {
                return "COMMAND_CLASS_BASIC";
            }
            break;

            case COMMAND_CLASS_SWITCH_MULTILEVEL:
            {
                return "COMMAND_CLASS_SWITCH_MULTILEVEL";
            }
            break;

            case COMMAND_CLASS_SWITCH_BINARY:
            {
                return "COMMAND_CLASS_SWITCH_BINARY";
            }
            break;

            case COMMAND_CLASS_SWITCH_ALL:
            {
                return "COMMAND_CLASS_SWITCH_ALL";
            }
            break;

            case COMMAND_CLASS_MANUFACTURER_SPECIFIC:
            {
                return "COMMAND_CLASS_MANUFACTURER_SPECIFIC";
            }
            break;

            case COMMAND_CLASS_VERSION:
            {
                return "COMMAND_CLASS_VERSION";
            }
            break;

            case COMMAND_CLASS_POWERLEVEL:
            {
                return "COMMAND_CLASS_POWERLEVEL";
            }
            break;

            case COMMAND_CLASS_CONTROLLER_REPLICATION:
            {
                return "COMMAND_CLASS_CONTROLLER_REPLICATION";
            }
            break;

            case COMMAND_CLASS_NODE_NAMING:
            {
                return "COMMAND_CLASS_NODE_NAMING";
            }
            break;

            case COMMAND_CLASS_SENSOR_BINARY:
            {
                return "COMMAND_CLASS_SENSOR_BINARY";
            }
            break;

            case COMMAND_CLASS_SENSOR_MULTILEVEL:
            {
                return "COMMAND_CLASS_SENSOR_MULTILEVEL";
            }
            break;

            case COMMAND_CLASS_ASSOCIATION:
            {
                return "COMMAND_CLASS_ASSOCIATION";
            }
            break;

            case COMMAND_CLASS_MULTI_CHANNEL_ASSOCIATION_V2:
            {
                if (ver >= 2)
                {
                    return "COMMAND_CLASS_MULTI_CHANNEL_ASSOCIATION";
                }
                return "COMMAND_CLASS_MULTI_INSTANCE_ASSOCIATION";
            }
            break;

            case COMMAND_CLASS_ASSOCIATION_COMMAND_CONFIGURATION:
            {
                return "COMMAND_CLASS_ASSOCIATION_COMMAND_CONFIGURATION";
            }
            break;

            case COMMAND_CLASS_NO_OPERATION:
            {
                return "COMMAND_CLASS_NO_OPERATION";
            }
            break;

            case COMMAND_CLASS_MULTI_CHANNEL_V2:
            {
                if (ver >= 2)
                {
                    return "COMMAND_CLASS_MULTI_CHANNEL";
                }
                return "COMMAND_CLASS_MULTI_INSTANCE";
            }
            break;

            case COMMAND_CLASS_WAKE_UP:
            {
                return "COMMAND_CLASS_WAKE_UP";
            }
            break;

            case COMMAND_CLASS_MANUFACTURER_PROPRIETARY:
            {
                return "COMMAND_CLASS_MANUFACTURER_PROPRIETARY";
            }
            break;

            case COMMAND_CLASS_METER_TBL_MONITOR:
            {
                return "COMMAND_CLASS_METER_TBL_MONITOR";
            }
            break;

            case COMMAND_CLASS_METER_TBL_CONFIG:
            {
                return "COMMAND_CLASS_METER_TBL_CONFIG";
            }
            break;

            case COMMAND_CLASS_METER:
            {
                return "COMMAND_CLASS_METER";
            }
            break;

            case COMMAND_CLASS_METER_PULSE:
            {
                return "COMMAND_CLASS_METER_PULSE";
            }
            break;

            case COMMAND_CLASS_SIMPLE_AV_CONTROL:
            {
                return "COMMAND_CLASS_SIMPLE_AV_CONTROL";
            }
            break;

            case COMMAND_CLASS_CONFIGURATION:
            {
                return "COMMAND_CLASS_CONFIGURATION";
            }
            break;

            case COMMAND_CLASS_INDICATOR:
            {
                return "COMMAND_CLASS_INDICATOR";
            }
            break;

            case COMMAND_CLASS_SECURITY:
            {
                return "COMMAND_CLASS_SECURITY";
            }
            break;

            case COMMAND_CLASS_SECURITY_2:
            {
                return "COMMAND_CLASS_SECURITY_2";
            }
            break;

            case COMMAND_CLASS_HAIL:
            {
                return "COMMAND_CLASS_HAIL";
            }
            break;

            case COMMAND_CLASS_PROTECTION:
            {
                return "COMMAND_CLASS_PROTECTION";
            }
            break;

            case COMMAND_CLASS_SWITCH_TOGGLE_BINARY:
            {
                return "COMMAND_CLASS_SWITCH_TOGGLE_BINARY";
            }
            break;

            case COMMAND_CLASS_BATTERY:
            {
                return "COMMAND_CLASS_BATTERY";
            }
            break;

            case COMMAND_CLASS_DOOR_LOCK:
            {
                return "COMMAND_CLASS_DOOR_LOCK";
            }
            break;

            case COMMAND_CLASS_USER_CODE:
            {
                return "COMMAND_CLASS_USER_CODE";
            }
            break;

            case COMMAND_CLASS_ALARM:
            {
                if (ver >= 3)
                {
                    return "COMMAND_CLASS_NOTIFICATION";
                }
                return "COMMAND_CLASS_ALARM";
            }
            break;

            case COMMAND_CLASS_SCHEDULE_ENTRY_LOCK:
            {
                return "COMMAND_CLASS_SCHEDULE_ENTRY_LOCK";
            }
            break;

            case COMMAND_CLASS_DOOR_LOCK_LOGGING:
            {
                return "COMMAND_CLASS_DOOR_LOCK_LOGGING";
            }
            break;

            case COMMAND_CLASS_TIME_PARAMETERS:
            {
                return "COMMAND_CLASS_TIME_PARAMETERS";
            }
            break;

            case COMMAND_CLASS_CRC_16_ENCAP:
            {
                return "COMMAND_CLASS_CRC_16_ENCAP";
            }
            break;

            case COMMAND_CLASS_TRANSPORT_SERVICE:
            {
                return "COMMAND_CLASS_TRANSPORT_SERVICE";
            }
            break;

            case COMMAND_CLASS_ZIP:
            {
                return "COMMAND_CLASS_ZIP";
            }
            break;

            case COMMAND_CLASS_NETWORK_MANAGEMENT_PROXY:
            {
                return "COMMAND_CLASS_NETWORK_MANAGEMENT_PROXY";
            }
            break;

            case COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION:
            {
                return "COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION";
            }
            break;

            case COMMAND_CLASS_NETWORK_MANAGEMENT_BASIC:
            {
                return "COMMAND_CLASS_NETWORK_MANAGEMENT_BASIC";
            }
            break;

            case COMMAND_CLASS_NETWORK_MANAGEMENT_PRIMARY:
            {
                return "COMMAND_CLASS_NETWORK_MANAGEMENT_PRIMARY";
            }
            break;

            case COMMAND_CLASS_THERMOSTAT_FAN_MODE:
            {
                return "COMMAND_CLASS_THERMOSTAT_FAN_MODE";
            }
            break;

            case COMMAND_CLASS_THERMOSTAT_FAN_STATE:
            {
                return "COMMAND_CLASS_THERMOSTAT_FAN_STATE";
            }
            break;

            case COMMAND_CLASS_THERMOSTAT_MODE:
            {
                return "COMMAND_CLASS_THERMOSTAT_MODE";
            }
            break;

            case COMMAND_CLASS_THERMOSTAT_OPERATING_STATE:
            {
                return "COMMAND_CLASS_THERMOSTAT_OPERATING_STATE";
            }
            break;

            case COMMAND_CLASS_THERMOSTAT_SETPOINT:
            {
                return "COMMAND_CLASS_THERMOSTAT_SETPOINT";
            }
            break;

            case COMMAND_CLASS_THERMOSTAT_SETBACK:
            {
                return "COMMAND_CLASS_THERMOSTAT_SETBACK";
            }
            break;

            case COMMAND_CLASS_CLOCK:
            {
                return "COMMAND_CLASS_CLOCK";
            }
            break;

            case COMMAND_CLASS_LOCK:
            {
                return "COMMAND_CLASS_LOCK";
            }
            break;

            case COMMAND_CLASS_CLIMATE_CONTROL_SCHEDULE:
            {
                return "COMMAND_CLASS_CLIMATE_CONTROL_SCHEDULE";
            }
            break;

            case COMMAND_CLASS_MULTI_CMD:
            {
                return "COMMAND_CLASS_MULTI_CMD";
            }
            break;

            case COMMAND_CLASS_APPLICATION_STATUS:
            {
                return "COMMAND_CLASS_APPLICATION_STATUS";
            }
            break;

            case COMMAND_CLASS_FIRMWARE_UPDATE_MD:
            {
                return "COMMAND_CLASS_FIRMWARE_UPDATE_MD";
            }
            break;

            case COMMAND_CLASS_ZWAVEPLUS_INFO:
            {
                return "COMMAND_CLASS_ZWAVEPLUS_INFO";
            }
            break;

            case COMMAND_CLASS_DEVICE_RESET_LOCALLY:
            {
                return "COMMAND_CLASS_DEVICE_RESET_LOCALLY";
            }
            break;

            case COMMAND_CLASS_ASSOCIATION_GRP_INFO:
            {
                return "COMMAND_CLASS_ASSOCIATION_GRP_INFO";
            }
            break;

            case COMMAND_CLASS_SCENE_ACTIVATION:
            {
                return "COMMAND_CLASS_SCENE_ACTIVATION";
            }
            break;

            case COMMAND_CLASS_SCENE_ACTUATOR_CONF:
            {
                return "COMMAND_CLASS_SCENE_ACTUATOR_CONF";
            }
            break;

            case COMMAND_CLASS_SCENE_CONTROLLER_CONF:
            {
                return "COMMAND_CLASS_SCENE_CONTROLLER_CONF";
            }
            break;

            case COMMAND_CLASS_ZIP_GATEWAY:
            {
                return "COMMAND_CLASS_ZIP_GATEWAY";
            }
            break;

            case COMMAND_CLASS_ZIP_PORTAL:
            {
                return "COMMAND_CLASS_ZIP_PORTAL";
            }
#ifdef  TEST_EXT_CMD_CLASS
            case COMMAND_CLASS_EXT_TEST:        //Testing of extended command class
            {
                return "COMMAND_CLASS_EXT_TEST";
            }
            break;
#endif
            /******************skysoft******************/
            case COMMAND_CLASS_SWITCH_COLOR:
            {
                return "COMMAND_CLASS_SWITCH_COLOR";
            }
            break;

            case COMMAND_CLASS_BASIC_TARIFF_INFO:
            {
                return "COMMAND_CLASS_BASIC_TARIFF_INFO";
            }
            break;

            case COMMAND_CLASS_BARRIER_OPERATOR:
            {
                return "COMMAND_CLASS_BARRIER_OPERATOR";
            }
            break;

            case COMMAND_CLASS_LANGUAGE:
            {
                return "COMMAND_CLASS_LANGUAGE";
            }
            break;

            case COMMAND_CLASS_CENTRAL_SCENE:
            {
                return "COMMAND_CLASS_CENTRAL_SCENE";
            }
            break;

            case COMMAND_CLASS_ZIP_NAMING:
            {
                return "COMMAND_CLASS_ZIP_NAMING";
            }
            break;

            case COMMAND_CLASS_IP_ASSOCIATION:
            {
                return "COMMAND_CLASS_IP_ASSOCIATION";
            }
            break;

            /******************skysoft******************/
        default:
            return "UNKNOWN";
    }
}


/**
prompt_str - prompt for a string from user
@param[in] disp_str   The prompt string to display
@param[in] out_buf_sz The size of out_str buffer
@param[out] out_str   The buffer where the user input string to be stored
@return          The out_str if successful; else NULL.
*/
static char  *prompt_str(hl_appl_ctx_t *hl_appl, const char *disp_str, int out_buf_sz, char *out_str)
{
    int retry;
    puts(disp_str);
    retry = 3;
    while (retry-- > 0)
    {
        if (fgets(out_str, out_buf_sz, stdin) && (*out_str) && ((*out_str) != '\n'))
        {
            char *newline;
            //Remove newline character

            newline = strchr(out_str, '\n');
            if (newline)
            {
                *newline = '\0';
            }
            return out_str;
        }
    }
    return NULL;
}


/**
prompt_hex - prompt for an hexadecimal unsigned integer input from user
@param[in] str   The prompt string to display
@return          The unsigned integer that user has input
*/
static unsigned prompt_hex(hl_appl_ctx_t *hl_appl, char *str)
{
    char user_input_str[36];
    unsigned  ret;

    if (prompt_str(hl_appl, str, 36, user_input_str))
    {
#ifdef USE_SAFE_VERSION
        if (sscanf_s(user_input_str, "%x", &ret) == 1)
        {
            return ret;
        }
#else
        if (sscanf(user_input_str, "%x", &ret) == 1)
        {
            return ret;
        }
#endif
    }
    return 0;
}


/**
prompt_char - prompt for a character input from user
@param[in] str   The prompt string to display
@return          The character that user has input. Null character on error.
*/
static char prompt_char(hl_appl_ctx_t *hl_appl, char *str)
{
    char ret[80];

    if (prompt_str(hl_appl, str, 80, ret))
    {
        return ret[0];
    }
    return 0;
}


/**
prompt_yes - prompt for yes or no from user
@param[in] str   The prompt string to display
@return          1 = user has input yes, 0 =  user has input no
*/
static int prompt_yes(hl_appl_ctx_t *hl_appl, char *str)
{
    char c;

    c = prompt_char(hl_appl, str);
    if (c == 'y' || c == 'Y')
    {
        return 1;
    }
    return 0;
}


/**
hex2bin - Convert hex character to binary
@param[in] c        hex character
@return  Value of hex character on success, negative value on failure
*/
static int hex2bin(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c-'0';
    }
    else if (c >= 'a' && c <= 'f')
    {
        return c-'a' + 10;
    }
    else if (c >= 'A' && c <= 'F')
    {
        return c-'A' + 10;
    }
    else
    {
        return -1;
    }
}


/**
hexstring_to_bin - Convert ASCII hexstring to binary string
@param[in] psk_str   ASCII hexstring
@param[in] psk_len   ASCII hexstring length (must be even number)
@param[out] psk_bin  Binary string
@return  Zero on success, non-zero on failure
*/
static int hexstring_to_bin(char *psk_str, int psk_len, uint8_t *psk_bin)
{
    int i = 0;
    int val;

    while(psk_len > 0)
    {
      val = hex2bin(*psk_str++);
      if(val < 0)
          return -1;
      psk_bin[i]  = (val & 0x0F) << 4;

      val = hex2bin(*psk_str++);
      if(val < 0)
          return -1;
      psk_bin[i] |= (val & 0x0F);

      i++;
      psk_len -= 2;
    }

    return 0;
}


/**
config_param_get - get configuration parameters
@param[in] cfg_file     Configuration file name
@param[out] host_port   Host port
@param[out] router      Z/IP router IP address
@param[out] psk         DTLS pre-shared key (PSK)
@return         ZW_ERR_XXX
*/
static int config_param_get(char *cfg_file, uint16_t *host_port, char *router, char *psk)
{
    FILE        *file;
    const char  delimiters[] = " =\r\n";
    char        line[384];
    char        *prm_name;
    char        *prm_val;

    //Initialize output
    *router = '\0';
    *psk = '\0';
    *host_port = 0;

    //Open config file
    if (!cfg_file)
    {
        return ZW_ERR_FILE_OPEN;
    }

    file = fopen(cfg_file, "rt");
    if (!file)
    {
        return ZW_ERR_FILE_OPEN;
    }

    while (fgets(line, 384, file))
    {
        if (*line == '#')
        {   //Skip comment line
            continue;
        }

        //Check if '=' exists
        if (strchr(line, '='))
        {
            //Get the parameter name and value
            prm_name = strtok(line, delimiters);

            if (prm_name)
            {
                prm_val = strtok(NULL, delimiters);

                if (!prm_val)
                {
                    continue;
                }

                //Compare the parameter name
                if (strcmp(prm_name, "ZipLanPort") == 0)
                {
                    unsigned port;
                    if (sscanf(prm_val, "%u", &port) == 1)
                    {
                        *host_port = (uint16_t)port;
                    }
                }
                else if (strcmp(prm_name, "ZipRouterIP") == 0)
                {
                    strcpy(router, prm_val);
                }
                else if (strcmp(prm_name, "DTLSPSK") == 0)
                {
                    strcpy(psk, prm_val);
                }
            }
        }
    }

    fclose(file);

    return 0;
}


/**
hl_nw_tx_cb - Callback function to notify application transmit data status
@param[in]  user        The high-level api context
param[in]   tx_sts      Transmit status ZWNET_TX_xx
@return
*/
static void hl_nw_tx_cb(void *user, uint8_t tx_sts)
{
    static const char    *tx_cmplt_sts[] = {"ok",
        "timeout: no ACK received",
        "system error",
        "destination host needs long response time",
        "frame failed to reach destination host"
    };

    if (tx_sts == TRANSMIT_COMPLETE_OK)
    {
        //printf("Higher level appl send data completed successfully\n");
    }
    else
    {
        printf("Higher level appl send data completed with error:%s\n",
               (tx_sts < sizeof(tx_cmplt_sts)/sizeof(char *))? tx_cmplt_sts[tx_sts]  : "unknown");
    }
}


/**
hl_nw_node_cb - Callback function to notify node is added, deleted, or updated
@param[in]  user        The high-level api context
@param[in]  noded   Node
@param[in]  mode        The node status
@return
*/
static void hl_nw_node_cb(void *user, zwnoded_p noded, int mode)
{
    switch (mode)
    {
        case ZWNET_NODE_ADDED:
            {
                printf("\nNode:%u added\n", (unsigned)noded->nodeid);
            }
            break;

        case ZWNET_NODE_REMOVED:
            {
                printf("\nNode:%u removed\n", (unsigned)noded->nodeid);
            }
            break;
    }
}

/**
gw_intf_get - Search for the Z/IP gateway interface
@param[in]  net     network handle
@param[out] gw_if   Z/IP gateway interface
@return  0 on success; otherwise negative number
*/
static int gw_intf_get(zwnet_p net, zwifd_t *gw_if)
{
    int         result;
    zwnoded_t   node;
    zwepd_t     ep;
    zwifd_t     intf;

    //Get first node (controller node)
    result = zwnet_get_node(net, &node);
    if (result != 0)
    {
        return result;
    }

    if (!zwnode_get_ep(&node, &ep)) //get first endpoint of the node
    {
        if (!zwep_get_if(&ep, &intf)) //get first interface of the endpoint
        {
            do
            {
                if (intf.cls == COMMAND_CLASS_ZIP_GATEWAY)
                {   //Found
                    *gw_if = intf;
                    return 0;
                }

            }while (!zwif_get_next(&intf, &intf)); //get next interface
        }
    }

    return  ZW_ERR_INTF_NOT_FOUND;
}

/**
hl_unsolicited_addr_setup - Setup unsolicited address to receive unsolicited report
@param[in]  hl_appl     The high-level api context
@return  0 on success, negative error number on failure
*/
static int hl_unsolicited_addr_setup(hl_appl_ctx_t *hl_appl)
{
    int         result;
    uint8_t     local_ip[16];
    uint16_t    local_port;
    zwifd_t     gw_ifd;

    //Get local Z/IP client listening address and port
    result = zwnet_local_addr_get(hl_appl->zwnet, hl_appl->zip_gw_ip, local_ip, hl_appl->use_ipv4);
    printf(" local_ip: %d-%d-%d-%d-%d-%d-%d-%d-%d-%d-%d-%d-%d-%d-%d-%d",
                     local_ip[0],local_ip[1],local_ip[2],local_ip[3],local_ip[4],local_ip[5],local_ip[6]
                     ,local_ip[7],local_ip[8],local_ip[9],local_ip[10],local_ip[11],local_ip[12],local_ip[13],local_ip[14],local_ip[15]
                     );

    local_ip[0] = 192;
    local_ip[1] = 168;
    local_ip[2] = 47;
    local_ip[3] = 1;

    if (result != 0)
    {
        printf("Error: couldn't get local Z/IP client listening address: %d\n", result);
        return result;
    }

    local_port = zwnet_listen_port_get(hl_appl->zwnet);

    if (hl_appl->use_ipv4)
    {   //Convert to IPv4-mapped IPv6 address
        uint8_t unsolicit_ipv4[4];

        //Save the IPv4 address
        memcpy(unsolicit_ipv4, local_ip, 4);

        //Convert the IPv4 address to IPv4-mapped IPv6 address
        memset(local_ip, 0, 10);
        local_ip[10] = 0xFF;
        local_ip[11] = 0xFF;
        memcpy(&local_ip[12], unsolicit_ipv4, 4);
    }

    result = gw_intf_get(hl_appl->zwnet, &gw_ifd);
    if (result != 0)
    {
        printf("Error: couldn't find Z/IP gateway interface: %d\n", result);
        return result;
    }

    result = zwif_gw_unsolicit_set(&gw_ifd, local_ip, local_port);

    if (result != 0)
    {
        printf("Error: couldn't set unsolicited address: %d\n", result);
    }

    return result;

}

/**
hl_nw_notify_cb - Callback function to notify the status of current operation
@param[in]  user        user context
@param[in]  op          network operation ZWNET_OP_XXX
@param[in]  sts         status of current operation
@param[in]  info        additional information for the specified op and sts; NULL if there is no additional info
@return
*/
static void hl_nw_notify_cb(void *user, uint8_t op, uint16_t sts, zwnet_sts_t *info)
{
    hl_appl_ctx_t *hl_appl = (hl_appl_ctx_t *)user;

    //Check whether the status is progress status of discovering each detailed node information
    if (sts & OP_GET_NI_TOTAL_NODE_MASK)
    {
        uint16_t    total_nodes;
        uint16_t    cmplt_nodes;

        total_nodes = (sts & OP_GET_NI_TOTAL_NODE_MASK) >> 8;
        cmplt_nodes = sts & OP_GET_NI_NODE_CMPLT_MASK;
        printf("Get node info %u/%u completed\n", cmplt_nodes, total_nodes);
        return;
    }

    switch (op)
    {
        case ZWNET_OP_INITIALIZE:
            printf("\nInitialization status:%u\n",(unsigned)sts);
            if (sts == OP_DONE)
            {
                hl_appl->init_status = 1;
                if (hl_unsolicited_addr_setup(hl_appl) == 0)
                {
                    printf("setting unsolicited address done!\n");
                    hl_appl->init_status = 2;
                    show_menu();
                }
            }
            else
            {
                printf("Press 'x' to exit ...\n");
            }
            break;

        case ZWNET_OP_ADD_NODE:
            printf("Add node status:%u\n",(unsigned)sts);
            if (sts == OP_DONE)
            {   //Clear add node DSK callback control & status
                hl_appl->sec2_cb_enter = 0;
                hl_appl->sec2_cb_exit = 1;

                hl_appl->add_status = ADD_NODE_STS_DONE;
            }
            else if (sts == OP_FAILED)
            {   //Clear add node DSK callback control & status
                hl_appl->sec2_cb_enter = 0;
                hl_appl->sec2_cb_exit = 1;

                hl_appl->add_status = ADD_NODE_STS_UNKNOWN;
            }


            if (hl_appl->add_status != ADD_NODE_STS_PROGRESS)
            {
                printf("\n(1) Add node\n(x) Exit\n");
                printf("Select your choice:\n");
            }
            break;

        default:
            printf("hl_nw_notify_cb op:%u, status:%u\n", (unsigned)op, (unsigned)sts);
    }
}


/**
lib_init - Initialize library
@param[in]  hl_appl             The high-level api context
@param[in]  host_port           Host listening port
@param[in]  zip_router_ip       Z/IP router IP address in numerical form
@param[in]  use_ipv4            Flag to indicate zip_router_ip is in IPv4 or IPv6 format. 1= IPv4; 0= IPv6
@param[in]  dev_cfg_file_name   Device specific configuration database file name
@param[in]  dtls_psk            DTLS pre-shared key
@param[in]  dtls_psk_len        DTLS pre-shared key length (in bytes)
@param[in]  pref_dir            Full path of directory for storing network/user preference files
@return  0 on success, negative error number on failure
*/
int lib_init(hl_appl_ctx_t *hl_appl, uint16_t host_port, uint8_t *zip_router_ip, int use_ipv4,
             char *dev_cfg_file_name, uint8_t *dtls_psk, uint8_t dtls_psk_len, char *pref_dir)
{
    int                 result;
    zwnet_init_t        zw_init = {0};

    zw_init.user = hl_appl; //high-level application context
    zw_init.node = hl_nw_node_cb;
    zw_init.notify = hl_nw_notify_cb;
    zw_init.appl_tx = hl_nw_tx_cb;
    zw_init.pref_dir = pref_dir;
    zw_init.print_txt_fn = NULL;
    zw_init.net_info_dir = NULL;
    zw_init.host_port = host_port;
    zw_init.use_ipv4 = use_ipv4;
    memcpy(zw_init.zip_router, zip_router_ip, (use_ipv4)? IPV4_ADDR_LEN : IPV6_ADDR_LEN);
    zw_init.dev_cfg_file = dev_cfg_file_name;
    zw_init.dev_cfg_usr = NULL;
    zw_init.dtls_psk_len = dtls_psk_len;
    if (dtls_psk_len)
    {
        memcpy(zw_init.dtls_psk, dtls_psk, dtls_psk_len);
    }
    //Unhandled command handler
    zw_init.unhandled_cmd = NULL;

    //Init ZW network
    result = zwnet_init(&zw_init, &hl_appl->zwnet);

    if (result != 0)
    {
        printf("zwnet_init with error:%d\n", result);

        //Display device configuration file error
        if (zw_init.err_loc.dev_ent)
        {
            printf("Parsing device configuration file error loc:\n");
            printf("Device entry number:%u\n", zw_init.err_loc.dev_ent);
            if (zw_init.err_loc.ep_ent)
            {
                printf("Endpoint entry number:%u\n", zw_init.err_loc.ep_ent);
            }

            if (zw_init.err_loc.if_ent)
            {
                printf("Interface entry number:%u\n", zw_init.err_loc.if_ent);
            }
        }
        return result;
    }

    return 0;
}


/**
nw_init - initialization network
@param[in] hl_appl   user application context
@return  0 on success; otherwise negative number
*/
int nw_init(hl_appl_ctx_t *hl_appl)
{
    int             ret;
    char            zip_gw_addr_str[100];
    uint16_t        host_port;                  ///< Host listening port
    char            psk_str[384];
    int             psk_len;
    uint8_t         dtls_psk[MAX_DTLS_PSK/2];   ///< DTLS pre-shared key
    uint8_t         zip_gw_ip[16];              ///< Z/IP gateway address in IPv4 or IPv6

    //Read config file to get configuration parameters
    ret = config_param_get("app.cfg", &host_port, zip_gw_addr_str, psk_str);
    if (ret != 0)
    {
        printf("Error: couldn't get config param from file: app.cfg\n");
        return ret;
    }

    //Check DTLS pre-shared key validity
    psk_len = strlen(psk_str);

    if (psk_len > 0)
    {
        if (psk_len > MAX_DTLS_PSK)
        {
            printf("PSK string length is too long\n");
            return ZW_ERR_VALUE;
        }
        if (psk_len % 2)
        {
            printf("PSK string length should be even\n");
            return ZW_ERR_VALUE;
        }
        //Convert ASCII hexstring to binary string
        ret = hexstring_to_bin(psk_str, psk_len, dtls_psk);
        if (ret != 0)
        {
            printf("PSK string is not hex string\n");
            return ZW_ERR_VALUE;
        }
    }

    //Convert IPv4 / IPv6 address string to numeric equivalent
    ret = zwnet_ip_aton(zip_gw_addr_str, zip_gw_ip, &hl_appl->use_ipv4);

    if (ret != 0)
    {
        printf("Invalid Z/IP router IP address:%s\n", zip_gw_addr_str);
        return ZW_ERR_IP_ADDR;
    }

    //Initialize library
    ret = lib_init(hl_appl, host_port, zip_gw_ip, hl_appl->use_ipv4, "zwave_device_rec.txt" /*device info database file*/,
                  dtls_psk, psk_len/2, NULL);

    if (ret < 0)
    {
        printf("lib_init with error: %d\n", ret);
    }
    return ret;
}


/**
hl_add_node_s2_cb - callback for add node with security 2 operation to report Device Specific Key (DSK)
@param[in]  usr_param  user supplied parameter when calling zwnet_add
@param[in]  cb_param   DSK related callback parameters
*/
static void hl_add_node_s2_cb(void *usr_param, sec2_add_cb_prm_t *cb_param)
{
    hl_appl_ctx_t *hl_appl = (hl_appl_ctx_t *)usr_param;
    int           res;

    if (cb_param->cb_type == S2_CB_TYPE_REQ_KEY)
    {
        uint8_t granted_key;
        uint8_t grant_csa;

        if (hl_appl->sec2_cb_enter & SEC2_ENTER_KEY_REQ)
        {   //Requested keys callback is allowed
            hl_appl->sec2_cb_enter &= ~SEC2_ENTER_KEY_REQ;
        }
        else
        {
            printf("\nNot allowed to processed Security 2 requested keys callback!\n");
            return;
        }

        printf("\nDevice requested keys bit-mask: %02Xh\n", cb_param->cb_prm.req_key.req_keys);

        printf("Key (bit-mask in hex) :\n");
        printf("                      Security 2 key 0 (01)\n");
        printf("                      Security 2 key 1 (02)\n");
        printf("                      Security 2 key 2 (04)\n");
        printf("                      Security 0       (80)\n");

        granted_key = prompt_hex(hl_appl, "Grant keys bit-mask (hex):");

        grant_csa = 0;
        if (cb_param->cb_prm.req_key.req_csa)
        {
            printf("Device requested for client-side authentication (CSA)\n");
            if (prompt_yes(hl_appl, "Grant CSA (y/n)?:"))
            {
                grant_csa = 1;
                printf("Please enter this 10-digit CSA Pin into the joining device:%s\n", cb_param->cb_prm.req_key.csa_pin);
            }
            //No DSK callback when in CSA mode
            hl_appl->sec2_cb_enter &= ~SEC2_ENTER_DSK;

        }

        res = zwnet_add_sec2_grant_key(hl_appl->zwnet, granted_key, grant_csa);

        if (res != 0)
        {
            printf("zwnet_add_sec2_grant_key with error: %d\n", res);
        }

        //Check whether if there is DSK callback pending
        if (!(hl_appl->sec2_cb_enter))
        {   //No callback pending
            hl_appl->sec2_cb_exit = 1;
        }
    }
    else
    {
        sec2_dsk_cb_prm_t   *dsk_prm;
        int                 accept;
        char                dsk_str[200];

        if (hl_appl->sec2_cb_enter & SEC2_ENTER_DSK)
        {   //DSK callback is allowed
            hl_appl->sec2_cb_enter &= ~SEC2_ENTER_DSK;
        }
        else
        {
            printf("\nNot allowed to processed Security 2 DSK callback!\n");
            return;
        }

        dsk_prm = &cb_param->cb_prm.dsk;

        if (dsk_prm->pin_required)
        {
            printf("\nReceived DSK: XXXXX%s\n", dsk_prm->dsk);
        }
        else
        {
            printf("\nReceived DSK: %s\n", dsk_prm->dsk);
        }

        accept = prompt_yes(hl_appl, "Do you accept this device to be added securely (y/n)?:");

        printf("You %s the device.\n", (accept)? "accepted" : "rejected");

        if (accept && dsk_prm->pin_required)
        {
            if (prompt_str(hl_appl, "Enter 5-digit PIN that matches the received DSK:", 200, dsk_str))
            {

#ifdef USE_SAFE_VERSION
                strcat_s(dsk_str, 200, dsk_prm->dsk);
#else
                strcat(dsk_str, dsk_prm->dsk);
#endif
            }
        }

        res = zwnet_add_sec2_accept(hl_appl->zwnet, accept, (dsk_prm->pin_required)? dsk_str : dsk_prm->dsk);

        if (res != 0)
        {
            printf("zwnet_add_sec2_accept with error: %d\n", res);
        }

        hl_appl->sec2_cb_exit = 1;
    }
}


/**
hl_add_node - Add node
@param[in]  hl_appl  Application context
@return zero if successful; else negative error number
*/
static int hl_add_node(hl_appl_ctx_t *hl_appl)
{
    int     res;
    char    dsk_str[200];
    zwnetd_p netdesc;

    netdesc = zwnet_get_desc(hl_appl->zwnet);

    if (netdesc->ctl_cap & ZWNET_CTLR_CAP_S2)
    {
        printf("Controller supports security 2.\n");
        hl_appl->sec2_add_node = 1;
    }
    else
    {
        hl_appl->sec2_add_node = 0;
    }

    if (hl_appl->sec2_add_node)
    {
        hl_appl->sec2_add_prm.dsk = NULL;

        if (prompt_yes(hl_appl, "Pre-enter Device Specific Key (DSK) (y/n)?:"))
        {
            if (prompt_str(hl_appl, "DSK:", 200, dsk_str))
            {
                hl_appl->sec2_add_prm.dsk = dsk_str;
            }
        }

        hl_appl->sec2_add_prm.usr_param = hl_appl;

        hl_appl->sec2_add_prm.cb = hl_add_node_s2_cb;

    }

    res = zwnet_add(hl_appl->zwnet, 1, (hl_appl->sec2_add_node)? &hl_appl->sec2_add_prm : NULL, 0);

    if (res == 0)
    {
        if (hl_appl->sec2_add_node)
        {
            int wait_count;

            hl_appl->sec2_cb_enter = SEC2_ENTER_KEY_REQ;

            if (!hl_appl->sec2_add_prm.dsk)
            {   //No pre-entered DSK, requires DSK callback
                hl_appl->sec2_cb_enter |= SEC2_ENTER_DSK;
            }

            hl_appl->sec2_cb_exit = 0;

            printf("Waiting for Requested keys and/or DSK callback ...\n");

            //Wait for S2 callback to exit
            wait_count = 600;    //Wait for 60 seconds
            while (wait_count-- > 0)
            {
                if (hl_appl->sec2_cb_exit == 1)
                    break;
                plt_sleep(100);
            }
        }
    }

    return res;

}

/**
bin_sensor_intf_get - Search for the first binary sensor interface
@param[in]  net             network handle
@param[out] bin_sensor_if   first binary sensor interface found
@return  0 on success; otherwise negative number
*/
static int firmware_update_intf_get(zwnet_p net, zwifd_t *firmware_if)
{
    int         result;
    zwnoded_t   node;
    zwepd_t     ep;
    zwifd_t     intf;

    //Get first node (controller node)
    result = zwnet_get_node(net, &node);
    if (result != 0)
    {
        return result;
    }

    do 
    {
        if (!zwnode_get_ep(&node, &ep)) //get first endpoint of the node
        {
            do
            {
                if (!zwep_get_if(&ep, &intf)) //get first interface of the endpoint
                {
                    do
                    {
                        if (intf.cls == COMMAND_CLASS_FIRMWARE_UPDATE_MD)
                        {   //Found
                            *firmware_if = intf;
                            return 0;
                        }

                    }while (!zwif_get_next(&intf, &intf)); //get next interface
                }
            }while (!zwep_get_next(&ep, &ep)); //get next endpoint
        }
    }while (!zwnode_get_next(&node, &node)); //get next node

    return  ZW_ERR_INTF_NOT_FOUND;
}

static void hl_fw_info_report_cb(zwifd_p ifd, zwfw_info_t *fw_info)
{
    printf("__________________________________________________________________________\n");
    printf("Vendor id: %04Xh, z-wave firmware id: %04Xh, checksum: %04Xh\n",
                 fw_info->vid, fw_info->zw_fw_id, fw_info->chksum);

    printf("Max fragment size: %u(%s), upgradable: %s\n",
                 fw_info->max_frag_sz, (fw_info->fixed_frag_sz)? "fixed" : "variable",
                 (fw_info->upgrade_flg == ZW_FW_UPGD_YES)? "Y" : "N");

    if (fw_info->other_fw_cnt)
    {
        int i;
        for (i=0; i<fw_info->other_fw_cnt; i++)
        {
            printf("Firmware target %d id: %04Xh\n",
                         i+1, fw_info->other_fw_id[i]);
        }
    }
    printf("__________________________________________________________________________\n");
}

static void hl_fw_updt_sts_cb(zwifd_p ifd, uint8_t status)
{
    printf("__________________________________________________________________________\n");
    const char *fw_updt_sts_str[] =
    {   "Invalid combination of vendor id and firmware id",
        "Need out-of-band authentication event to enable firmware update",
        "The requested Fragment Size exceeds the Max Fragment Size",
        "This firmware target is not upgradable",
        "OK. Valid combination of vendor id and firmware id",
        "Unknown status"
    };
    int sts_idx;

    if (status <= 3)
    {
        sts_idx = status;
    }
    else if (status == ZW_FW_UPDT_ERR_VALID)
    {
        sts_idx = 4;
    }
    else
    {
        sts_idx = 5;
    }

    printf("Firmware update request status:%s(%u)\n", fw_updt_sts_str[sts_idx], status);
    printf("__________________________________________________________________________\n");
}

/**
hl_fw_updt_cmplt_cb - report callback for firmware update completion status
@param[in]  ifd             interface
@param[in]  status          firmware update completion status, ZW_FW_UPDT_CMPLT_XXX
@param[in]  wait_tm         time (in seconds) that is needed before the receiving node becomes
                            available again for communication after the transfer of an image. This parameter is
                            valid only if wait_tm_valid=1
@param[in]  wait_tm_valid   flag to indicate the wait_tm parameter is valid.
*/
static void hl_fw_updt_cmplt_cb(zwifd_p ifd, uint8_t status, uint16_t wait_tm, int wait_tm_valid)
{
    printf("__________________________________________________________________________\n");
    const char *fw_updt_cmplt_str[] =
    {   "Cheksum error in requested firmware",
        "Download of the requested firmware failed",
        "Firmware updated successfully. Device is ready and operational",
        "Firmware updated successfully. Device will power cycle itself",
        "Unknown status"
    };
    int sts_idx;

    if (status <= 1)
    {
        sts_idx = status;
    }
    else if (status == ZW_FW_UPDT_CMPLT_OK_NO_RESTART)
    {
        sts_idx = 2;
    }
    else if (status == ZW_FW_UPDT_CMPLT_OK_RESTART)
    {
        sts_idx = 3;
    }
    else
    {
        sts_idx = 4;
    }

    printf("Firmware update completion status:%s(%u)\n", fw_updt_cmplt_str[sts_idx], (unsigned)status);

    if (wait_tm_valid)
    {
        printf("Expected device reboot time:%u s\n", (unsigned)wait_tm);
    }
    printf("__________________________________________________________________________\n");
}

/**
hl_fw_updt_restart_cb - report callback for firmware update target restart status
@param[in]  node    node
@param[in]  status  firmware update target restart status, ZW_FW_UPDT_RESTART_XXX
*/
static void hl_fw_updt_restart_cb(zwnoded_p node, uint8_t status)
{
    printf("__________________________________________________________________________\n");
    const char *fw_updt_restart_str[] =
    {   "Node restarted and is ready",
        "Failed"
    };

    printf("Firmware update target restart status of node %u:%s\n",
                    node->nodeid,
                    fw_updt_restart_str[status]);
    printf("__________________________________________________________________________\n");
}

static uint32_t  hl_desc_id_gen(zwnet_p nw)
{
    hl_appl_ctx_t       *hl_appl;
    zwnetd_t            *net_desc;

    net_desc = zwnet_get_desc(nw);

    hl_appl = (hl_appl_ctx_t *)net_desc->user;

    if (hl_appl->desc_id == 0)
    {   //ID of zero is invalid
        hl_appl->desc_id++;
    }
    return hl_appl->desc_id++;
}


static int hl_desc_init(desc_cont_t **head, zwnet_p nw)
{
    int         result;
    zwnoded_t   noded;
    zwepd_t     ep_desc;
    zwifd_t     ifd;
    zwnoded_p   node;
    zwepd_p     ep;
    zwifd_p     intf;
    desc_cont_t *last_node_cont;
    desc_cont_t *last_ep_cont;
    desc_cont_t *last_intf_cont;

    *head = (desc_cont_t *)calloc(1, sizeof(desc_cont_t) + sizeof(zwnoded_t) - 1);
    if (*head == NULL)
    {
        return ZW_ERR_MEMORY;
    }
    (*head)->type = DESC_TYPE_NODE;
    (*head)->id = hl_desc_id_gen(nw);
    node = (zwnoded_p)(*head)->desc;
    last_node_cont = *head;

    result = zwnet_get_node(nw, node);
    if (result != 0)
    {
        //plt_msg_show("hl_desc_init get controller node with error:%d", result);
        return result;
    }

    while (node)
    {
        last_ep_cont = (desc_cont_t *)calloc(1, sizeof(desc_cont_t) + sizeof(zwepd_t) - 1);
        if (!last_ep_cont)
        {
            return ZW_ERR_MEMORY;
        }
        last_ep_cont->type = DESC_TYPE_EP;
        last_ep_cont->id = hl_desc_id_gen(nw);
        ep = (zwepd_p)last_ep_cont->desc;
        zwnode_get_ep(node, ep);
        last_node_cont->down = last_ep_cont;

        while (ep)
        {
            if (zwep_get_if(ep, &ifd) < 0)
            {
                break;
            }

            //Add interfaces
            last_intf_cont = (desc_cont_t *)calloc(1, sizeof(desc_cont_t) + sizeof(zwifd_t) - 1);
            if (!last_intf_cont)
            {
                return ZW_ERR_MEMORY;
            }

            last_intf_cont->type = DESC_TYPE_INTF;
            last_intf_cont->id = hl_desc_id_gen(nw);
            intf = (zwifd_p)last_intf_cont->desc;
            *intf = ifd;
            last_ep_cont->down = last_intf_cont;

            while (intf)
            {
                //Get the next interface
                result = zwif_get_next(intf, &ifd);
                if (result == 0)
                {
                    desc_cont_t     *intf_cont;
                    zwifd_p         ifdp;

                    intf = &ifd;
                    intf_cont = (desc_cont_t *)calloc(1, sizeof(desc_cont_t) + sizeof(zwifd_t) - 1);
                    if (!intf_cont)
                    {
                        return ZW_ERR_MEMORY;
                    }
                    intf_cont->type = DESC_TYPE_INTF;
                    intf_cont->id = hl_desc_id_gen(nw);
                    ifdp = (zwifd_p)intf_cont->desc;
                    *ifdp = ifd;
                    last_intf_cont->next = intf_cont;
                    last_intf_cont = intf_cont;
                }
                else
                {
                    intf = NULL;
                }
            }

            //Get the next endpoint
            result = zwep_get_next(ep, &ep_desc);
            if (result == 0)
            {
                desc_cont_t     *ep_cont;
                zwepd_p         epp;

                ep = &ep_desc;
                ep_cont = (desc_cont_t *)calloc(1, sizeof(desc_cont_t) + sizeof(zwepd_t) - 1);
                if (!ep_cont)
                {
                    return ZW_ERR_MEMORY;
                }
                ep_cont->type = DESC_TYPE_EP;
                ep_cont->id = hl_desc_id_gen(nw);
                epp = (zwepd_p)ep_cont->desc;
                *epp = ep_desc;
                last_ep_cont->next = ep_cont;
                last_ep_cont = ep_cont;

            }
            else
            {
                ep = NULL;
            }
        }

        //Get the next node
        result = zwnode_get_next(node, &noded);
        if (result == 0)
        {
            desc_cont_t     *node_cont;
            zwnoded_p       nodedp;

            node = &noded;

            node_cont = (desc_cont_t *)calloc(1, sizeof(desc_cont_t) + sizeof(zwnoded_t) - 1);
            if (!node_cont)
            {
                return ZW_ERR_MEMORY;
            }
            node_cont->type = DESC_TYPE_NODE;
            node_cont->id = hl_desc_id_gen(nw);
            nodedp = (zwnoded_p)node_cont->desc;
            *nodedp = noded;
            last_node_cont->next = node_cont;
            last_node_cont = node_cont;
        }
        else
        {
            node = NULL;
        }
    }
    return 0;
}

static void hl_ext_ver_show(hl_appl_ctx_t *hl_appl, zwnoded_p node)
{
    ext_ver_t   *ext_ver;
    int         i;
    char str[50] = {0};

    ext_ver = zwnode_get_ext_ver(node);
    if (ext_ver)
    {
        printf("Hardware version:%u\n", (unsigned)(ext_ver->hw_ver));

        for (i=0; i<ext_ver->fw_cnt; i++)
        {
            printf("Firmware %d version:%u.%02u\n", i+1, (unsigned)(ext_ver->fw_ver[i] >> 8),
                         (unsigned)(ext_ver->fw_ver[i] & 0xFF));
        }
        free(ext_ver);
    }
}

void hl_bin2str(void * buf, uint32_t len, char *hex_str, uint32_t hex_str_len)
{
    uint8_t     *bin_byte = (uint8_t *)buf;
    char        tmp[8];

    hex_str[0] = '\0';

    //Convert a line of binary data into hex string
    while (len-- > 0)
    {
        sprintf(tmp,"%02X ",(unsigned) *bin_byte++);
        strcat(hex_str, tmp);
    }
}

static void hl_dev_id_show(hl_appl_ctx_t *hl_appl, dev_id_t *dev_id)
{
    const char *dev_id_type_str[] =
            {
                    "Device id oem",
                    "Device serial number",
                    "Device id unknown type"
            };
    uint8_t   id_type;

    id_type = (uint8_t)((dev_id->type > DEV_ID_TYPE_SN)? 2 : dev_id->type);

    if (dev_id->format == DEV_ID_FMT_UTF)
    {   //UTF-8
        printf("%s:%s\n", dev_id_type_str[id_type], dev_id->dev_id);
    }
    else if (dev_id->format == DEV_ID_FMT_BIN)
    {   //Binary
        char hex_string[(32*3)+1];

        hl_bin2str(dev_id->dev_id, dev_id->len, hex_string, (32*3)+1);
        printf("%s:h'%s\n", dev_id_type_str[id_type], hex_string);
    }
}

static void hl_grp_info_show(zwifd_p intf)
{
    int                 j;
    int                 i;
    int                 result;
    if_grp_info_dat_t   *grp_info;
    void                *plt_ctx;
    zw_grp_info_p       grp_info_ent;
    char str[50] = {0};

    result = zwif_group_info_get(intf, &grp_info);

    if (result == 0)
    {
        printf("                        Group info type:%s\n", (grp_info->dynamic)? "dynamic" : "static");
        printf("                        Maximum supported groups:%u\n", grp_info->group_cnt);
        printf("                        Valid groups:%u\n", grp_info->valid_grp_cnt);

        for (i=0; i<grp_info->valid_grp_cnt; i++)
        {
            grp_info_ent = grp_info->grp_info[i];

            if (grp_info_ent)
            {
                printf("                        --------------------------------------------\n");
                printf("                        Group id:%u, profile:%04xh, event code:%04xh,\n",
                             grp_info_ent->grp_num, grp_info_ent->profile, grp_info_ent->evt_code);
                printf("                        name:%s, command list:\n",
                             grp_info_ent->name);

                for (j=0; j<grp_info_ent->cmd_ent_cnt; j++)
                {
                    printf("                        command class:%04xh(%s), command:%02xh\n",
                                 grp_info_ent->cmd_lst[j].cls,
                                 hl_class_str_get(grp_info_ent->cmd_lst[j].cls, 1),
                                 grp_info_ent->cmd_lst[j].cmd);
                }
            }
        }

        //Free group info
        zwif_group_info_free(grp_info);
    }
}

static void hl_zwaveplus_show(hl_appl_ctx_t *hl_appl, zwplus_info_t *info)
{
    int         idx;
    const char *zwplus_node_type_str[] =
            {
                    "Z-Wave+ node",
                    "Z-Wave+ for IP router",
                    "Z-Wave+ for IP gateway",
                    "Z-Wave+ for IP - client IP node",
                    "Z-Wave+ for IP - client Z-Wave node",
                    "unknown"
            };

    const char *zwplus_role_type_str[] =
            {
                    "Central Static Controller",
                    "Sub Static Controller",
                    "Portable Controller",
                    "Portable Reporting Controller",
                    "Portable Slave",
                    "Always On Slave",
                    "Sleeping Reporting Slave",
                    "Reachable_Sleeping_Slave",
                    "unknown"
            };

    printf("ZWave+ version:%u\n", (unsigned)(info->zwplus_ver));

    idx = (info->node_type <= 4)? info->node_type : 5;
    printf("ZWave+ node type:%s\n", zwplus_node_type_str[idx]);

    idx = (info->role_type <= 7)? info->role_type : 8;
    printf("ZWave+ role type:%s\n", zwplus_role_type_str[idx]);

    char str[50] = {0};

    printf("ZWave+ installer icon:%04Xh\n", (unsigned)(info->instr_icon));

    printf("ZWave+ user icon:%04Xh\n", (unsigned)(info->usr_icon));
    //cJSON_AddStringToObject(EpInfo, "ZWave+ device type", hl_zwaveplus_icon_to_device_type(info->usr_icon));
}

/**
hl_node_desc_dump - dump the node descriptor info
@param[in]  hl_appl     The high-level api context
@return
*/
static int hl_node_desc_dump(hl_appl_ctx_t *hl_appl)
{
    int         result;
    zwnetd_p    net_desc;
    zwnoded_p   node;
    zwepd_p     ep;
    zwifd_p     intf;
    desc_cont_t *last_node_cont;
    desc_cont_t *last_ep_cont;
    desc_cont_t *last_intf_cont;
    char str[100] = {0};

    plt_mtx_lck(hl_appl->desc_cont_mtx);

    //Check whether the descriptor container linked list is initialized
    if (!hl_appl->desc_cont_hd)
    {
        result = hl_desc_init(&hl_appl->desc_cont_hd, hl_appl->zwnet);
        if (result != 0)
        {
            printf("hl_desc_init with error:%d\n", result);
            return result;
        }
    }

    //Get the first node (local controller) and home id
    last_node_cont = hl_appl->desc_cont_hd;

    net_desc = zwnet_get_desc(hl_appl->zwnet);

    while (last_node_cont)
    {
        if (last_node_cont->type != DESC_TYPE_NODE)
        {
            printf("node: wrong desc type:%u\n", last_node_cont->type);
        }

        node = (zwnoded_p)last_node_cont->desc;

        printf("__________________________________________________________________________\n");
        printf("Node id:%u[%u], Home id:%08X\n", (unsigned)node->nodeid,
                     last_node_cont->id, (unsigned)net_desc->id);

        if (node->sleep_cap)
        {
            printf("Node is capable to sleep with wakeup interval:%us\n", node->wkup_intv);
        }

        if (node->sensor)
        {
            printf("Node is FLIRS\n");
        }

        //plt_msg_show(hl_plt_ctx_get(hl_appl), "Node security inclusion status:%s", hl_is_security_inclusion(node->sec_incl_failed));
        printf("Vendor id:%04X\n", node->vid);
        printf("Product type id:%04X\n", node->type);
        printf("Product id:%04X\n", node->pid);
        /*plt_msg_show(hl_plt_ctx_get(hl_appl), "Category:%s", (node->category <= DEV_WALL_CTLR)?
                                                             dev_category_str[node->category] : "unknown");*/
        printf("Z-wave library type:%u\n", node->lib_type);
        printf("Z-wave protocol version:%u.%02u\n", (unsigned)(node->proto_ver >> 8),
                     (unsigned)(node->proto_ver & 0xFF));
        printf("Application version:%u.%02u\n", (unsigned)(node->app_ver >> 8),
                     (unsigned)(node->app_ver & 0xFF));

        hl_ext_ver_show(hl_appl, node);

        if (node->dev_id.len > 0)
        {
            hl_dev_id_show(hl_appl, &node->dev_id);
        }

        //Get endpoint
        last_ep_cont = last_node_cont->down;

        while (last_ep_cont)
        {
            if (last_ep_cont->type != DESC_TYPE_EP)
            {
                printf("ep: wrong desc type:%u\n", last_ep_cont->type);
            }

            ep = (zwepd_p)last_ep_cont->desc;

            printf("Endpoint id:%u[%u]\n", ep->epid, last_ep_cont->id);
            printf("Device class: generic:%02X, specific:%02X\n",
                         ep->generic, ep->specific);

            if (ep->zwplus_info.zwplus_ver)
            {
                hl_zwaveplus_show(hl_appl, &ep->zwplus_info);
            }

            //Get interface
            last_intf_cont = last_ep_cont->down;

            while (last_intf_cont)
            {
                if (last_intf_cont->type != DESC_TYPE_INTF)
                {
                    printf("interface: wrong desc type:%u\n", last_intf_cont->type);
                }

                intf = (zwifd_p)last_intf_cont->desc;

                printf("              Interface: %02Xv%u:%s [%u]%c%c\n",
                             (unsigned)intf->cls, intf->real_ver, hl_class_str_get(intf->cls, intf->real_ver),
                             last_intf_cont->id, (intf->propty & IF_PROPTY_SECURE)? '*' : ' ',
                             (intf->propty & IF_PROPTY_UNSECURE)? '^' : ' ');

                if (intf->cls == COMMAND_CLASS_SENSOR_MULTILEVEL)
                {
                    //hl_sup_sensor_show(intf, InterfaceInfo);
                    //result = zwif_sensor_rpt_set(intf, hl_ml_snsr_rep_cb_1);
                }
                else if (intf->cls == COMMAND_CLASS_ASSOCIATION_GRP_INFO)
                {
                    hl_grp_info_show(intf);
                }
                else if (intf->cls == COMMAND_CLASS_METER)
                {
                    //hl_meter_info_show(intf, InterfaceInfo);
                }
                else if (intf->cls == COMMAND_CLASS_NOTIFICATION_V4)
                {
                    //hl_notification_info_show(intf, InterfaceInfo);
                    //result = zwif_notification_rpt_set(intf, hl_notification_get_report_cb);
                }
                else if (intf->cls == COMMAND_CLASS_BATTERY)
                {
                    //result = zwif_battery_rpt_set(intf, hl_battery_report_cb);
                }
                else if (intf->cls == COMMAND_CLASS_SENSOR_BINARY)
                {
                    //result = zwif_bsensor_rpt_set(intf, hl_bin_snsr_rep_cb);
                }

                //Get the next interface
                last_intf_cont = last_intf_cont->next;
            }

            //Get the next endpoint
            last_ep_cont = last_ep_cont->next;
        }

        //Get the next node
        last_node_cont = last_node_cont->next;
    }
    printf("__________________________________________________________________________\n");

    plt_mtx_ulck(hl_appl->desc_cont_mtx);

    return 0;
}


//Callback function for zwnet_initiate.
void cb_get_dsk_fn(void *usr_ctx, char *dsk)
{
    printf("Learn mode callback, cb_get_dsk_fn, dsk: %s\n",dsk);
}


static int hl_destid_get(hl_appl_ctx_t *hl_appl, int nodeId, int cmd, uint8_t endpoindId)
{
    int result, find = 0;
    zwnetd_p    net_desc;
    zwnoded_p   node;
    zwepd_p     ep;
    zwifd_p     intf;
    desc_cont_t *last_node_cont;
    desc_cont_t *last_ep_cont;
    desc_cont_t *last_intf_cont;

    plt_mtx_lck(hl_appl->desc_cont_mtx);

    //Check whether the descriptor container linked list is initialized
    if (!hl_appl->desc_cont_hd)
    {
        result = hl_desc_init(&hl_appl->desc_cont_hd, hl_appl->zwnet);
        if (result != 0)
        {
            printf("hl_destid_get with error:%d", result);
            plt_mtx_ulck(hl_appl->desc_cont_mtx);
            return -1;
        }
    }

    //Get the first node (local controller) and home id
    last_node_cont = hl_appl->desc_cont_hd;

    net_desc = zwnet_get_desc(hl_appl->zwnet);

    while (last_node_cont)
    {
        if (last_node_cont->type != DESC_TYPE_NODE)
        {
            printf("node: wrong desc type:%u", last_node_cont->type);
        }

        node = (zwnoded_p)last_node_cont->desc;

        if((unsigned)node->nodeid == nodeId)
        {
            printf("The request node found, id %d, now start find it's cmd interface",nodeId);
            break;
        }
        else{
            //Get the next node
            last_node_cont = last_node_cont->next;
        }
    }

    if(last_node_cont == NULL)
    {
        printf("The request node isn't found, please try another");
        plt_mtx_ulck(hl_appl->desc_cont_mtx);
        return -1;
    }

    last_ep_cont = last_node_cont->down;

    while (last_ep_cont)
    {
        if (last_ep_cont->type != DESC_TYPE_EP)
        {
            printf("ep: wrong desc type:%u", last_ep_cont->type);
        }

        ep = (zwepd_p)last_ep_cont->desc;

        //Get interface
        last_intf_cont = last_ep_cont->down;

        while (last_intf_cont)
        {
            if (last_intf_cont->type != DESC_TYPE_INTF)
            {
                printf("interface: wrong desc type:%u", last_intf_cont->type);
            }

            intf = (zwifd_p)last_intf_cont->desc;

/*            ALOGD("              Interface: %02Xv%u:%s [%u]%c%c",
                  (unsigned)intf->cls, intf->ver, hl_class_str_get(intf->cls, intf->ver),
                  last_intf_cont->id, (intf->propty & IF_PROPTY_SECURE)? '*' : ' ',
                  (intf->propty & IF_PROPTY_UNSECURE)? '^' : ' ');*/

            if((intf->epid == endpoindId) && (unsigned)intf->cls == cmd)
            {
                printf("required interface found, nodeid:%d, cmd intf id:%d, EndPoint id:%d(%d)",nodeId,last_intf_cont->id,intf->epid, last_ep_cont->id);
                hl_appl->dst_desc_id = last_intf_cont->id;
                hl_appl->rep_desc_id = last_intf_cont->id;
                hl_appl->temp_desc = last_intf_cont->id;
                find = 1;
                break;
            }

            //Get the next interface
            last_intf_cont = last_intf_cont->next;
        }

        //Get the next endpoint
        last_ep_cont = last_ep_cont->next;
    }

    plt_mtx_ulck(hl_appl->desc_cont_mtx);

    if(find == 1)
    {
        return 0;
    }
    else
    {
        printf("--------------------------------------------------------------------------------\n");
        printf("  The request cmd interface not found, make sure this node supported it indeed\n");
        printf("--------------------------------------------------------------------------------");
        return ZW_ERR_CLASS_NOT_FOUND;
    }
}

/**
hl_grp_sup_cb - max number of groupings callback
@param[in]  ifd       interface
@param[in]  max_grp   maximum number of groupings
@return
*/
static void hl_grp_sup_cb(zwifd_p ifd,  uint8_t max_grp, int valid)
{
    printf("Max number of groupings:%d\n", max_grp);
}

static desc_cont_t    *hl_desc_cont_get(desc_cont_t *head, uint32_t desc_id)
{
    desc_cont_t     *last_node_cont;
    desc_cont_t     *last_ep_cont;
    desc_cont_t     *last_cls_cont;
    desc_cont_t     *last_intf_cont;

    //Start searching from the first node
    last_node_cont = head;

    while (last_node_cont)
    {
        if (last_node_cont->id == desc_id)
        {
            return last_node_cont;
        }

        //Search endpoint
        last_ep_cont = last_node_cont->down;

        while (last_ep_cont)
        {
            if (last_ep_cont->id == desc_id)
            {
                return last_ep_cont;
            }

            //Search class
            last_cls_cont = last_ep_cont->down;

            while (last_cls_cont)
            {
                if (last_cls_cont->id == desc_id)
                {
                    return last_cls_cont;
                }

                //Search interface
                last_intf_cont = last_cls_cont->down;

                while (last_intf_cont)
                {
                    if (last_intf_cont->id == desc_id)
                    {
                        return last_intf_cont;
                    }
                    //Get the next interface
                    last_intf_cont = last_intf_cont->next;
                }
                //Get the next class
                last_cls_cont = last_cls_cont->next;
            }
            //Get the next endpoint
            last_ep_cont = last_ep_cont->next;
        }
        //Get the next node
        last_node_cont = last_node_cont->next;
    }
    return NULL;
}

/**
hl_intf_desc_get - get interface descriptor from descriptor container
@param[in]  head        The head of the descriptor container linked-list
@param[in]  desc_id     Unique descriptor id
@return     Interface descriptor if found; else return NULL
@pre        Caller must lock the desc_cont_mtx before calling this function.
*/
zwifd_p    hl_intf_desc_get(desc_cont_t *head, uint32_t desc_id)
{
    desc_cont_t *desc_cont;

    //Get the interface descriptor
    desc_cont = hl_desc_cont_get(head, desc_id);
    if (!desc_cont)
    {
        printf("hl_intf_desc_get invalid desc id:%u\n",desc_id);
        //plt_msg_ts_show("hl_intf_desc_get invalid desc id:%u", desc_id);
        return NULL;
    }

    if (desc_cont->type != DESC_TYPE_INTF)
    {
        printf("hl_intf_desc_get desc id:%u is not type interface\n", desc_id);
        //plt_msg_ts_show("hl_intf_desc_get desc id:%u is not type interface", desc_id);
        return NULL;
    }

    return(zwifd_p)desc_cont->desc;
}

/**
hl_grp_sup - Get max number of groupings
@param[in]  hl_appl     The high-level api context
@return  0 on success, negative error number on failure
*/
int32_t hl_grp_sup(hl_appl_ctx_t   *hl_appl)
{
    int     result;
    zwifd_p ifd;

    //Get the interface descriptor
    plt_mtx_lck(hl_appl->desc_cont_mtx);
    ifd = hl_intf_desc_get(hl_appl->desc_cont_hd, hl_appl->rep_desc_id);
    if (!ifd)
    {
        plt_mtx_ulck(hl_appl->desc_cont_mtx);
        return ZW_ERR_INTF_NOT_FOUND;
    }

    result = zwif_group_sup_get(ifd, hl_grp_sup_cb, 0);

    plt_mtx_ulck(hl_appl->desc_cont_mtx);

    if (result < 0)
    {
        printf("zwif_group_sup_get with error:%d", result);
    }

    return result;
}


int  zwcontrol_get_max_supported_groups(hl_appl_ctx_t* hl_appl, uint32_t nodeId, uint8_t endpoindId)
{
    if(!hl_appl->init_status)
    {
        return -1;
    }

    if(hl_destid_get(hl_appl, nodeId, COMMAND_CLASS_ASSOCIATION, endpoindId))
    {
        return -1;
    }

    int result = hl_grp_sup(hl_appl);
    if(result == 1)
    {
        printf("zwcontrol_get_max_supported_groups command queued");
    }

    return result;
}

char  *prompt_str_1(const char *disp_str, int out_buf_sz, char *out_str)
{
    int retry;
    puts(disp_str);
    retry = 3;
    while (retry-- > 0)
    {
        if (fgets(out_str, out_buf_sz, stdin) && (*out_str) && ((*out_str) != '\n'))
        {
            char *newline;
            //Remove newline character

            newline = strchr(out_str, '\n');
            if (newline)
            {
                *newline = '\0';
            }
            return out_str;
        }
    }
    return NULL;
}

unsigned prompt_uint(char *str)
{
    char user_input_str[36];
    unsigned  ret;

    if (prompt_str_1(str, 36, user_input_str))
    {
        if (sscanf(user_input_str, "%u", &ret) == 1)
        {
            return ret;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    hl_appl_ctx_t   appl_ctx = {0};
    int             choice;
    int             result;
    zwifd_t         firmware_update_if = {0};
    zwfw_updt_req_t     fw_updt_req = {0};

    //Init user-application
    appl_ctx.use_ipv4 = 1; //Use IPv4

    //Initialize network
    if (nw_init(&appl_ctx) != 0)
        return -1;

    printf("Initialize network in progress, please wait for status ...\n");
    printf("Press 'x' to exit ...\n");

    while (1)
    {
        do
        {
            choice = getchar();
        } while (choice == 0x0A);

        if (appl_ctx.init_status == 0)
        {
            if (choice == 'x')
            {
                 //Exit and clean up
                zwnet_exit(appl_ctx.zwnet);
                return 0;
           }
        }
        else if ((appl_ctx.add_status == ADD_NODE_STS_UNKNOWN) || (appl_ctx.add_status == ADD_NODE_STS_DONE))
        {
            switch (choice)
            {
                case '1':
                    result = hl_add_node(&appl_ctx);
                    //result = zwnet_add(appl_ctx.zwnet, 1, (appl_ctx.sec2_add_node)? &appl_ctx.sec2_add_prm : NULL);
                    if (!appl_ctx.sec2_add_node)
                    {
                        if (result == 0)
                        {
                            printf("Add node in progress, please wait for status ...\n");
                            appl_ctx.add_status = ADD_NODE_STS_PROGRESS;
                        }
                        else
                        {
                            printf("Add node with error:%d\n", result);
                        }
                    }
                    break;
                case '2':
                    hl_node_desc_dump(&appl_ctx);
                    break;
                case '3':
                    result = zwnet_initiate(appl_ctx.zwnet,cb_get_dsk_fn,&appl_ctx);
                    if (result != 0)
                    {
                        printf("===================> hl_lrn_mod_set with error:%d \n", result);
                    }
                    //return 0;
                    break;
                /*case '4':
                    printf("Request firmware update start\n");
                    fw_updt_req.vid = 0x0000;
                    fw_updt_req.fw_id = 0;
                    fw_updt_req.fw_tgt = 0;
                    //fw_updt_req.frag_sz = hl_appl->fw_frag_sz;
                    fw_updt_req.hw_ver = 1;

                    const char * str = "/system/bin/serialapi_controller_bridge_ZM5304_JP.hex";
                    strcpy(appl_ctx.save_file,str);
                    fw_updt_req.fw_file = appl_ctx.save_file;
                    fw_updt_req.sts_cb = hl_fw_updt_sts_cb;
                    fw_updt_req.cmplt_cb = hl_fw_updt_cmplt_cb;
                    fw_updt_req.restart_cb = hl_fw_updt_restart_cb;
                    printf("Call zwif_fw_updt_req\n");
                    result = zwif_fw_updt_req(&firmware_update_if, &fw_updt_req);
                    break;*/

                    case '4':
                        appl_ctx.node_id = prompt_uint("Enter node id:");

                        printf("user enter nodeid is:%d\n",appl_ctx.node_id);

                        result = zwcontrol_get_max_supported_groups(&appl_ctx, appl_ctx.node_id, 0);
                        printf("zwcontrol_get_max_supported_groups, result: %d\n", result);
                        if(result != 0)
                        {
                            printf("zwcontrol_get_max_supported_groups get with error:%d\n", result);
                        }
                        break;

                case 'x':
                    //Exit and clean up
                    zwnet_exit(appl_ctx.zwnet);
                    return 0;
                    break;

                default:
                    printf("Invalid choice:%c\n", choice);
            }
            show_menu();
        }
        else    //ADD_NODE_STS_PROGRESS
        {
            switch (choice)
            {
                case '1':
                    result = zwnet_abort(appl_ctx.zwnet);
                    if (result == 0)
                    {
                        printf("Add node operation aborted.\n");
                        appl_ctx.add_status = ADD_NODE_STS_UNKNOWN;
                    }
                    else
                    {
                        printf("Add node operation can't be aborted, error:%d\n", result);
                    }
                    break;

                case 'x':
                    //Exit and clean up
                    zwnet_exit(appl_ctx.zwnet);
                    return 0;
                    break;

                default:
                    printf("Invalid choice:%c\n", choice);
            }

            show_menu();

        }
    }

    return 0;
}

