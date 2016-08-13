#ifndef _PHONE_CAPTURE_H_
#define _PHONE_CAPTURE_H_
/*********************************************************************************
 *  Header File Contents - Start - phone_capture.h
 ********************************************************************************/

// PCAP read timeout in ms
#define PCAP_TO_MS                  1000
#define PCAP_TO_COUNTER_MAX         15
#define PCAP_IDLE_TIME_FOR_CLOSE    300
#define MAX_IP_PER_CALL             4
#define PCAP_MAX_NUM_SIP_SESSION    100

typedef enum pcap_session_state_et
{
    STATE_INACTIVE,
    STATE_REGISTER_IN_PROGRESS,
    STATE_REGISTER_SUCESS,
    STATE_REGISTER_FAIL,
    STATE_INVITE_IN_PROGRESS,
    STATE_INVITE_SUCESS,
    STATE_INVITE_FAIL
} pcap_session_state_et;

typedef enum pcap_session_event_et
{
    EVENT_NULL,
    EVENT_REGISTER,
    EVENT_INVITE,
    EVENT_ACK,
    EVENT_CANCEL,
    EVENT_100,
    EVENT_183,
    EVENT_200,
    EVENT_200_SDP,
    EVENT_401,
    EVENT_403,
    EVENT_407,
    EVENT_480,
} pcap_session_event_et;

typedef struct pcap_session_context_t
{
    U8          had_bye;
    S8          call_id[1024];
    U32         call_id_len;
    in_addr_t   ip[MAX_IP_PER_CALL];
    U16         port[MAX_IP_PER_CALL];
    U32         ssrc[MAX_IP_PER_CALL];
    S32         number_of_ip;
    time_t      last_packet_time;
    struct timeval  ts_current_packet;
    pcap_session_state_et   state;
    pcap_counter_context_t  counter;
    pcap_time_context_t     time;
} pcap_session_context_t;

typedef struct pcap_context_t
{
/*    U32         ue_ip;
    U32         cur_pkt_src;
    U32         cur_pkt_dst;*/
    U8          stop_capture;
    U8          is_mo;
    U8          number_of_sessions;
    pcap_session_context_t  sip_context[PCAP_MAX_NUM_SIP_SESSION];
    S8          fn_pcap[128];
    pcap_dumper_t   *p_pcap_dumper;
    U32         total_packets;
    U32         total_sip_packets;
    U32         total_rtp_packets;
    time_t      overall_last_packet_time;
} pcap_context_t;

pcap_context_t  pcap_context;

/*#define PHONE_CAPTURE_LOG       printf*/

#define     PACKET_RECEIVED         (pcap_context.total_packets)++
#define     PACKET_SIP_RECEIVED     (pcap_context.total_sip_packets)++
#define     PACKET_RTP_RECEIVED     (pcap_context.total_rtp_packets)++

#define     COUNT_SIP_REG_FAIL(_id)                     (pcap_context.sip_context[_id].counter.sip_counter.count_sip_reg_fail)++
#define     COUNT_SIP_REG_SUCCESS(_id)                  (pcap_context.sip_context[_id].counter.sip_counter.count_sip_reg_success)++
#define     COUNT_SIP_MO_SETUP_SESSION_SUCCESS(_id)     (pcap_context.sip_context[_id].counter.sip_counter.count_sip_mo_setup_session_success)++
// TODO - Start
#define     COUNT_SIP_MO_SETUP_SESSION_FAILURE(_id)     (pcap_context.sip_context[_id].counter.sip_counter.count_sip_mo_setup_session_failure)++
// TODO - End
#define     COUNT_SIP_MT_SETUP_SESSION_SUCCESS(_id)     (pcap_context.sip_context[_id].counter.sip_counter.count_sip_mt_setup_session_success)++
// TODO - Start
#define     COUNT_SIP_MT_SETUP_SESSION_FAILURE(_id)     (pcap_context.sip_context[_id].counter.sip_counter.count_sip_mt_setup_session_failure)++
// TODO - End
#define     COUNT_SIP_MO_SETUP_SESSION_ATTEMPT(_id)     (pcap_context.sip_context[_id].counter.sip_counter.count_sip_mo_setup_session_attempt)++
#define     COUNT_SIP_MT_SETUP_SESSION_ATTEMPT(_id)     (pcap_context.sip_context[_id].counter.sip_counter.count_sip_mt_setup_session_attempt)++
// TODO - Start
#define     COUNT_SIP_ERROR_RESPONSE(_id)               (pcap_context.sip_context[_id].counter.sip_counter.count_sip_error_response)++
#define     COUNT_SIP_REJECTED(_id)                     (pcap_context.sip_context[_id].counter.sip_counter.count_sip_rejected)++
// TODO - End
#define     COUNT_SIP_OUT_MSG(_id)                      (pcap_context.sip_context[_id].counter.sip_counter.count_sip_out_msg)++
#define     COUNT_SIP_MSG_RESENT(_id)                   (pcap_context.sip_context[_id].counter.sip_counter.count_sip_msg_resent)++
#define     COUNT_SIP_UE_REGISTER_ATTEMPT(_id)          (pcap_context.sip_context[_id].counter.sip_counter.count_sip_ue_register_attempt)++
#define     COUNT_SIP_UE_REGISTER_SUCCESS(_id)          (pcap_context.sip_context[_id].counter.sip_counter.count_sip_ue_register_success)++
#define     COUNT_SIP_UE_REGISTER_REJECT(_id)           (pcap_context.sip_context[_id].counter.sip_counter.count_sip_ue_register_reject)++

#define     COUNT_RTP_PACKET_LOSS(_id)                  (pcap_context.sip_context[_id].counter.rtp_counter.count_rtp_packet_loss)++
#define     COUNT_RTP_PACKET_TOTAL(_id)                 (pcap_context.sip_context[_id].counter.rtp_counter.count_rtp_packet_total)++
#define     COUNT_RTP_INCOMING_OOS(_id)                 (pcap_context.sip_context[_id].counter.rtp_counter.count_rtp_incoming_oos)++
#define     COUNT_RTP_PACKET_TOTAL_RECV(_id)            (pcap_context.sip_context[_id].counter.rtp_counter.count_rtp_packet_total_recv)++

#define     TIME_VAL_SAVE(_ts1,_ts2) \
{ \
    _ts1->tv_sec = _ts2->tv_sec; \
    _ts1->tv_usec = _ts2->tv_usec; \
}

#define     TIME_VAL_DIFF(_ts1,_ts2,_ts3) \
{ \
    if(_ts2->tv_usec >= _ts1->tv_usec) \
    { \
        _ts3->tv_usec = _ts2->tv_usec - _ts1->tv_usec; \
        _ts3->tv_sec = _ts2->tv_sec - _ts1->tv_sec; \
    } \
    else \
    { \
        _ts3->tv_usec = (1000000 + _ts2->tv_usec) - _ts1->tv_usec; \
        _ts3->tv_sec = _ts2->tv_sec - 1 - _ts1->tv_sec; \
    } \
}

#define SET_STATE(_id,_event) \
{ \
    PHONE_CAPTURE_LOG("SId:[%d] State:[%s] Event: [%s]\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(_event)); \
    switch (_event) \
    { \
        case EVENT_REGISTER: \
                             phone_capture_handle_register_event(_id); \
        break; \
        case EVENT_INVITE: \
                           phone_capture_handle_invite_event(_id); \
        break; \
        case EVENT_ACK: \
                           phone_capture_handle_ack_event(_id); \
        break; \
        case EVENT_CANCEL: \
                           phone_capture_handle_cancel_event(_id); \
        break; \
        case EVENT_100: \
                        phone_capture_handle_100_event(_id); \
        break; \
        case EVENT_183: \
                        phone_capture_handle_183_event(_id); \
        break; \
        case EVENT_200: \
                        phone_capture_handle_200_event(_id); \
        break; \
        case EVENT_200_SDP: \
                        phone_capture_handle_200_sdp_event(_id); \
        break; \
        case EVENT_401: \
                        phone_capture_handle_401_event(_id); \
        break; \
        case EVENT_403: \
                        phone_capture_handle_403_event(_id); \
        break; \
        case EVENT_407: \
                        phone_capture_handle_407_event(_id); \
        break; \
        case EVENT_480: \
                        phone_capture_handle_480_event(_id); \
        break; \
        default: \
                 PHONE_CAPTURE_LOG("Invalid Event [%d]\n", _event); \
        break; \
    } \
}

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))


/*********************************************************************************
 *  Header File Contents - End - phone_capture.h
 ********************************************************************************/

void phone_capture_handle_register_event (U32 idx);
void phone_capture_handle_invite_event (U32 idx);
void phone_capture_handle_ack_event (U32 idx);
void phone_capture_handle_cancel_event (U32 idx);
void phone_capture_handle_100_event (U32 idx);
void phone_capture_handle_183_event (U32 idx);
void phone_capture_handle_200_event (U32 idx);
void phone_capture_handle_200_sdp_event (U32 idx);
void phone_capture_handle_401_event (U32 idx);
void phone_capture_handle_403_event (U32 idx);
void phone_capture_handle_407_event (U32 idx);
void phone_capture_handle_480_event (U32 idx);

void phone_capture_handle_rtp_packet (U32 idx_leg, U32 idx_rtp, rtp_hdr_t *p_rtp_hdr);
const char * phone_capture_get_state_string (pcap_session_state_et state);
const char * phone_capture_get_event_string (pcap_session_event_et event);

#endif
