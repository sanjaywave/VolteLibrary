#ifndef _PHONE_CAPTURE_KPI_H_
#define _PHONE_CAPTURE_KPI_H_

/*********************************************************************************
 *  Header File Contents - Start - phone_kpi.h
 ********************************************************************************/

typedef struct pcap_sip_counter_context_t
{
    U32 count_sip_reg_fail;
    U32 count_sip_reg_success;
    U32 count_sip_mo_setup_session_success;
    U32 count_sip_mo_setup_session_failure;
    U32 count_sip_mt_setup_session_success;
    U32 count_sip_mt_setup_session_failure;
    U32 count_sip_mo_setup_session_attempt;
    U32 count_sip_mt_setup_session_attempt;
    U32 count_sip_error_response;
    U32 count_sip_rejected;
    U32 count_sip_out_msg;
    U32 count_sip_msg_resent;
    U32 count_sip_ue_register_attempt;
    U32 count_sip_ue_register_success;
    U32 count_sip_ue_register_reject;
} pcap_sip_counter_context_t;

typedef struct pcap_rtp_counter_context_t
{
    U32 count_rtp_packet_loss;
    U32 count_rtp_packet_total;
    U32 count_rtp_incoming_oos;
    U32 count_rtp_packet_total_recv;
} pcap_rtp_counter_context_t;

typedef struct pcap_counter_context_t
{
    pcap_sip_counter_context_t  sip_counter;
    pcap_rtp_counter_context_t  rtp_counter;
} pcap_counter_context_t;

typedef struct pcap_sip_time_context_t
{
    struct timeval  ts_reg_start;
    struct timeval  ts_reg_end;
} pcap_sip_time_context_t;

typedef struct pcap_rtp_time_context_t
{
} pcap_rtp_time_context_t;

typedef struct pcap_time_context_t
{
    pcap_sip_time_context_t  sip_time;
    pcap_sip_time_context_t  rtp_time;
} pcap_time_context_t;

/*********************************************************************************
 *  Header File Contents - End - phone_kpi.h
 ********************************************************************************/

#endif
