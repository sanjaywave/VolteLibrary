#include <endian.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/ip.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <pcap.h>

#include "errors.h"
#include "phone_capture_types.h"
#include "phone_capture_header.h"
#include "phone_capture_kpi.h"
#include "phone_capture.h"

void phone_capture_handle_rtp_packet (U32 idx_leg, U32 idx_rtp, rtp_hdr_t *p_rtp_hdr)
{
    PHONE_CAPTURE_LOG("SId:[%u] RTP Packet IP[0x%x] Port[%u] SSRC[0x%x] SN[%u]\n",
    idx_leg, pcap_context.sip_context[idx_leg].ip[idx_rtp],
    htons(pcap_context.sip_context[idx_leg].port[idx_rtp]),
    pcap_context.sip_context[idx_leg].ssrc[idx_rtp],
    htons(p_rtp_hdr->seq));
}

