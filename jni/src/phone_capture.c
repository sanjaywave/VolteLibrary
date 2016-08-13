#include <endian.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

//#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <pcap.h>

#include "errors.h"
#include "phone_capture_types.h"
#include "phone_capture_header.h"
#include "phone_capture_kpi.h"
#include "phone_capture.h"
#include "phone_capture_api.h"


#ifndef _GNU_SOURCE
void *memmem (const void* haystack, size_t hl, const void* needle, size_t nl) 
{
    S32 i;

    if (nl > hl)
    {
        return 0;
    }
    for (i = hl - nl + 1; i; --i) 
    {
        if (!memcmp (haystack, needle, nl))
        {
            return (S8*)haystack;
        }
        haystack = (void*)((S8*)haystack + 1);
    }
    return 0;
}
#endif

static S32 phone_capture_cleanup (time_t currtime)
{
    if (currtime - pcap_context.overall_last_packet_time > PCAP_IDLE_TIME_FOR_CLOSE)
    {
        if (pcap_context.p_pcap_dumper != NULL)
        {
            pcap_dump_close (pcap_context.p_pcap_dumper);
            pcap_context.p_pcap_dumper = NULL;
        }
    }
    return 0;
}

static U32 phone_capture_get_ssrc (void *p_udp_packet_data, S8 is_rtcp)
{
    if (is_rtcp)
    {
        return ntohl (*(U32*)((U8*)p_udp_packet_data + 4));
    }
    else
    {
        return ntohl(*(U32*)((U8*)p_udp_packet_data + 8));
    }
}

static S8 * phone_capture_gettag (const void *ptr, U32 len, const S8 *tag, U32 *gettaglen)
{
    /*U32 register    r;
      U32 register    l;
      U32 register    tag_len;*/
    // TODO - need to replace unsigned long in this function
    unsigned long r, l, tag_len;
    S8 *rc;

    tag_len = strlen (tag);
    r = (unsigned long)memmem (ptr, len, tag, tag_len);

    if (r == 0)
    {
        l = 0;
    }
    else
    {
        r += tag_len;
        l = (unsigned long)memmem ((void *)r, len - (r - (unsigned long)ptr), "\r\n", 2);
        if (l > 0)
        {
            l -= r;
        }
        else
        {
            l = 0;
            r = 0;
        }
    }
    rc = (S8*)r;
    if (rc)
    {
        while (rc[0] == ' ')
        {
            rc++;
            l--;
        }
    }
    *gettaglen = l;
    return rc;
}

static S32 phone_capture_find_by_call_id (S8 *p_call_id, U32 call_id_len)
{
    U32 idx = 0;

    for (idx = 0; idx < pcap_context.number_of_sessions; idx++)
    {
        if ((pcap_context.sip_context[idx].call_id_len == call_id_len) &&
                (memcmp (pcap_context.sip_context[idx].call_id, p_call_id, call_id_len) == 0))
            //(memcmp (pcap_context.sip_context[idx].call_id, p_call_id, MIN(call_id_len, 32)) == 0))
        {
            return idx;
        }
    }
    return -1;
}

static S32 phone_capture_add (S8 *p_call_id, U32 call_id_len, time_t time)
{
    S32 idx = pcap_context.number_of_sessions;

    if (pcap_context.number_of_sessions < PCAP_MAX_NUM_SIP_SESSION)
    {
        memcpy(pcap_context.sip_context[idx].call_id, p_call_id, call_id_len);
        //memcpy(pcap_context.sip_context[idx].call_id, p_call_id, MIN(call_id_len, 32));
        pcap_context.sip_context[idx].call_id_len = call_id_len;
        pcap_context.sip_context[idx].number_of_ip = 0;
        pcap_context.sip_context[idx].had_bye = 0;
        pcap_context.sip_context[idx].last_packet_time = time;

        (pcap_context.number_of_sessions)++;
        return idx;
    }
    return -1;
}

static S32 phone_capture_find_ip_port_ssrc (in_addr_t addr, U16 port,
        U32 ssrc, S32 *idx_leg, S32 *idx_rtp)
{
    S32 i_leg;
    S32 i_rtp;

    for (i_leg = 0; i_leg < pcap_context.number_of_sessions; i_leg++)
    {
        for (i_rtp = 0; i_rtp < pcap_context.sip_context[i_leg].number_of_ip; i_rtp++)
        {
            if (pcap_context.sip_context[i_leg].port[i_rtp] == port && 
                    pcap_context.sip_context[i_leg].ip[i_rtp] == addr)
            {
                if (!pcap_context.sip_context[i_leg].had_bye || 
                        pcap_context.sip_context[i_leg].ssrc[i_rtp] == ssrc)
                {
                    pcap_context.sip_context[i_leg].ssrc[i_rtp] = ssrc;
                    *idx_leg = i_leg;
                    *idx_rtp = i_rtp;
                    return 1;
                }
            }
        }
    }
    return 0;
}

static S32 phone_capture_add_ip_port (U32 call_id, in_addr_t addr, U16 port)
{
    S32 idx;
    S32 found;
    S32 no_of_ip = pcap_context.sip_context[call_id].number_of_ip;

    if (no_of_ip >= MAX_IP_PER_CALL)
    {
        return -1;	
    }

    found = 0;
    for (idx = 0; idx < no_of_ip; idx++)
    {
        if (pcap_context.sip_context[call_id].ip[idx] == addr && 
                pcap_context.sip_context[call_id].port[idx] == port)
        {
            found = 1;
            break;
        } 
    }

    if (!found)
    {
        pcap_context.sip_context[call_id].ip[no_of_ip]=addr;
        pcap_context.sip_context[call_id].port[no_of_ip]=port;
        pcap_context.sip_context[call_id].number_of_ip++;
    }
    return 0;
}

static S32 phone_capture_get_sip_peername (S8 *p_data, S32 data_len, 
        const S8 *tag, S8 *peername, S32 peername_len)
{
    unsigned long r, r2;
    U32 peername_tag_len;
    S8 *peername_tag = phone_capture_gettag (p_data, data_len, tag, &peername_tag_len);

    if ((r = (unsigned long)memmem (peername_tag, peername_tag_len, "sip:", 4)) == 0)
    {
        goto fail_exit;
    }

    r += 4;
    if ((r2 = (unsigned long)memmem (peername_tag, peername_tag_len, "@", 1)) == 0)
    {
        goto fail_exit;
    }

    if (r2 <= r)
    {
        goto fail_exit;
    }

    memcpy (peername, (void*)r, r2 - r);
    memset (peername + (r2 - r), 0, 1);

    return 0;

fail_exit:
    strcpy (peername, "empty");

    return 1;
}

static S32 phone_capture_get_ip_port_from_sdp (S8 *sdp_text, in_addr_t *addr, U16 *port)
{
    U32 tag_length;
    S8 *tag_string;
    S8 s1[20];

    tag_string = phone_capture_gettag (sdp_text, strlen(sdp_text), "c=IN IP4 ", &tag_length);

    memset (s1, '\0', sizeof (s1));
    memcpy (s1, tag_string, MIN(tag_length, 19));

    if ((long)(*addr = inet_addr (s1)) == -1)
    {
        *addr=0;
        *port=0;
        return 1;
    }

    tag_string = phone_capture_gettag (sdp_text, strlen (sdp_text), "m=audio ", &tag_length);
    if (tag_length == 0)
    {
        tag_string = phone_capture_gettag (sdp_text, strlen (sdp_text), "m=image ", &tag_length);
    }
    if (tag_length == 0 || (*port = atoi (tag_string)) == 0)
    {
        *port=0;
        return 1;
    }
    return 0;
}

const char * phone_capture_get_state_string (pcap_session_state_et state)
{
    switch (state)
    {
        case STATE_INACTIVE:
            return "STATE_INACTIVE";
            break;

        case STATE_REGISTER_IN_PROGRESS:
            return "STATE_REGISTER_IN_PROGRESS";
            break;

        case STATE_REGISTER_SUCESS:
            return "STATE_REGISTER_SUCESS";
            break;

        case STATE_REGISTER_FAIL:
            return "STATE_REGISTER_FAIL";
            break;

        case STATE_INVITE_IN_PROGRESS:
            return "STATE_INVITE_IN_PROGRESS";
            break;

        case STATE_INVITE_SUCESS:
            return "STATE_INVITE_SUCESS";
            break;

        case STATE_INVITE_FAIL:
            return "STATE_INVITE_FAIL";
            break;

        default:
            return "STATE_INVALID";
    }
}

const char * phone_capture_get_event_string (pcap_session_event_et event)
{
    switch (event)
    {
        case EVENT_NULL:
            return "EVENT_NULL";
            break;
        case EVENT_REGISTER:
            return "EVENT_REGISTER";
            break;
        case EVENT_INVITE:
            return "EVENT_INVITE";
            break;
        case EVENT_ACK:
            return "EVENT_ACK";
            break;
        case EVENT_CANCEL:
            return "EVENT_CANCEL";
            break;
        case EVENT_100:
            return "EVENT_100";
            break;
        case EVENT_183:
            return "EVENT_183";
            break;
        case EVENT_200:
            return "EVENT_200";
            break;
        case EVENT_200_SDP:
            return "EVENT_200_SDP";
            break;
        case EVENT_401:
            return "EVENT_401";
            break;
        case EVENT_403:
            return "EVENT_403";
            break;
        case EVENT_407:
            return "EVENT_407";
            break;
        case EVENT_480:
            return "EVENT_480";
            break;
        default:
            return "INVALID_EVENT";
    }
}
static void phone_capture_sip_context_dump (pcap_session_context_t *p_sip_context)
{
    U32 idx = 0;

    PHONE_CAPTURE_LOG("had_bye;:%u\n", p_sip_context->had_bye);
    PHONE_CAPTURE_LOG("call_id;:%s\n", p_sip_context->call_id);
    PHONE_CAPTURE_LOG("call_id_len;:%u\n", p_sip_context->call_id_len);
    PHONE_CAPTURE_LOG("number_of_ip;:%u\n", p_sip_context->number_of_ip);
    for (idx = 0; idx < p_sip_context->number_of_ip; idx++)
    {
        PHONE_CAPTURE_LOG("ip[%u];:0x%x\n", idx, p_sip_context->ip[idx]);
        PHONE_CAPTURE_LOG("port[%u];:0x%x\n", idx, p_sip_context->port[idx]);
        PHONE_CAPTURE_LOG("ssrc[%u];:%u\n", idx, p_sip_context->ssrc[idx]);
    }
    PHONE_CAPTURE_LOG("last_packet_time;:%u\n", (U32)(p_sip_context->last_packet_time));
    PHONE_CAPTURE_LOG("state:%s\n", phone_capture_get_state_string (p_sip_context->state));
    PHONE_CAPTURE_LOG("count_sip_reg_fail:%u\n", p_sip_context->counter.sip_counter.count_sip_reg_fail);
    PHONE_CAPTURE_LOG("count_sip_reg_success:%u\n", p_sip_context->counter.sip_counter.count_sip_reg_success);
    PHONE_CAPTURE_LOG("count_sip_mo_setup_session_success:%u\n", p_sip_context->counter.sip_counter.count_sip_mo_setup_session_success);
    PHONE_CAPTURE_LOG("count_sip_mo_setup_session_failure:%u\n", p_sip_context->counter.sip_counter.count_sip_mo_setup_session_failure);
    PHONE_CAPTURE_LOG("count_sip_mt_setup_session_success:%u\n", p_sip_context->counter.sip_counter.count_sip_mt_setup_session_success);
    PHONE_CAPTURE_LOG("count_sip_mt_setup_session_failure:%u\n", p_sip_context->counter.sip_counter.count_sip_mt_setup_session_failure);
    PHONE_CAPTURE_LOG("count_sip_mo_setup_session_attempt:%u\n", p_sip_context->counter.sip_counter.count_sip_mo_setup_session_attempt);
    PHONE_CAPTURE_LOG("count_sip_mt_setup_session_attempt:%u\n", p_sip_context->counter.sip_counter.count_sip_mt_setup_session_attempt);
    PHONE_CAPTURE_LOG("count_sip_error_response:%u\n", p_sip_context->counter.sip_counter.count_sip_error_response);
    PHONE_CAPTURE_LOG("count_sip_rejected:%u\n", p_sip_context->counter.sip_counter.count_sip_rejected);
    PHONE_CAPTURE_LOG("count_sip_out_msg:%u\n", p_sip_context->counter.sip_counter.count_sip_out_msg);
    PHONE_CAPTURE_LOG("count_sip_msg_resent:%u\n", p_sip_context->counter.sip_counter.count_sip_msg_resent);
    PHONE_CAPTURE_LOG("count_sip_ue_register_attempt:%u\n", p_sip_context->counter.sip_counter.count_sip_ue_register_attempt);
    PHONE_CAPTURE_LOG("count_sip_ue_register_success:%u\n", p_sip_context->counter.sip_counter.count_sip_ue_register_success);
    PHONE_CAPTURE_LOG("count_sip_ue_register_reject:%u\n", p_sip_context->counter.sip_counter.count_sip_ue_register_reject);
    PHONE_CAPTURE_LOG("count_rtp_packet_loss:%u\n", p_sip_context->counter.rtp_counter.count_rtp_packet_loss);
    PHONE_CAPTURE_LOG("count_rtp_packet_total:%u\n", p_sip_context->counter.rtp_counter.count_rtp_packet_total);
    PHONE_CAPTURE_LOG("count_rtp_incoming_oos:%u\n", p_sip_context->counter.rtp_counter.count_rtp_incoming_oos);
    PHONE_CAPTURE_LOG("count_rtp_packet_total_recv:%u\n", p_sip_context->counter.rtp_counter.count_rtp_packet_total_recv);
}

static void phone_capture_pcap_context_dump ()
{
    U32 idx = 0;

    PHONE_CAPTURE_LOG("****Dump Start****\n");
    //PHONE_CAPTURE_LOG("ue_ip (Network Format):0x%x\n", pcap_context.ue_ip);
    PHONE_CAPTURE_LOG("number_of_sessions:%u\n", pcap_context.number_of_sessions);
    PHONE_CAPTURE_LOG("fn_pcap:%s\n", pcap_context.fn_pcap);
    PHONE_CAPTURE_LOG("total_packets:%u\n", pcap_context.total_packets);
    PHONE_CAPTURE_LOG("total_sip_packets:%u\n", pcap_context.total_sip_packets);
    PHONE_CAPTURE_LOG("total_rtp_packets:%u\n", pcap_context.total_rtp_packets);
    PHONE_CAPTURE_LOG("overall_last_packet_time:%u\n", (U32)(pcap_context.overall_last_packet_time));

    for (idx = 0; idx < pcap_context.number_of_sessions; idx++)
    {
        PHONE_CAPTURE_LOG("SIP Context [%u]\n===================\n", idx);
        phone_capture_sip_context_dump (&(pcap_context.sip_context[idx]));
    }
    PHONE_CAPTURE_LOG("****Dump End****\n\n");

}

void phone_capture_stop_capture ()
{
    pcap_context.stop_capture = 1;
}

void phone_capture_main (const S8 *p_in_pcap, S8 *p_out_pcap, S8 *p_filter, U32 ue_ip)
{

    pcap_t *p_pcap_handle;/* Session handle */
    const S8 *opt_chdir="~/";/* directory to write dump */
    S8 *ifname = "any";/* interface to sniff on */
    S8 errbuf[PCAP_ERRBUF_SIZE];/* Error string */
    struct bpf_program fp;/* The compiled filter */
    S8 *p_filter_exp = "udp";/* The filter expression */
    bpf_u_int32 mask;/* Our netmask */
    bpf_u_int32 net;/* Our IP */
    struct pcap_pkthdr *pkt_header; /* The header that pcap gives us */
    const U8 *pkt_data; /* The actual packet */
    //U32 last_cleanup=0;
    S32 result;
    S32 offset_to_ip=0;
    S32 opt_promisc=1;
    S32 verbosity=0;
    struct iphdr *p_iphdr;
    struct udphdr *p_udphdr;
    S8 *p_udp_payload;
    S8 *tag_string_call_id;
    S8 tag_string_call_id_str[1024];
    S8 *tag_string;
    //S8 str1[1024],str2[1024];
    U32 udp_payload_length;
    U32 tag_length;
    U32 tag_length_call_id;
    S32 config_timeout_counter = 0;
    S32 idx;
    S32 idx_leg=0;
    S32 idx_rtp=0;
    S32 is_rtcp=0;
    U16 rtp_port_mask=0xfffe;
    //U32 cur_pkt_src;
    //U32 cur_pkt_dst;

    memset ((void*)&pcap_context, 0, sizeof(pcap_context_t));

    // Set UE IP
    //pcap_context.ue_ip = ue_ip;

    if (NULL == p_out_pcap)
    {
        PHONE_CAPTURE_LOG ("Pcap output file name cannot be NULL\n");
    }

    // Set the filter expression
    if (NULL != p_filter)
    {
        p_filter_exp = p_filter;
    }
    PHONE_CAPTURE_LOG ("Capturing using filter expression: %s\n", p_filter_exp);

    // Start capture
    pcap_context.stop_capture = 0;

    /* Find the IPv4 network number and netmask for a device
     * S32 pcap_lookupnet(const S8 *device, bpf_u_S3232 *netp,
     *   bpf_u_S3232 *maskp, S8 *errbuf);
     */    
    if (pcap_lookupnet (ifname, &net, &mask, errbuf) == -1) 
    {
        fprintf(stderr, "Couldn't get netmask for interface %s: %s\n", ifname, errbuf);
        net = 0;
        mask = 0;
    }

    if (p_in_pcap != NULL)
    {
        net = 0;
        mask = 0;
        p_pcap_handle = pcap_open_offline (p_in_pcap, errbuf);
        if (p_pcap_handle == NULL) 
        {
            fprintf (stderr, "Couldn't open pcap file '%s': %s\n", p_in_pcap, errbuf);
            return;
        }
    }
    else
    {
        PHONE_CAPTURE_LOG ("Capturing on interface: %s\n", ifname);
        /*
         * Open a device for capturing
         * pcap_t *pcap_open_live(const S8 *device, S32 snaplen,
         *   S32 promisc, S32 to_ms, S8 *errbuf);
         *
         * snaplen specifies the snapshot length to be set on the handle.
         * promisc specifies if the S32erface is to be put S32o promiscuous mode.
         * to_ms specifies the read timeout in milliseconds.
         * 
         */ 
        p_pcap_handle = pcap_open_live (ifname, 1600, opt_promisc, PCAP_TO_MS, errbuf);
        if (p_pcap_handle == NULL) 
        {
            fprintf (stderr, "Couldn't open interface '%s': %s\n", ifname, errbuf);
            return;
        }
    }

    chdir (opt_chdir);

    /*
     * Compile a filter expression
     * S32 pcap_compile(pcap_t *p, struct bpf_program *fp,
     * const S8 *str, S32 optimize, bpf_u_S3232 netmask);
     */
    if (pcap_compile (p_pcap_handle, &fp, p_filter_exp, 0, net) == -1) 
    {
        fprintf (stderr, "Couldn't parse filter %s: %s\n", p_filter_exp, pcap_geterr(p_pcap_handle));
        return;
    }

    /*
     * Set the filter
     * S32 pcap_setfilter(pcap_t *p, struct bpf_program *fp);
     */
    if (pcap_setfilter (p_pcap_handle, &fp) == -1) 
    {
        fprintf (stderr, "Couldn't install filter %s: %s\n", p_filter_exp, pcap_geterr(p_pcap_handle));
        return;
    }

    /* 
     * Get the link-layer header type
     * S32 pcap_datalink(pcap_t *p);
     */
    S32 dlt=pcap_datalink (p_pcap_handle);
    switch (dlt)
    {
        case DLT_EN10MB :
            offset_to_ip = sizeof (struct ether_header);
            break;
        case DLT_LINUX_SLL :
            offset_to_ip = 16;
            break;
        case DLT_RAW :
            offset_to_ip = 0;
            break;
        default : 
            PHONE_CAPTURE_LOG ("Unknown interface type (%d).\n", dlt);
            return;
    }

    // Open pcap to be created
    pcap_context.p_pcap_dumper = pcap_dump_open (p_pcap_handle, p_out_pcap);
    if (pcap_context.p_pcap_dumper == NULL)
    {
        fprintf (stderr, "Couldn't open pcap file '%s': %s\n", p_out_pcap, errbuf);
        return;
    }

    /*
     * Read the next packet from a pcap_t
     * S32 pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
     *   const u_S8 **pkt_data);
     */
    while ((0 == pcap_context.stop_capture) &&
            ((result = pcap_next_ex (p_pcap_handle, &pkt_header, &pkt_data)) >= 0))
    {
        if (result == 0)
        {
            /*
             * If the pcap read configured timeout has elapsed
             * continue reading
             * If timeout has occured continously for 15s break
             */
            if (config_timeout_counter < PCAP_TO_COUNTER_MAX)
            {
                config_timeout_counter++;
                continue;
            }
            break;
        }

        PACKET_RECEIVED;

#if 0
        if (pkt_header->ts.tv_sec - last_cleanup > 15)
        {
            if (last_cleanup > 0)
            {
                phone_capture_cleanup (pkt_header->ts.tv_sec);
            }
            last_cleanup = pkt_header->ts.tv_sec;
        }
#endif

        // Extract poS32er to IP packet
        p_iphdr = (struct iphdr *)((S8*)pkt_data + offset_to_ip);

        //cur_pkt_src = p_iphdr->saddr;
        //cur_pkt_dst = p_iphdr->daddr;
        if (ue_ip == p_iphdr->saddr)
        {
            pcap_context.is_mo = 1;
        }
        else
        {
            pcap_context.is_mo = 0;
        }

        // If packet is of type UDP viz. IPPROTO_UDP == 17
        if (p_iphdr->protocol == IPPROTO_UDP)
        {
            // Extract poS32er to UDP packet
            p_udphdr = (struct udphdr *)((S8*)p_iphdr + sizeof (*p_iphdr));

            // Extract poS32er to UDP Payload
            p_udp_payload = (S8 *)p_udphdr + sizeof (*p_udphdr);

            /*
             * Calculate UDP payload length
             * Total packet length - (address of udp payload start - address of packet start)
             */
            udp_payload_length = pkt_header->len - ((unsigned long)p_udp_payload - (unsigned long)pkt_data);

            // Check if this is an RTCP packet
            is_rtcp = (htons (p_udphdr->source) & 1) && (htons (p_udphdr->dest) & 1);

            if (phone_capture_find_ip_port_ssrc (p_iphdr->daddr,
                        htons (p_udphdr->dest) & rtp_port_mask,
                        phone_capture_get_ssrc (p_udp_payload, is_rtcp),
                        &idx_leg,
                        &idx_rtp))
            {
                phone_capture_handle_rtp_packet (idx_leg, idx_rtp, (rtp_hdr_t *)p_udp_payload);

                // Save packet time in pcap context
                pcap_context.overall_last_packet_time = pkt_header->ts.tv_sec;

                /* Write a packet to a capture file
                 * void pcap_dump(u_S8 *user, struct pcap_pkthdr *h, u_S8 *sp);
                 * TODO - If pcap_dump is not writing to pcap files quickly enough
                 * we can try pcap_dump_flush later on. Use of pcap_dump_flush 
                 * results in slower output
                 */
                pcap_dump ((U8 *)pcap_context.p_pcap_dumper, pkt_header, pkt_data);
            }
            else if (phone_capture_find_ip_port_ssrc (p_iphdr->saddr,
                        htons (p_udphdr->source) & rtp_port_mask,
                        phone_capture_get_ssrc (p_udp_payload, is_rtcp),
                        &idx_leg,
                        &idx_rtp))
            {
                phone_capture_handle_rtp_packet (idx_leg, idx_rtp, (rtp_hdr_t *)p_udp_payload);

                // Save packet time in pcap context
                pcap_context.overall_last_packet_time = pkt_header->ts.tv_sec;
                // Write a packet to a capture file
                pcap_dump ((U8 *)pcap_context.p_pcap_dumper, pkt_header, pkt_data);
            }
            else if (htons(p_udphdr->source)==5060||
                    htons(p_udphdr->dest)==5060)
            {
                S8 caller[256];
                S8 called[256];
                S8 sip_method[256];
                S8 sip_method_original_str[256];

                //figure out method
                memcpy (sip_method, p_udp_payload, sizeof (sip_method) - 1);
                memcpy (sip_method_original_str, p_udp_payload, sizeof (sip_method_original_str) - 1);
                sip_method[sizeof(sip_method)-1]='\0';
                sip_method_original_str[sizeof(sip_method_original_str)-1]='\0';

                if (strchr (sip_method, ' ') != NULL)
                {
                    *strchr (sip_method, ' ') = '\0';
                }
                else
                {
                    sip_method[0] = '\0';
                    if (verbosity >= 2)
                    {
                        PHONE_CAPTURE_LOG ("Empty SIP method!\n");
                    }
                }

                p_udp_payload[udp_payload_length] = 0;
                phone_capture_get_sip_peername(p_udp_payload,udp_payload_length,"From:",caller,sizeof(caller));
                phone_capture_get_sip_peername(p_udp_payload,udp_payload_length,"To:",called,sizeof(called));
                tag_string_call_id = phone_capture_gettag(p_udp_payload,udp_payload_length,"Call-ID:",&tag_length_call_id);
                memcpy(tag_string_call_id_str, tag_string_call_id, tag_length_call_id);
                tag_string_call_id_str[tag_length_call_id] = '\0';

                // Find the Call Id for this call
                if (tag_string_call_id != NULL && ((idx = phone_capture_find_by_call_id (tag_string_call_id, tag_length_call_id)) < 0))
                {
                    // This is a call not in our context yet
                    if ((idx = phone_capture_add (tag_string_call_id, tag_length_call_id, pkt_header->ts.tv_sec)) < 0)
                    {
                        PHONE_CAPTURE_LOG("Too many simultaneous calls. Ran out of call table space!\n");
                        break;
                    }
                }
                //Save packet time in context
                pcap_context.sip_context[idx].ts_current_packet.tv_sec = pkt_header->ts.tv_sec;
                pcap_context.sip_context[idx].ts_current_packet.tv_usec = pkt_header->ts.tv_usec;

                // Only this counter is outside of event handler file
                if (1 == pcap_context.is_mo)
                {
                    COUNT_SIP_OUT_MSG(idx);
                }

                // Extract content-type
                tag_string = NULL;
                tag_string = phone_capture_gettag (p_udp_payload, udp_payload_length, "Content-Type:", &tag_length);

                // Call added to our context
                if (strcmp (sip_method, "REGISTER") == 0)
                {
                    SET_STATE(idx, EVENT_REGISTER);
                }
                else if (strcmp (sip_method, "INVITE") == 0)
                {
                    SET_STATE(idx, EVENT_INVITE);
                }
                else if (strcmp (sip_method, "ACK") == 0)
                {
                    SET_STATE(idx, EVENT_ACK);
                }
                else if (strcmp (sip_method, "CANCEL") == 0)
                {
                    SET_STATE(idx, EVENT_CANCEL);
                }
                else if (NULL != strstr (sip_method_original_str, "100"))
                {
                    SET_STATE(idx, EVENT_100);
                }
                else if (NULL != strstr (sip_method_original_str, "183"))
                {
                    SET_STATE(idx, EVENT_183);
                }
                else if (NULL != strstr (sip_method_original_str, "200 OK"))
                {
                    if (idx >= 0 && tag_length > 0 && (0 == strncasecmp (tag_string, "application/sdp", tag_length)))
                    {
                        SET_STATE(idx, EVENT_200_SDP);
                    }
                    else
                    {
                        SET_STATE(idx, EVENT_200);
                    }
                }
                else if (NULL != strstr (sip_method_original_str, "401"))
                {
                    SET_STATE(idx, EVENT_401);
                }
                else if (NULL != strstr (sip_method_original_str, "403"))
                {
                    SET_STATE(idx, EVENT_403);
                }
                else if (NULL != strstr (sip_method_original_str, "407"))
                {
                    SET_STATE(idx, EVENT_407);
                }
                else if (NULL != strstr (sip_method_original_str, "480"))
                {
                    SET_STATE(idx, EVENT_480);
                }
                else if (NULL != strstr (sip_method_original_str, "100 trying"))
                {
                    PHONE_CAPTURE_LOG ("Session Id [%u] - 100 trying\n", idx);
                }
                else if (NULL != strstr (sip_method_original_str, "408 Request Timeout"))
                {
                    PHONE_CAPTURE_LOG ("Session Id [%u] - 408 Request Timeout\n", idx);
                }
                else if (verbosity >= 2)
                {
                    PHONE_CAPTURE_LOG ("Unknown SIP method:'%s'!\n", sip_method);
                }

                if (strcmp(sip_method, "BYE") == 0)
                {
                    pcap_context.sip_context[idx].had_bye = 1;
                }

                if (idx >= 0 && tag_length > 0 && 
                        strncasecmp (tag_string, "application/sdp", tag_length) == 0 && 
                        strstr (p_udp_payload, "\r\n\r\n") != NULL)
                {
                    in_addr_t tmp_addr;
                    U16 tmp_port;
                    if (!phone_capture_get_ip_port_from_sdp(strstr(p_udp_payload,"\r\n\r\n")+1,&tmp_addr,&tmp_port))
                    {
                        phone_capture_add_ip_port(idx, tmp_addr,tmp_port);
                    }
                    else
                    {
                        if (verbosity>=2)
                        {
                            PHONE_CAPTURE_LOG ("Can't get ip/port from SDP:\n%s\n\n",strstr(p_udp_payload,"\r\n\r\n")+1);
                        }
                    }
                }

                // Write packet to pcap
                pcap_dump ((U8 *)pcap_context.p_pcap_dumper, pkt_header, pkt_data);
                PHONE_CAPTURE_LOG("Packet [%u] sip_method [%s] session [%u] call-id [%s]\n",
                        pcap_context.total_packets, sip_method, idx, tag_string_call_id_str);
            }
            else
            {
                if (verbosity>=3)
                {
                    PHONE_CAPTURE_LOG ("Skipping udp packet 0x%x:%d->0x%x:%d\n",
                            p_iphdr->saddr, htons(p_udphdr->source),
                            p_iphdr->daddr, htons(p_udphdr->dest));
                }
            }
        }
    }

    // Dump statistics
    phone_capture_pcap_context_dump ();

    /* flush / close files */
    phone_capture_cleanup (1<<31);
    /* And close the session */
    pcap_close(p_pcap_handle);
    return;
}
S32 main (S32 argc, S8 *argv[])
{
/*
 * Usage:
 * pcap_capture_main (arg1, arg2, arg3, arg4) - Used for capturing of pcap and KPIs
 * 1) arg1 - PCAP file to be used as input. NULL for live capture. Type: String
 * 2) arg2 - PCAP file name to be used as output for pcap dump. Cannot be NULL. Type: String
 * 3) arg3 - Filter expression to be used for pcap capture. Type: String
 * 4) arg4 - UE IP address. Type: U32
 *
 * phone_capture_stop_capture () - Used to stop live running pcap capture
 *
 */
	 S8  * ptr;
	 U32  IpAddress;
	 if (argc == 2)
	  {
		  ptr = argv[1];
		  IpAddress = atoi(ptr);
	  printf("IpAddress = %d",IpAddress);
	  }else
	  {
		  printf ("Cmd line argument required \n");
		  return -1;
	  }

    /*phone_capture_main (NULL, "/mnt/sdcard/diagApp/test_out1.pcap", NULL, 0x0201A8C0);*/
	if(enableLog())
		Log_Trace (__FILE__,__LINE__,__func__,LOGL_SUCCESS,"  Log File open error !");
    phone_capture_main (NULL, "/mnt/sdcard/diagApp/test_out1.pcap", NULL, IpAddress);


    //phone_capture_main ("test2.pcap", "test_out2.pcap", NULL, 0x0A00A8C0);

    return (0);
}
