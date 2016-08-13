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


void phone_capture_handle_register_event (U32 idx)
{
    pcap_session_state_et   new_state;

    switch(pcap_context.sip_context[idx].state) 
    {
        case STATE_REGISTER_IN_PROGRESS:
            new_state = STATE_REGISTER_IN_PROGRESS;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            COUNT_SIP_MSG_RESENT(idx);
            COUNT_SIP_UE_REGISTER_ATTEMPT(idx);

            break;
        case STATE_REGISTER_SUCESS:
            new_state = STATE_REGISTER_IN_PROGRESS;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            COUNT_SIP_MSG_RESENT(idx);
            COUNT_SIP_UE_REGISTER_ATTEMPT(idx);

            break;
        case STATE_INACTIVE:
            new_state = STATE_REGISTER_IN_PROGRESS;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            COUNT_SIP_UE_REGISTER_ATTEMPT(idx);

            break;
        default:
            PHONE_CAPTURE_LOG("ERROR-> SId:[%u] STATE [%s], EVENT [%s] not handled\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_REGISTER));
            break;
    }
}

void phone_capture_handle_invite_event (U32 idx)
{
    pcap_session_state_et   new_state;

    switch(pcap_context.sip_context[idx].state) 
    {
        case STATE_REGISTER_SUCESS:
            new_state = STATE_INVITE_IN_PROGRESS;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            COUNT_SIP_MSG_RESENT(idx);
            if (1 == pcap_context.is_mo)
            {
                COUNT_SIP_MO_SETUP_SESSION_ATTEMPT(idx);
            }
            else
            {
                COUNT_SIP_MT_SETUP_SESSION_ATTEMPT(idx);
            }
            
            break;
        case STATE_INVITE_IN_PROGRESS:
            new_state = STATE_INVITE_IN_PROGRESS;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            COUNT_SIP_MSG_RESENT(idx);
            if (1 == pcap_context.is_mo)
            {
                COUNT_SIP_MO_SETUP_SESSION_ATTEMPT(idx);
            }
            else
            {
                COUNT_SIP_MT_SETUP_SESSION_ATTEMPT(idx);
            }
            
            break;
        case STATE_INACTIVE:
            new_state = STATE_INVITE_IN_PROGRESS;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            if (1 == pcap_context.is_mo)
            {
                COUNT_SIP_MO_SETUP_SESSION_ATTEMPT(idx);
            }
            else
            {
                COUNT_SIP_MT_SETUP_SESSION_ATTEMPT(idx);
            }
            break;
        default:
            PHONE_CAPTURE_LOG("ERROR-> SId:[%u] STATE [%s], EVENT [%s] not handled\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_INVITE));

            if (1 == pcap_context.is_mo)
            {
                COUNT_SIP_MO_SETUP_SESSION_ATTEMPT(idx);
            }
            else
            {
                COUNT_SIP_MT_SETUP_SESSION_ATTEMPT(idx);
            }
            break;
    }
}

void phone_capture_handle_ack_event (U32 idx)
{
    PHONE_CAPTURE_LOG("SId:[%u] STATE [%s], EVENT [%s]\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_ACK));
}

void phone_capture_handle_cancel_event (U32 idx)
{
    pcap_session_state_et   new_state;

    switch(pcap_context.sip_context[idx].state) 
    {
        case STATE_REGISTER_IN_PROGRESS:
            new_state = STATE_INACTIVE;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
        case STATE_INVITE_IN_PROGRESS:
            new_state = STATE_INACTIVE;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
        default:
            PHONE_CAPTURE_LOG("SId:[%u] STATE [%s], EVENT [%s] not handled\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_CANCEL));
            break;
    }
}

void phone_capture_handle_100_event (U32 idx)
{
    PHONE_CAPTURE_LOG("SId:[%u] STATE [%s], EVENT [%s]\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_100));
}

void phone_capture_handle_183_event (U32 idx)
{
    PHONE_CAPTURE_LOG("SId:[%u] STATE [%s], EVENT [%s]\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_183));
}

void phone_capture_handle_200_event (U32 idx)
{
    pcap_session_state_et   new_state;

    switch(pcap_context.sip_context[idx].state) 
    {
        case STATE_REGISTER_IN_PROGRESS:
            new_state = STATE_REGISTER_SUCESS;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            COUNT_SIP_REG_SUCCESS(idx);
            COUNT_SIP_UE_REGISTER_SUCCESS(idx);

            break;
            #if 0
        case STATE_INVITE_IN_PROGRESS:
            new_state = STATE_INVITE_SUCESS;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
            #endif
        default:
            PHONE_CAPTURE_LOG("ERROR-> SId:[%u] STATE [%s], EVENT [%s] not handled\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_200));
            break;
    }
}

void phone_capture_handle_200_sdp_event (U32 idx)
{
    pcap_session_state_et   new_state;

    switch(pcap_context.sip_context[idx].state) 
    {
        case STATE_INVITE_IN_PROGRESS:
            new_state = STATE_INVITE_SUCESS;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;


            if (1 == pcap_context.is_mo)
            {
                COUNT_SIP_MO_SETUP_SESSION_SUCCESS(idx);
            }
            else
            {
                COUNT_SIP_MT_SETUP_SESSION_SUCCESS(idx);
            }
            
            break;
        default:
            PHONE_CAPTURE_LOG("ERROR-> SId:[%u] STATE [%s], EVENT [%s] not handled\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_200_SDP));
            break;
    }
}

void phone_capture_handle_401_event (U32 idx)
{
    pcap_session_state_et   new_state;

    switch(pcap_context.sip_context[idx].state) 
    {
        case STATE_REGISTER_IN_PROGRESS:
            new_state = STATE_REGISTER_FAIL;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            COUNT_SIP_REG_FAIL(idx);
            COUNT_SIP_UE_REGISTER_REJECT(idx);

            // Transition to inactive
            new_state = STATE_INACTIVE;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
        case STATE_INVITE_IN_PROGRESS:
            new_state = STATE_INVITE_FAIL;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            // Transition to inactive
            new_state = STATE_INACTIVE;
            PHONE_CAPTURE_LOG("SId: [%u]Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
        default:
            PHONE_CAPTURE_LOG("ERROR-> SId: [%u] STATE [%s], EVENT [%s] not handled\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_401));
            break;
    }
}

void phone_capture_handle_403_event (U32 idx)
{
    pcap_session_state_et   new_state;

    switch(pcap_context.sip_context[idx].state) 
    {
        case STATE_REGISTER_IN_PROGRESS:
            new_state = STATE_REGISTER_FAIL;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            COUNT_SIP_REG_FAIL(idx);

            // Transition to inactive
            new_state = STATE_INACTIVE;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
        case STATE_INVITE_IN_PROGRESS:
            new_state = STATE_INVITE_FAIL;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            // Transition to inactive
            new_state = STATE_INACTIVE;
            PHONE_CAPTURE_LOG("SId: [%u]Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
        default:
            PHONE_CAPTURE_LOG("ERROR-> SId: [%u] STATE [%s], EVENT [%s] not handled\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_403));
            break;
    }
}

void phone_capture_handle_407_event (U32 idx)
{
    pcap_session_state_et   new_state;

    switch(pcap_context.sip_context[idx].state) 
    {
        case STATE_REGISTER_IN_PROGRESS:
            new_state = STATE_REGISTER_FAIL;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            COUNT_SIP_REG_FAIL(idx);

            // Transition to inactive
            new_state = STATE_INACTIVE;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
        case STATE_INVITE_IN_PROGRESS:
            new_state = STATE_INVITE_FAIL;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            // Transition to inactive
            new_state = STATE_INACTIVE;
            PHONE_CAPTURE_LOG("SId: [%u]Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
        default:
            PHONE_CAPTURE_LOG("ERROR-> SId: [%u] STATE [%s], EVENT [%s] not handled\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_407));
            break;
    }
}

void phone_capture_handle_480_event (U32 idx)
{
    pcap_session_state_et   new_state;

    switch(pcap_context.sip_context[idx].state) 
    {
        case STATE_REGISTER_IN_PROGRESS:
            new_state = STATE_REGISTER_FAIL;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;

            COUNT_SIP_REG_FAIL(idx);

            // Transition to inactive
            new_state = STATE_INACTIVE;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
        case STATE_INVITE_IN_PROGRESS:
            new_state = STATE_INVITE_FAIL;
            PHONE_CAPTURE_LOG("SId:[%u] Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            // Transition to inactive
            new_state = STATE_INACTIVE;
            PHONE_CAPTURE_LOG("SId: [%u]Old State:%s New State: %s\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_state_string(new_state));
            pcap_context.sip_context[idx].state = new_state;
            break;
        default:
            PHONE_CAPTURE_LOG("ERROR-> SId: [%u] STATE [%s], EVENT [%s] not handled\n", idx, phone_capture_get_state_string(pcap_context.sip_context[idx].state), phone_capture_get_event_string(EVENT_480));
            break;
    }
}


