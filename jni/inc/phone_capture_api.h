#ifndef _PHONE_CAPTURE_API_H_
#define _PHONE_CAPTURE_API_H_

void phone_capture_stop_capture ();
void phone_capture_main (const S8 *p_in_pcap, S8 *p_out_pcap, S8 *p_filter, U32 ue_ip);

#endif

