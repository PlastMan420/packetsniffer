#pragma once
#include <minwindef.h>

typedef struct ip_hdr
{
    BYTE  ip_header_len : 4;  // 4-bit header length (in 32-bit words)
    BYTE  ip_version : 4;  // 4-bit IPv4 version
    BYTE  ip_tos;           // IP type of service
    WORD ip_total_length;  // Total length
    WORD ip_id;            // Unique identifier

    BYTE  ip_frag_offset : 5; // Fragment offset field

    BYTE  ip_more_fragment : 1;
    BYTE  ip_dont_fragment : 1;
    BYTE  ip_reserved_zero : 1;

    BYTE  ip_frag_offset1;    //fragment offset

    BYTE  ip_ttl;           // Time to live
    BYTE  ip_protocol;      // Protocol(TCP,UDP etc)
    WORD ip_checksum;      // IP checksum
    UINT   ip_srcaddr;       // Source address
    UINT   ip_destaddr;      // Source address
}   IPV4_HDR;

typedef struct udp_hdr
{
    WORD source_port;     // Source port no.
    WORD dest_port;       // Dest. port no.
    WORD udp_length;      // Udp packet length
    WORD udp_checksum;    // Udp checksum (optional)
}   UDP_HDR;

typedef struct tcp_header
{
    WORD source_port;  // source port
    WORD dest_port;    // destination port
    UINT   sequence;     // sequence number - 32 bits
    UINT   acknowledge;  // acknowledgement number - 32 bits

    BYTE  ns : 1;          //Nonce Sum Flag Added in RFC 3540.
    BYTE  reserved_part1 : 3; //according to rfc
    BYTE  data_offset : 4;    //number of dwords in the TCP header.

    BYTE  fin : 1;      //Finish Flag
    BYTE  syn : 1;      //Synchronise Flag
    BYTE  rst : 1;      //Reset Flag
    BYTE  psh : 1;      //Push Flag
    BYTE  ack : 1;      //Acknowledgement Flag
    BYTE  urg : 1;      //Urgent Flag

    BYTE  ecn : 1;      //ECN-Echo Flag
    BYTE  cwr : 1;      //Congestion Window Reduced Flag

    WORD window;          // window
    WORD checksum;        // checksum
    WORD urgent_pointer;  // urgent pointer
}   TCP_HDR;

typedef struct icmp_hdr
{
    BYTE type;          // ICMP Error type
    BYTE code;          // Type sub code
    USHORT checksum;
    USHORT id;
    USHORT seq;
}   ICMP_HDR;