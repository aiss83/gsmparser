# gsmparser
Smal utility to anyone who wants to parse 3GPP GSM/GPRS messages as separate ones. Based uppon tshark utility.

Requirements:
 - tshark is required to parse prepared pcap files.
 - text2pcap is required to prepare pcap files from message and protocol descriptor.
 - python 3.5 and later to run this script.

Usage:
./gsmparse 'RR' '2d 06 3f 10 0e e0 01 79 b9 48 00 00 c5 be dc c4 2b 2b 2b 2b 2b 2b 2b'
 - first argument is protocol name,
 - second is hexadecimal string of octets (only that syntax is allowed now).

Possible protocols:
'RR': Radio-resource management protocol (CCCH basically),
'RLC_Uplink': GPRS RLC/MAC frames on uplink channel,
'RLC_Downlink': GPRS RLC/MAC frames on downlink channel,
'LLC': Logical Link Control frames,
'GPRS_LLC': Logical Link Control special kind used for GPRS,
'SNDCP': Sub Network Dependent Convergence Protocol used for GPRS to transport used data to SGSN,
'SNDCP_XID': used to parse XID negotiation parameters.
