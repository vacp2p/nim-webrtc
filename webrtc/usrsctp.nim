import strformat, os

# Socket definitions
import nativesockets

# C include directory
const root = currentSourcePath.parentDir
const usrsctpInclude = root/"usrsctp"/"usrsctplib"

{.passc: fmt"-I{usrsctpInclude}".}

# Generated @ 2022-11-21T15:11:52+01:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --compile=./usrsctp/usrsctplib/netinet/sctp_input.c --compile=./usrsctp/usrsctplib/netinet/sctp_asconf.c --compile=./usrsctp/usrsctplib/netinet/sctp_pcb.c --compile=./usrsctp/usrsctplib/netinet/sctp_usrreq.c --compile=./usrsctp/usrsctplib/netinet/sctp_cc_functions.c --compile=./usrsctp/usrsctplib/netinet/sctp_auth.c --compile=./usrsctp/usrsctplib/netinet/sctp_userspace.c --compile=./usrsctp/usrsctplib/netinet/sctp_output.c --compile=./usrsctp/usrsctplib/netinet/sctp_callout.c --compile=./usrsctp/usrsctplib/netinet/sctp_crc32.c --compile=./usrsctp/usrsctplib/netinet/sctp_sysctl.c --compile=./usrsctp/usrsctplib/netinet/sctp_sha1.c --compile=./usrsctp/usrsctplib/netinet/sctp_timer.c --compile=./usrsctp/usrsctplib/netinet/sctputil.c --compile=./usrsctp/usrsctplib/netinet/sctp_bsd_addr.c --compile=./usrsctp/usrsctplib/netinet/sctp_peeloff.c --compile=./usrsctp/usrsctplib/netinet/sctp_indata.c --compile=./usrsctp/usrsctplib/netinet/sctp_ss_functions.c --compile=./usrsctp/usrsctplib/user_socket.c --compile=./usrsctp/usrsctplib/netinet6/sctp6_usrreq.c --compile=./usrsctp/usrsctplib/user_mbuf.c --compile=./usrsctp/usrsctplib/user_environment.c --compile=./usrsctp/usrsctplib/user_recv_thread.c --pnim --preprocess --noHeader --defines=SCTP_PROCESS_LEVEL_LOCKS --defines=SCTP_SIMPLE_ALLOCATOR --defines=__Userspace__ --defines=STDC_HEADERS=1 --defines=HAVE_SYS_TYPES_H=1 --defines=HAVE_SYS_STAT_H=1 --defines=HAVE_STDLIB_H=1 --defines=HAVE_STRING_H=1 --defines=HAVE_MEMORY_H=1 --defines=HAVE_STRINGS_H=1 --defines=HAVE_INTTYPES_H=1 --defines=HAVE_STDINT_H=1 --defines=HAVE_UNISTD_H=1 --defines=HAVE_DLFCN_H=1 --defines=LT_OBJDIR=".libs/" --defines=SCTP_DEBUG=1 --defines=INET=1 --defines=INET6=1 --defines=HAVE_SOCKET=1 --defines=HAVE_INET_ADDR=1 --defines=HAVE_STDATOMIC_H=1 --defines=HAVE_SYS_QUEUE_H=1 --defines=HAVE_LINUX_IF_ADDR_H=1 --defines=HAVE_LINUX_RTNETLINK_H=1 --defines=HAVE_NETINET_IP_ICMP_H=1 --defines=HAVE_NET_ROUTE_H=1 --defines=_GNU_SOURCE --replace=sockaddr=SockAddr --replace=SockAddr_storage=Sockaddr_storage --replace=SockAddr_in=Sockaddr_in --replace=SockAddr_conn=Sockaddr_conn --replace=socklen_t=SockLen --includeDirs=./usrsctp/usrsctplib ./usrsctp/usrsctplib/usrsctp.h

# const 'SCTP_PACKED' has unsupported value '__attribute__((packed))'
# const 'SCTP_INACTIVE' has unsupported value '0x0002 /* neither SCTP_ADDR_REACHABLE'
# const 'SCTP_CMT_MAX' has unsupported value 'SCTP_CMT_MPTCP'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-DSCTP_PROCESS_LEVEL_LOCKS".}
{.passc: "-DSCTP_SIMPLE_ALLOCATOR".}
{.passc: "-D__Userspace__".}
{.passc: "-DSTDC_HEADERS=1".}
{.passc: "-DHAVE_SYS_TYPES_H=1".}
{.passc: "-DHAVE_SYS_STAT_H=1".}
{.passc: "-DHAVE_STDLIB_H=1".}
{.passc: "-DHAVE_STRING_H=1".}
{.passc: "-DHAVE_MEMORY_H=1".}
{.passc: "-DHAVE_STRINGS_H=1".}
{.passc: "-DHAVE_INTTYPES_H=1".}
{.passc: "-DHAVE_STDINT_H=1".}
{.passc: "-DHAVE_UNISTD_H=1".}
{.passc: "-DHAVE_DLFCN_H=1".}
{.passc: "-DLT_OBJDIR=\".libs/\"".}
{.passc: "-DSCTP_DEBUG=1".}
{.passc: "-DINET=1".}
{.passc: "-DINET6=1".}
{.passc: "-DHAVE_SOCKET=1".}
{.passc: "-DHAVE_INET_ADDR=1".}
{.passc: "-DHAVE_STDATOMIC_H=1".}
{.passc: "-DHAVE_SYS_QUEUE_H=1".}
{.passc: "-DHAVE_LINUX_IF_ADDR_H=1".}
{.passc: "-DHAVE_LINUX_RTNETLINK_H=1".}
{.passc: "-DHAVE_NETINET_IP_ICMP_H=1".}
{.passc: "-DHAVE_NET_ROUTE_H=1".}
{.passc: "-D_GNU_SOURCE".}
{.passc: "-I./usrsctp/usrsctplib".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_input.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_asconf.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_pcb.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_usrreq.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_cc_functions.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_auth.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_userspace.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_output.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_callout.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_crc32.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_sysctl.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_sha1.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_timer.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctputil.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_bsd_addr.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_peeloff.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_indata.c".}
{.compile: "./usrsctp/usrsctplib/netinet/sctp_ss_functions.c".}
{.compile: "./usrsctp/usrsctplib/user_socket.c".}
{.compile: "./usrsctp/usrsctplib/netinet6/sctp6_usrreq.c".}
{.compile: "./usrsctp/usrsctplib/user_mbuf.c".}
{.compile: "./usrsctp/usrsctplib/user_environment.c".}
{.compile: "./usrsctp/usrsctplib/user_recv_thread.c".}
const
  MSG_NOTIFICATION* = 0x00002000
  AF_CONN* = 123
  SCTP_FUTURE_ASSOC* = 0
  SCTP_CURRENT_ASSOC* = 1
  SCTP_ALL_ASSOC* = 2
  SCTP_EVENT_READ* = 0x00000001
  SCTP_EVENT_WRITE* = 0x00000002
  SCTP_EVENT_ERROR* = 0x00000004
  SCTP_ALIGN_RESV_PAD* = 92
  SCTP_ALIGN_RESV_PAD_SHORT* = 76
  SCTP_NO_NEXT_MSG* = 0x00000000
  SCTP_NEXT_MSG_AVAIL* = 0x00000001
  SCTP_NEXT_MSG_ISCOMPLETE* = 0x00000002
  SCTP_NEXT_MSG_IS_UNORDERED* = 0x00000004
  SCTP_NEXT_MSG_IS_NOTIFICATION* = 0x00000008
  SCTP_RECVV_NOINFO* = 0
  SCTP_RECVV_RCVINFO* = 1
  SCTP_RECVV_NXTINFO* = 2
  SCTP_RECVV_RN* = 3
  SCTP_SENDV_NOINFO* = 0
  SCTP_SENDV_SNDINFO* = 1
  SCTP_SENDV_PRINFO* = 2
  SCTP_SENDV_AUTHINFO* = 3
  SCTP_SENDV_SPA* = 4
  SCTP_SEND_SNDINFO_VALID* = 0x00000001
  SCTP_SEND_PRINFO_VALID* = 0x00000002
  SCTP_SEND_AUTHINFO_VALID* = 0x00000004
  SCTP_ASSOC_CHANGE* = 0x00000001
  SCTP_PEER_ADDR_CHANGE* = 0x00000002
  SCTP_REMOTE_ERROR* = 0x00000003
  SCTP_SEND_FAILED* = 0x00000004
  SCTP_SHUTDOWN_EVENT* = 0x00000005
  SCTP_ADAPTATION_INDICATION* = 0x00000006
  SCTP_PARTIAL_DELIVERY_EVENT* = 0x00000007
  SCTP_AUTHENTICATION_EVENT* = 0x00000008
  SCTP_STREAM_RESET_EVENT* = 0x00000009
  SCTP_SENDER_DRY_EVENT* = 0x0000000A
  SCTP_NOTIFICATIONS_STOPPED_EVENT* = 0x0000000B
  SCTP_ASSOC_RESET_EVENT* = 0x0000000C
  SCTP_STREAM_CHANGE_EVENT* = 0x0000000D
  SCTP_SEND_FAILED_EVENT* = 0x0000000E
  SCTP_COMM_UP* = 0x00000001
  SCTP_COMM_LOST* = 0x00000002
  SCTP_RESTART* = 0x00000003
  SCTP_SHUTDOWN_COMP* = 0x00000004
  SCTP_CANT_STR_ASSOC* = 0x00000005
  SCTP_ASSOC_SUPPORTS_PR* = 0x00000001
  SCTP_ASSOC_SUPPORTS_AUTH* = 0x00000002
  SCTP_ASSOC_SUPPORTS_ASCONF* = 0x00000003
  SCTP_ASSOC_SUPPORTS_MULTIBUF* = 0x00000004
  SCTP_ASSOC_SUPPORTS_RE_CONFIG* = 0x00000005
  SCTP_ASSOC_SUPPORTS_INTERLEAVING* = 0x00000006
  SCTP_ASSOC_SUPPORTS_MAX* = 0x00000006
  SCTP_ADDR_AVAILABLE* = 0x00000001
  SCTP_ADDR_UNREACHABLE* = 0x00000002
  SCTP_ADDR_REMOVED* = 0x00000003
  SCTP_ADDR_ADDED* = 0x00000004
  SCTP_ADDR_MADE_PRIM* = 0x00000005
  SCTP_ADDR_CONFIRMED* = 0x00000006
  SCTP_PARTIAL_DELIVERY_ABORTED* = 0x00000001
  SCTP_AUTH_NEW_KEY* = 0x00000001
  SCTP_AUTH_NO_AUTH* = 0x00000002
  SCTP_AUTH_FREE_KEY* = 0x00000003
  SCTP_STREAM_RESET_INCOMING_SSN* = 0x00000001
  SCTP_STREAM_RESET_OUTGOING_SSN* = 0x00000002
  SCTP_STREAM_RESET_DENIED* = 0x00000004
  SCTP_STREAM_RESET_FAILED* = 0x00000008
  SCTP_STREAM_CHANGED_DENIED* = 0x00000010
  SCTP_STREAM_RESET_INCOMING* = 0x00000001
  SCTP_STREAM_RESET_OUTGOING* = 0x00000002
  SCTP_ASSOC_RESET_DENIED* = 0x00000004
  SCTP_ASSOC_RESET_FAILED* = 0x00000008
  SCTP_STREAM_CHANGE_DENIED* = 0x00000004
  SCTP_STREAM_CHANGE_FAILED* = 0x00000008
  SCTP_DATA_UNSENT* = 0x00000001
  SCTP_DATA_SENT* = 0x00000002
  SCTP_DATA_LAST_FRAG* = 0x00000001
  SCTP_DATA_NOT_FRAG* = 0x00000003
  SCTP_NOTIFICATION* = 0x00000010
  SCTP_COMPLETE* = 0x00000020
  SCTP_EOF* = 0x00000100
  SCTP_ABORT* = 0x00000200
  SCTP_UNORDERED* = 0x00000400
  SCTP_ADDR_OVER* = 0x00000800
  SCTP_SENDALL* = 0x00001000
  SCTP_EOR* = 0x00002000
  SCTP_SACK_IMMEDIATELY* = 0x00004000
  SCTP_PR_SCTP_NONE* = 0x00000000
  SCTP_PR_SCTP_TTL* = 0x00000001
  SCTP_PR_SCTP_BUF* = 0x00000002
  SCTP_PR_SCTP_RTX* = 0x00000003
  SCTP_RTOINFO* = 0x00000001
  SCTP_ASSOCINFO* = 0x00000002
  SCTP_INITMSG* = 0x00000003
  SCTP_NODELAY* = 0x00000004
  SCTP_AUTOCLOSE* = 0x00000005
  SCTP_PRIMARY_ADDR* = 0x00000007
  SCTP_ADAPTATION_LAYER* = 0x00000008
  SCTP_DISABLE_FRAGMENTS* = 0x00000009
  SCTP_PEER_ADDR_PARAMS* = 0x0000000A
  SCTP_I_WANT_MAPPED_V4_ADDR* = 0x0000000D
  SCTP_MAXSEG* = 0x0000000E
  SCTP_DELAYED_SACK* = 0x0000000F
  SCTP_FRAGMENT_INTERLEAVE* = 0x00000010
  SCTP_PARTIAL_DELIVERY_POINT* = 0x00000011
  SCTP_HMAC_IDENT* = 0x00000014
  SCTP_AUTH_ACTIVE_KEY* = 0x00000015
  SCTP_AUTO_ASCONF* = 0x00000018
  SCTP_MAX_BURST* = 0x00000019
  SCTP_CONTEXT* = 0x0000001A
  SCTP_EXPLICIT_EOR* = 0x0000001B
  SCTP_REUSE_PORT* = 0x0000001C
  SCTP_EVENT* = 0x0000001E
  SCTP_RECVRCVINFO* = 0x0000001F
  SCTP_RECVNXTINFO* = 0x00000020
  SCTP_DEFAULT_SNDINFO* = 0x00000021
  SCTP_DEFAULT_PRINFO* = 0x00000022
  SCTP_REMOTE_UDP_ENCAPS_PORT* = 0x00000024
  SCTP_ECN_SUPPORTED* = 0x00000025
  SCTP_PR_SUPPORTED* = 0x00000026
  SCTP_AUTH_SUPPORTED* = 0x00000027
  SCTP_ASCONF_SUPPORTED* = 0x00000028
  SCTP_RECONFIG_SUPPORTED* = 0x00000029
  SCTP_NRSACK_SUPPORTED* = 0x00000030
  SCTP_PKTDROP_SUPPORTED* = 0x00000031
  SCTP_MAX_CWND* = 0x00000032
  SCTP_ENABLE_STREAM_RESET* = 0x00000900
  SCTP_PLUGGABLE_SS* = 0x00001203
  SCTP_SS_VALUE* = 0x00001204
  SCTP_STATUS* = 0x00000100
  SCTP_GET_PEER_ADDR_INFO* = 0x00000101
  SCTP_PEER_AUTH_CHUNKS* = 0x00000102
  SCTP_LOCAL_AUTH_CHUNKS* = 0x00000103
  SCTP_GET_ASSOC_NUMBER* = 0x00000104
  SCTP_GET_ASSOC_ID_LIST* = 0x00000105
  SCTP_TIMEOUTS* = 0x00000106
  SCTP_PR_STREAM_STATUS* = 0x00000107
  SCTP_PR_ASSOC_STATUS* = 0x00000108
  SCTP_SET_PEER_PRIMARY_ADDR* = 0x00000006
  SCTP_AUTH_CHUNK* = 0x00000012
  SCTP_AUTH_KEY* = 0x00000013
  SCTP_AUTH_DEACTIVATE_KEY* = 0x0000001D
  SCTP_AUTH_DELETE_KEY* = 0x00000016
  SCTP_RESET_STREAMS* = 0x00000901
  SCTP_RESET_ASSOC* = 0x00000902
  SCTP_ADD_STREAMS* = 0x00000903
  SPP_HB_ENABLE* = 0x00000001
  SPP_HB_DISABLE* = 0x00000002
  SPP_HB_DEMAND* = 0x00000004
  SPP_PMTUD_ENABLE* = 0x00000008
  SPP_PMTUD_DISABLE* = 0x00000010
  SPP_HB_TIME_IS_ZERO* = 0x00000080
  SPP_IPV6_FLOWLABEL* = 0x00000100
  SPP_DSCP* = 0x00000200
  SCTP_ENABLE_RESET_STREAM_REQ* = 0x00000001
  SCTP_ENABLE_RESET_ASSOC_REQ* = 0x00000002
  SCTP_ENABLE_CHANGE_ASSOC_REQ* = 0x00000004
  SCTP_ENABLE_VALUE_MASK* = 0x00000007
  SCTP_AUTH_HMAC_ID_RSVD* = 0x00000000
  SCTP_AUTH_HMAC_ID_SHA1* = 0x00000001
  SCTP_AUTH_HMAC_ID_SHA256* = 0x00000003
  SCTP_AUTH_HMAC_ID_SHA224* = 0x00000004
  SCTP_AUTH_HMAC_ID_SHA384* = 0x00000005
  SCTP_AUTH_HMAC_ID_SHA512* = 0x00000006
  SCTP_CLOSED* = 0x00000000
  SCTP_BOUND* = 0x00001000
  SCTP_LISTEN* = 0x00002000
  SCTP_COOKIE_WAIT* = 0x00000002
  SCTP_COOKIE_ECHOED* = 0x00000004
  SCTP_ESTABLISHED* = 0x00000008
  SCTP_SHUTDOWN_SENT* = 0x00000010
  SCTP_SHUTDOWN_RECEIVED* = 0x00000020
  SCTP_SHUTDOWN_ACK_SENT* = 0x00000040
  SCTP_SHUTDOWN_PENDING* = 0x00000080
  SCTP_ACTIVE* = 0x00000001
  SCTP_UNCONFIRMED* = 0x00000200
  SCTP_DATA* = 0x00000000
  SCTP_INITIATION* = 0x00000001
  SCTP_INITIATION_ACK* = 0x00000002
  SCTP_SELECTIVE_ACK* = 0x00000003
  SCTP_HEARTBEAT_REQUEST* = 0x00000004
  SCTP_HEARTBEAT_ACK* = 0x00000005
  SCTP_ABORT_ASSOCIATION* = 0x00000006
  SCTP_SHUTDOWN* = 0x00000007
  SCTP_SHUTDOWN_ACK* = 0x00000008
  SCTP_OPERATION_ERROR* = 0x00000009
  SCTP_COOKIE_ECHO* = 0x0000000A
  SCTP_COOKIE_ACK* = 0x0000000B
  SCTP_ECN_ECHO* = 0x0000000C
  SCTP_ECN_CWR* = 0x0000000D
  SCTP_SHUTDOWN_COMPLETE* = 0x0000000E
  SCTP_AUTHENTICATION* = 0x0000000F
  SCTP_NR_SELECTIVE_ACK* = 0x00000010
  SCTP_ASCONF_ACK* = 0x00000080
  SCTP_PACKET_DROPPED* = 0x00000081
  SCTP_STREAM_RESET* = 0x00000082
  SCTP_PAD_CHUNK* = 0x00000084
  SCTP_FORWARD_CUM_TSN* = 0x000000C0
  SCTP_ASCONF* = 0x000000C1
  SCTP_CC_RFC2581* = 0x00000000
  SCTP_CC_HSTCP* = 0x00000001
  SCTP_CC_HTCP* = 0x00000002
  SCTP_CC_RTCC* = 0x00000003
  SCTP_CC_OPT_RTCC_SETMODE* = 0x00002000
  SCTP_CC_OPT_USE_DCCC_EC* = 0x00002001
  SCTP_CC_OPT_STEADY_STEP* = 0x00002002
  SCTP_CMT_OFF* = 0
  SCTP_CMT_BASE* = 1
  SCTP_CMT_RPV1* = 2
  SCTP_CMT_RPV2* = 3
  SCTP_CMT_MPTCP* = 4
  SCTP_SS_DEFAULT* = 0x00000000
  SCTP_SS_ROUND_ROBIN* = 0x00000001
  SCTP_SS_ROUND_ROBIN_PACKET* = 0x00000002
  SCTP_SS_PRIORITY* = 0x00000003
  SCTP_SS_FAIR_BANDWITH* = 0x00000004
  SCTP_SS_FIRST_COME* = 0x00000005
  SCTP_BINDX_ADD_ADDR* = 0x00008001
  SCTP_BINDX_REM_ADDR* = 0x00008002
  SCTP_DUMP_OUTBOUND* = 1
  SCTP_DUMP_INBOUND* = 0
  SCTP_DEBUG_NONE* = 0x00000000
  SCTP_DEBUG_ALL* = 0xFFFFFFFF
type
  sctp_assoc_t* = uint32
  sctp_common_header* {.bycopy.} = object
    source_port*: uint16
    destination_port*: uint16
    verification_tag*: uint32
    crc32c*: uint32

  Sockaddr_conn* {.bycopy.} = object
    sconn_family*: uint16
    sconn_port*: uint16
    sconn_addr*: pointer

  sctp_sockstore* {.union, bycopy.} = object
    sin*: Sockaddr_in
    sin6*: Sockaddr_in6
    sconn*: Sockaddr_conn
    sa*: SockAddr

  sctp_rcvinfo* {.bycopy.} = object
    rcv_sid*: uint16
    rcv_ssn*: uint16
    rcv_flags*: uint16
    rcv_ppid*: uint32
    rcv_tsn*: uint32
    rcv_cumtsn*: uint32
    rcv_context*: uint32
    rcv_assoc_id*: sctp_assoc_t

  sctp_nxtinfo* {.bycopy.} = object
    nxt_sid*: uint16
    nxt_flags*: uint16
    nxt_ppid*: uint32
    nxt_length*: uint32
    nxt_assoc_id*: sctp_assoc_t

  sctp_recvv_rn* {.bycopy.} = object
    recvv_rcvinfo*: sctp_rcvinfo
    recvv_nxtinfo*: sctp_nxtinfo

  sctp_snd_all_completes* {.bycopy.} = object
    sall_stream*: uint16
    sall_flags*: uint16
    sall_ppid*: uint32
    sall_context*: uint32
    sall_num_sent*: uint32
    sall_num_failed*: uint32

  sctp_sndinfo* {.bycopy.} = object
    snd_sid*: uint16
    snd_flags*: uint16
    snd_ppid*: uint32
    snd_context*: uint32
    snd_assoc_id*: sctp_assoc_t

  sctp_prinfo* {.bycopy.} = object
    pr_policy*: uint16
    pr_value*: uint32

  sctp_authinfo* {.bycopy.} = object
    auth_keynumber*: uint16

  sctp_sendv_spa* {.bycopy.} = object
    sendv_flags*: uint32
    sendv_sndinfo*: sctp_sndinfo
    sendv_prinfo*: sctp_prinfo
    sendv_authinfo*: sctp_authinfo

  sctp_udpencaps* {.bycopy.} = object
    sue_address*: Sockaddr_storage
    sue_assoc_id*: uint32
    sue_port*: uint16

  sctp_assoc_change* {.bycopy.} = object
    sac_type*: uint16
    sac_flags*: uint16
    sac_length*: uint32
    sac_state*: uint16
    sac_error*: uint16
    sac_outbound_streams*: uint16
    sac_inbound_streams*: uint16
    sac_assoc_id*: sctp_assoc_t
    sac_info*: UncheckedArray[uint8] ## ```
                                     ##   not available yet
                                     ## ```
  
  sctp_paddr_change* {.bycopy.} = object
    spc_type*: uint16
    spc_flags*: uint16
    spc_length*: uint32
    spc_aaddr*: Sockaddr_storage
    spc_state*: uint32
    spc_error*: uint32
    spc_assoc_id*: sctp_assoc_t
    spc_padding*: array[4, uint8]

  sctp_remote_error* {.bycopy.} = object
    sre_type*: uint16
    sre_flags*: uint16
    sre_length*: uint32
    sre_error*: uint16
    sre_assoc_id*: sctp_assoc_t
    sre_data*: UncheckedArray[uint8]

  sctp_shutdown_event* {.bycopy.} = object
    sse_type*: uint16
    sse_flags*: uint16
    sse_length*: uint32
    sse_assoc_id*: sctp_assoc_t

  sctp_adaptation_event* {.bycopy.} = object
    sai_type*: uint16
    sai_flags*: uint16
    sai_length*: uint32
    sai_adaptation_ind*: uint32
    sai_assoc_id*: sctp_assoc_t

  sctp_pdapi_event* {.bycopy.} = object
    pdapi_type*: uint16
    pdapi_flags*: uint16
    pdapi_length*: uint32
    pdapi_indication*: uint32
    pdapi_stream*: uint32
    pdapi_seq*: uint32
    pdapi_assoc_id*: sctp_assoc_t

  sctp_authkey_event* {.bycopy.} = object
    auth_type*: uint16
    auth_flags*: uint16
    auth_length*: uint32
    auth_keynumber*: uint16
    auth_indication*: uint32
    auth_assoc_id*: sctp_assoc_t

  sctp_sender_dry_event* {.bycopy.} = object
    sender_dry_type*: uint16
    sender_dry_flags*: uint16
    sender_dry_length*: uint32
    sender_dry_assoc_id*: sctp_assoc_t

  sctp_stream_reset_event* {.bycopy.} = object
    strreset_type*: uint16
    strreset_flags*: uint16
    strreset_length*: uint32
    strreset_assoc_id*: sctp_assoc_t
    strreset_stream_list*: UncheckedArray[uint16]

  sctp_assoc_reset_event* {.bycopy.} = object
    assocreset_type*: uint16
    assocreset_flags*: uint16
    assocreset_length*: uint32
    assocreset_assoc_id*: sctp_assoc_t
    assocreset_local_tsn*: uint32
    assocreset_remote_tsn*: uint32

  sctp_stream_change_event* {.bycopy.} = object
    strchange_type*: uint16
    strchange_flags*: uint16
    strchange_length*: uint32
    strchange_assoc_id*: sctp_assoc_t
    strchange_instrms*: uint16
    strchange_outstrms*: uint16

  sctp_send_failed_event* {.bycopy.} = object
    ssfe_type*: uint16
    ssfe_flags*: uint16
    ssfe_length*: uint32
    ssfe_error*: uint32
    ssfe_info*: sctp_sndinfo
    ssfe_assoc_id*: sctp_assoc_t
    ssfe_data*: UncheckedArray[uint8]

  sctp_event* {.bycopy.} = object
    se_assoc_id*: sctp_assoc_t
    se_type*: uint16
    se_on*: uint8

  sctp_tlv* {.bycopy.} = object
    sn_type*: uint16
    sn_flags*: uint16
    sn_length*: uint32

  sctp_notification* {.union, bycopy.} = object
    sn_header*: sctp_tlv
    sn_assoc_change*: sctp_assoc_change
    sn_paddr_change*: sctp_paddr_change
    sn_remote_error*: sctp_remote_error
    sn_shutdown_event*: sctp_shutdown_event
    sn_adaptation_event*: sctp_adaptation_event
    sn_pdapi_event*: sctp_pdapi_event
    sn_auth_event*: sctp_authkey_event
    sn_sender_dry_event*: sctp_sender_dry_event
    sn_send_failed_event*: sctp_send_failed_event
    sn_strreset_event*: sctp_stream_reset_event
    sn_assocreset_event*: sctp_assoc_reset_event
    sn_strchange_event*: sctp_stream_change_event

  sctp_event_subscribe* {.bycopy.} = object
    sctp_data_io_event*: uint8
    sctp_association_event*: uint8
    sctp_address_event*: uint8
    sctp_send_failure_event*: uint8
    sctp_peer_error_event*: uint8
    sctp_shutdown_event*: uint8
    sctp_partial_delivery_event*: uint8
    sctp_adaptation_layer_event*: uint8
    sctp_authentication_event*: uint8
    sctp_sender_dry_event*: uint8
    sctp_stream_reset_event*: uint8

  sctp_initmsg* {.bycopy.} = object
    sinit_num_ostreams*: uint16
    sinit_max_instreams*: uint16
    sinit_max_attempts*: uint16
    sinit_max_init_timeo*: uint16

  sctp_rtoinfo* {.bycopy.} = object
    srto_assoc_id*: sctp_assoc_t
    srto_initial*: uint32
    srto_max*: uint32
    srto_min*: uint32

  sctp_assocparams* {.bycopy.} = object
    sasoc_assoc_id*: sctp_assoc_t
    sasoc_peer_rwnd*: uint32
    sasoc_local_rwnd*: uint32
    sasoc_cookie_life*: uint32
    sasoc_asocmaxrxt*: uint16
    sasoc_number_peer_destinations*: uint16

  sctp_setprim* {.bycopy.} = object
    ssp_addr*: Sockaddr_storage
    ssp_assoc_id*: sctp_assoc_t
    ssp_padding*: array[4, uint8]

  sctp_setadaptation* {.bycopy.} = object
    ssb_adaptation_ind*: uint32

  sctp_paddrparams* {.bycopy.} = object
    spp_address*: Sockaddr_storage
    spp_assoc_id*: sctp_assoc_t
    spp_hbinterval*: uint32
    spp_pathmtu*: uint32
    spp_flags*: uint32
    spp_ipv6_flowlabel*: uint32
    spp_pathmaxrxt*: uint16
    spp_dscp*: uint8

  sctp_assoc_value* {.bycopy.} = object
    assoc_id*: sctp_assoc_t
    assoc_value*: uint32

  sctp_reset_streams* {.bycopy.} = object
    srs_assoc_id*: sctp_assoc_t
    srs_flags*: uint16
    srs_number_streams*: uint16 ## ```
                                ##   0 == ALL
                                ## ```
    srs_stream_list*: UncheckedArray[uint16] ## ```
                                             ##   list if strrst_num_streams is not 0
                                             ## ```
  
  sctp_add_streams* {.bycopy.} = object
    sas_assoc_id*: sctp_assoc_t
    sas_instrms*: uint16
    sas_outstrms*: uint16

  sctp_hmacalgo* {.bycopy.} = object
    shmac_number_of_idents*: uint32
    shmac_idents*: UncheckedArray[uint16]

  sctp_sack_info* {.bycopy.} = object
    sack_assoc_id*: sctp_assoc_t
    sack_delay*: uint32
    sack_freq*: uint32

  sctp_default_prinfo* {.bycopy.} = object
    pr_policy*: uint16
    pr_value*: uint32
    pr_assoc_id*: sctp_assoc_t

  sctp_paddrinfo* {.bycopy.} = object
    spinfo_address*: Sockaddr_storage
    spinfo_assoc_id*: sctp_assoc_t
    spinfo_state*: int32
    spinfo_cwnd*: uint32
    spinfo_srtt*: uint32
    spinfo_rto*: uint32
    spinfo_mtu*: uint32

  sctp_status* {.bycopy.} = object
    sstat_assoc_id*: sctp_assoc_t
    sstat_state*: int32
    sstat_rwnd*: uint32
    sstat_unackdata*: uint16
    sstat_penddata*: uint16
    sstat_instrms*: uint16
    sstat_outstrms*: uint16
    sstat_fragmentation_point*: uint32
    sstat_primary*: sctp_paddrinfo

  sctp_authchunks* {.bycopy.} = object
    gauth_assoc_id*: sctp_assoc_t ## ```
                                  ##   uint32_t gauth_number_of_chunks; not available
                                  ## ```
    gauth_chunks*: UncheckedArray[uint8] ## ```
                                         ##   uint32_t gauth_number_of_chunks; not available
                                         ## ```
  
  sctp_assoc_ids* {.bycopy.} = object
    gaids_number_of_ids*: uint32
    gaids_assoc_id*: UncheckedArray[sctp_assoc_t]

  sctp_setpeerprim* {.bycopy.} = object
    sspp_addr*: Sockaddr_storage
    sspp_assoc_id*: sctp_assoc_t
    sspp_padding*: array[4, uint8]

  sctp_authchunk* {.bycopy.} = object
    sauth_chunk*: uint8

  sctp_get_nonce_values* {.bycopy.} = object
    gn_assoc_id*: sctp_assoc_t
    gn_peers_tag*: uint32
    gn_local_tag*: uint32

  sctp_authkey* {.bycopy.} = object
    sca_assoc_id*: sctp_assoc_t
    sca_keynumber*: uint16
    sca_keylength*: uint16
    sca_key*: UncheckedArray[uint8]

  sctp_authkeyid* {.bycopy.} = object
    scact_assoc_id*: sctp_assoc_t
    scact_keynumber*: uint16

  sctp_cc_option* {.bycopy.} = object
    option*: cint
    aid_value*: sctp_assoc_value

  sctp_stream_value* {.bycopy.} = object
    assoc_id*: sctp_assoc_t
    stream_id*: uint16
    stream_value*: uint16

  sctp_timeouts* {.bycopy.} = object
    stimo_assoc_id*: sctp_assoc_t
    stimo_init*: uint32
    stimo_data*: uint32
    stimo_sack*: uint32
    stimo_shutdown*: uint32
    stimo_heartbeat*: uint32
    stimo_cookie*: uint32
    stimo_shutdownack*: uint32

  sctp_prstatus* {.bycopy.} = object
    sprstat_assoc_id*: sctp_assoc_t
    sprstat_sid*: uint16
    sprstat_policy*: uint16
    sprstat_abandoned_unsent*: uint64
    sprstat_abandoned_sent*: uint64

  socket* {.incompleteStruct.} = object
  sctp_timeval* {.bycopy.} = object
    tv_sec*: uint32
    tv_usec*: uint32

  sctpstat* {.bycopy.} = object
    sctps_discontinuitytime*: sctp_timeval ## ```
                                           ##   sctpStats 18 (TimeStamp) 
                                           ##      MIB according to RFC 3873
                                           ## ```
    sctps_currestab*: uint32 ## ```
                             ##   sctpStats  1   (Gauge32)
                             ## ```
    sctps_activeestab*: uint32 ## ```
                               ##   sctpStats  2 (Counter32)
                               ## ```
    sctps_restartestab*: uint32 ## ```
                                ##   sctpStats  2 (Counter32)
                                ## ```
    sctps_collisionestab*: uint32
    sctps_passiveestab*: uint32 ## ```
                                ##   sctpStats  3 (Counter32)
                                ## ```
    sctps_aborted*: uint32   ## ```
                             ##   sctpStats  4 (Counter32)
                             ## ```
    sctps_shutdown*: uint32  ## ```
                             ##   sctpStats  5 (Counter32)
                             ## ```
    sctps_outoftheblue*: uint32 ## ```
                                ##   sctpStats  6 (Counter32)
                                ## ```
    sctps_checksumerrors*: uint32 ## ```
                                  ##   sctpStats  7 (Counter32)
                                  ## ```
    sctps_outcontrolchunks*: uint32 ## ```
                                    ##   sctpStats  8 (Counter64)
                                    ## ```
    sctps_outorderchunks*: uint32 ## ```
                                  ##   sctpStats  9 (Counter64)
                                  ## ```
    sctps_outunorderchunks*: uint32 ## ```
                                    ##   sctpStats 10 (Counter64)
                                    ## ```
    sctps_incontrolchunks*: uint32 ## ```
                                   ##   sctpStats 11 (Counter64)
                                   ## ```
    sctps_inorderchunks*: uint32 ## ```
                                 ##   sctpStats 12 (Counter64)
                                 ## ```
    sctps_inunorderchunks*: uint32 ## ```
                                   ##   sctpStats 13 (Counter64)
                                   ## ```
    sctps_fragusrmsgs*: uint32 ## ```
                               ##   sctpStats 14 (Counter64)
                               ## ```
    sctps_reasmusrmsgs*: uint32 ## ```
                                ##   sctpStats 15 (Counter64)
                                ## ```
    sctps_outpackets*: uint32 ## ```
                              ##   sctpStats 16 (Counter64)
                              ## ```
    sctps_inpackets*: uint32 ## ```
                             ##   sctpStats 17 (Counter64) 
                             ##      input statistics:
                             ## ```
    sctps_recvpackets*: uint32 ## ```
                               ##   total input packets
                               ## ```
    sctps_recvdatagrams*: uint32 ## ```
                                 ##   total input datagrams
                                 ## ```
    sctps_recvpktwithdata*: uint32 ## ```
                                   ##   total packets that had data
                                   ## ```
    sctps_recvsacks*: uint32 ## ```
                             ##   total input SACK chunks
                             ## ```
    sctps_recvdata*: uint32  ## ```
                             ##   total input DATA chunks
                             ## ```
    sctps_recvdupdata*: uint32 ## ```
                               ##   total input duplicate DATA chunks
                               ## ```
    sctps_recvheartbeat*: uint32 ## ```
                                 ##   total input HB chunks
                                 ## ```
    sctps_recvheartbeatack*: uint32 ## ```
                                    ##   total input HB-ACK chunks
                                    ## ```
    sctps_recvecne*: uint32  ## ```
                             ##   total input ECNE chunks
                             ## ```
    sctps_recvauth*: uint32  ## ```
                             ##   total input AUTH chunks
                             ## ```
    sctps_recvauthmissing*: uint32 ## ```
                                   ##   total input chunks missing AUTH
                                   ## ```
    sctps_recvivalhmacid*: uint32 ## ```
                                  ##   total number of invalid HMAC ids received
                                  ## ```
    sctps_recvivalkeyid*: uint32 ## ```
                                 ##   total number of invalid secret ids received
                                 ## ```
    sctps_recvauthfailed*: uint32 ## ```
                                  ##   total number of auth failed
                                  ## ```
    sctps_recvexpress*: uint32 ## ```
                               ##   total fast path receives all one chunk
                               ## ```
    sctps_recvexpressm*: uint32 ## ```
                                ##   total fast path multi-part data
                                ## ```
    sctps_recv_spare*: uint32 ## ```
                              ##   formerly sctps_recvnocrc
                              ## ```
    sctps_recvswcrc*: uint32 ## ```
                             ##   formerly sctps_recvnocrc
                             ## ```
    sctps_recvhwcrc*: uint32
    sctps_sendpackets*: uint32 ## ```
                               ##   total output packets
                               ## ```
    sctps_sendsacks*: uint32 ## ```
                             ##   total output SACKs
                             ## ```
    sctps_senddata*: uint32  ## ```
                             ##   total output DATA chunks
                             ## ```
    sctps_sendretransdata*: uint32 ## ```
                                   ##   total output retransmitted DATA chunks
                                   ## ```
    sctps_sendfastretrans*: uint32 ## ```
                                   ##   total output fast retransmitted DATA chunks
                                   ## ```
    sctps_sendmultfastretrans*: uint32 ## ```
                                       ##   total FR's that happened more than once
                                       ##   	                                      to same chunk (u-del multi-fr algo).
                                       ## ```
    sctps_sendheartbeat*: uint32 ## ```
                                 ##   total output HB chunks
                                 ## ```
    sctps_sendecne*: uint32  ## ```
                             ##   total output ECNE chunks
                             ## ```
    sctps_sendauth*: uint32  ## ```
                             ##   total output AUTH chunks FIXME
                             ## ```
    sctps_senderrors*: uint32 ## ```
                              ##   ip_output error counter
                              ## ```
    sctps_send_spare*: uint32 ## ```
                              ##   formerly sctps_sendnocrc
                              ## ```
    sctps_sendswcrc*: uint32 ## ```
                             ##   formerly sctps_sendnocrc
                             ## ```
    sctps_sendhwcrc*: uint32 ## ```
                             ##   PCKDROPREP statistics:
                             ## ```
    sctps_pdrpfmbox*: uint32 ## ```
                             ##   Packet drop from middle box
                             ## ```
    sctps_pdrpfehos*: uint32 ## ```
                             ##   P-drop from end host
                             ## ```
    sctps_pdrpmbda*: uint32  ## ```
                             ##   P-drops with data
                             ## ```
    sctps_pdrpmbct*: uint32  ## ```
                             ##   P-drops, non-data, non-endhost
                             ## ```
    sctps_pdrpbwrpt*: uint32 ## ```
                             ##   P-drop, non-endhost, bandwidth rep only
                             ## ```
    sctps_pdrpcrupt*: uint32 ## ```
                             ##   P-drop, not enough for chunk header
                             ## ```
    sctps_pdrpnedat*: uint32 ## ```
                             ##   P-drop, not enough data to confirm
                             ## ```
    sctps_pdrppdbrk*: uint32 ## ```
                             ##   P-drop, where process_chunk_drop said break
                             ## ```
    sctps_pdrptsnnf*: uint32 ## ```
                             ##   P-drop, could not find TSN
                             ## ```
    sctps_pdrpdnfnd*: uint32 ## ```
                             ##   P-drop, attempt reverse TSN lookup
                             ## ```
    sctps_pdrpdiwnp*: uint32 ## ```
                             ##   P-drop, e-host confirms zero-rwnd
                             ## ```
    sctps_pdrpdizrw*: uint32 ## ```
                             ##   P-drop, midbox confirms no space
                             ## ```
    sctps_pdrpbadd*: uint32  ## ```
                             ##   P-drop, data did not match TSN
                             ## ```
    sctps_pdrpmark*: uint32  ## ```
                             ##   P-drop, TSN's marked for Fast Retran 
                             ##      timeouts
                             ## ```
    sctps_timoiterator*: uint32 ## ```
                                ##   Number of iterator timers that fired
                                ## ```
    sctps_timodata*: uint32  ## ```
                             ##   Number of T3 data time outs
                             ## ```
    sctps_timowindowprobe*: uint32 ## ```
                                   ##   Number of window probe (T3) timers that fired
                                   ## ```
    sctps_timoinit*: uint32  ## ```
                             ##   Number of INIT timers that fired
                             ## ```
    sctps_timosack*: uint32  ## ```
                             ##   Number of sack timers that fired
                             ## ```
    sctps_timoshutdown*: uint32 ## ```
                                ##   Number of shutdown timers that fired
                                ## ```
    sctps_timoheartbeat*: uint32 ## ```
                                 ##   Number of heartbeat timers that fired
                                 ## ```
    sctps_timocookie*: uint32 ## ```
                              ##   Number of times a cookie timeout fired
                              ## ```
    sctps_timosecret*: uint32 ## ```
                              ##   Number of times an endpoint changed its cookie secret
                              ## ```
    sctps_timopathmtu*: uint32 ## ```
                               ##   Number of PMTU timers that fired
                               ## ```
    sctps_timoshutdownack*: uint32 ## ```
                                   ##   Number of shutdown ack timers that fired
                                   ## ```
    sctps_timoshutdownguard*: uint32 ## ```
                                     ##   Number of shutdown guard timers that fired
                                     ## ```
    sctps_timostrmrst*: uint32 ## ```
                               ##   Number of stream reset timers that fired
                               ## ```
    sctps_timoearlyfr*: uint32 ## ```
                               ##   Number of early FR timers that fired
                               ## ```
    sctps_timoasconf*: uint32 ## ```
                              ##   Number of times an asconf timer fired
                              ## ```
    sctps_timodelprim*: uint32 ## ```
                               ##   Number of times a prim_deleted timer fired
                               ## ```
    sctps_timoautoclose*: uint32 ## ```
                                 ##   Number of times auto close timer fired
                                 ## ```
    sctps_timoassockill*: uint32 ## ```
                                 ##   Number of asoc free timers expired
                                 ## ```
    sctps_timoinpkill*: uint32 ## ```
                               ##   Number of inp free timers expired 
                               ##      former early FR counters
                               ## ```
    sctps_spare*: array[11, uint32] ## ```
                                    ##   Number of inp free timers expired 
                                    ##      former early FR counters
                                    ## ```
    sctps_hdrops*: uint32    ## ```
                             ##   packet shorter than header
                             ## ```
    sctps_badsum*: uint32    ## ```
                             ##   checksum error
                             ## ```
    sctps_noport*: uint32    ## ```
                             ##   no endpoint for port
                             ## ```
    sctps_badvtag*: uint32   ## ```
                             ##   bad v-tag
                             ## ```
    sctps_badsid*: uint32    ## ```
                             ##   bad SID
                             ## ```
    sctps_nomem*: uint32     ## ```
                             ##   no memory
                             ## ```
    sctps_fastretransinrtt*: uint32 ## ```
                                    ##   number of multiple FR in a RTT window
                                    ## ```
    sctps_markedretrans*: uint32 ## ```
                                 ##   number of multiple FR in a RTT window
                                 ## ```
    sctps_naglesent*: uint32 ## ```
                             ##   nagle allowed sending
                             ## ```
    sctps_naglequeued*: uint32 ## ```
                               ##   nagle doesn't allow sending
                               ## ```
    sctps_maxburstqueued*: uint32 ## ```
                                  ##   max burst doesn't allow sending
                                  ## ```
    sctps_ifnomemqueued*: uint32 ## ```
                                 ##   look ahead tells us no memory in
                                 ##   	                                      interface ring buffer OR we had a
                                 ##   	                                      send error and are queuing one send.
                                 ## ```
    sctps_windowprobed*: uint32 ## ```
                                ##   total number of window probes sent
                                ## ```
    sctps_lowlevelerr*: uint32 ## ```
                               ##   total times an output error causes us
                               ##   	                                      to clamp down on next user send.
                               ## ```
    sctps_lowlevelerrusr*: uint32 ## ```
                                  ##   total times sctp_senderrors were caused from
                                  ##   	                                      a user send from a user invoked send not
                                  ##   	                                      a sack response
                                  ## ```
    sctps_datadropchklmt*: uint32 ## ```
                                  ##   Number of in data drops due to chunk limit reached
                                  ## ```
    sctps_datadroprwnd*: uint32 ## ```
                                ##   Number of in data drops due to rwnd limit reached
                                ## ```
    sctps_ecnereducedcwnd*: uint32 ## ```
                                   ##   Number of times a ECN reduced the cwnd
                                   ## ```
    sctps_vtagexpress*: uint32 ## ```
                               ##   Used express lookup via vtag
                               ## ```
    sctps_vtagbogus*: uint32 ## ```
                             ##   Collision in express lookup.
                             ## ```
    sctps_primary_randry*: uint32 ## ```
                                  ##   Number of times the sender ran dry of user data on primary
                                  ## ```
    sctps_cmt_randry*: uint32 ## ```
                              ##   Same for above
                              ## ```
    sctps_slowpath_sack*: uint32 ## ```
                                 ##   Sacks the slow way
                                 ## ```
    sctps_wu_sacks_sent*: uint32 ## ```
                                 ##   Window Update only sacks sent
                                 ## ```
    sctps_sends_with_flags*: uint32 ## ```
                                    ##   number of sends with sinfo_flags !=0
                                    ## ```
    sctps_sends_with_unord*: uint32 ## ```
                                    ##   number of unordered sends
                                    ## ```
    sctps_sends_with_eof*: uint32 ## ```
                                  ##   number of sends with EOF flag set
                                  ## ```
    sctps_sends_with_abort*: uint32 ## ```
                                    ##   number of sends with ABORT flag set
                                    ## ```
    sctps_protocol_drain_calls*: uint32 ## ```
                                        ##   number of times protocol drain called
                                        ## ```
    sctps_protocol_drains_done*: uint32 ## ```
                                        ##   number of times we did a protocol drain
                                        ## ```
    sctps_read_peeks*: uint32 ## ```
                              ##   Number of times recv was called with peek
                              ## ```
    sctps_cached_chk*: uint32 ## ```
                              ##   Number of cached chunks used
                              ## ```
    sctps_cached_strmoq*: uint32 ## ```
                                 ##   Number of cached stream oq's used
                                 ## ```
    sctps_left_abandon*: uint32 ## ```
                                ##   Number of unread messages abandoned by close
                                ## ```
    sctps_send_burst_avoid*: uint32 ## ```
                                    ##   Unused
                                    ## ```
    sctps_send_cwnd_avoid*: uint32 ## ```
                                   ##   Send cwnd full  avoidance, already max burst inflight to net
                                   ## ```
    sctps_fwdtsn_map_over*: uint32 ## ```
                                   ##   number of map array over-runs via fwd-tsn's
                                   ## ```
    sctps_queue_upd_ecne*: uint32 ## ```
                                  ##   Number of times we queued or updated an ECN chunk on send queue
                                  ## ```
    sctps_reserved*: array[31, uint32] ## ```
                                       ##   Future ABI compat - remove int's from here when adding new
                                       ## ```
  
proc usrsctp_init*(a1: uint16; a2: proc (`addr`: pointer; buffer: pointer;
    length: uint; tos: uint8; set_df: uint8): cint {.cdecl.};
                   a3: proc (format: cstring) {.cdecl, varargs.}) {.importc,
    cdecl.}
proc usrsctp_init_nothreads*(a1: uint16; a2: proc (`addr`: pointer;
    buffer: pointer; length: uint; tos: uint8; set_df: uint8): cint {.cdecl.};
                             a3: proc (format: cstring) {.cdecl, varargs.}) {.
    importc, cdecl.}
proc usrsctp_socket*(domain: cint; `type`: cint; protocol: cint; receive_cb: proc (
    sock: ptr socket; `addr`: sctp_sockstore; data: pointer; datalen: uint;
    a5: sctp_rcvinfo; flags: cint; ulp_info: pointer): cint {.cdecl.}; send_cb: proc (
    sock: ptr socket; sb_free: uint32; ulp_info: pointer): cint {.cdecl.};
                     sb_threshold: uint32; ulp_info: pointer): ptr socket {.
    importc, cdecl.}
proc usrsctp_setsockopt*(so: ptr socket; level: cint; option_name: cint;
                         option_value: pointer; option_len: SockLen): cint {.
    importc, cdecl.}
proc usrsctp_getsockopt*(so: ptr socket; level: cint; option_name: cint;
                         option_value: pointer; option_len: ptr SockLen): cint {.
    importc, cdecl.}
proc usrsctp_opt_info*(so: ptr socket; id: sctp_assoc_t; opt: cint;
                       arg: pointer; size: ptr SockLen): cint {.importc, cdecl.}
proc usrsctp_getpaddrs*(so: ptr socket; id: sctp_assoc_t;
                        raddrs: ptr ptr SockAddr): cint {.importc, cdecl.}
proc usrsctp_freepaddrs*(addrs: ptr SockAddr) {.importc, cdecl.}
proc usrsctp_getladdrs*(so: ptr socket; id: sctp_assoc_t;
                        raddrs: ptr ptr SockAddr): cint {.importc, cdecl.}
proc usrsctp_freeladdrs*(addrs: ptr SockAddr) {.importc, cdecl.}
proc usrsctp_sendv*(so: ptr socket; data: pointer; len: uint; to: ptr SockAddr;
                    addrcnt: cint; info: pointer; infolen: SockLen;
                    infotype: cuint; flags: cint): int {.importc, cdecl.}
proc usrsctp_recvv*(so: ptr socket; dbuf: pointer; len: uint;
                    `from`: ptr SockAddr; fromlen: ptr SockLen; info: pointer;
                    infolen: ptr SockLen; infotype: ptr cuint;
                    msg_flags: ptr cint): int {.importc, cdecl.}
proc usrsctp_bind*(so: ptr socket; name: ptr SockAddr; namelen: SockLen): cint {.
    importc, cdecl.}
proc usrsctp_bindx*(so: ptr socket; addrs: ptr SockAddr; addrcnt: cint;
                    flags: cint): cint {.importc, cdecl.}
proc usrsctp_listen*(so: ptr socket; backlog: cint): cint {.importc, cdecl.}
proc usrsctp_accept*(so: ptr socket; aname: ptr SockAddr; anamelen: ptr SockLen): ptr socket {.
    importc, cdecl.}
proc usrsctp_peeloff*(a1: ptr socket; a2: sctp_assoc_t): ptr socket {.importc,
    cdecl.}
proc usrsctp_connect*(so: ptr socket; name: ptr SockAddr; namelen: SockLen): cint {.
    importc, cdecl.}
proc usrsctp_connectx*(so: ptr socket; addrs: ptr SockAddr; addrcnt: cint;
                       id: ptr sctp_assoc_t): cint {.importc, cdecl.}
proc usrsctp_close*(so: ptr socket) {.importc, cdecl.}
proc usrsctp_getassocid*(a1: ptr socket; a2: ptr SockAddr): sctp_assoc_t {.
    importc, cdecl.}
proc usrsctp_finish*(): cint {.importc, cdecl.}
proc usrsctp_shutdown*(so: ptr socket; how: cint): cint {.importc, cdecl.}
proc usrsctp_conninput*(a1: pointer; a2: pointer; a3: uint; a4: uint8) {.
    importc, cdecl.}
proc usrsctp_set_non_blocking*(a1: ptr socket; a2: cint): cint {.importc, cdecl.}
proc usrsctp_get_non_blocking*(a1: ptr socket): cint {.importc, cdecl.}
proc usrsctp_register_address*(a1: pointer) {.importc, cdecl.}
proc usrsctp_deregister_address*(a1: pointer) {.importc, cdecl.}
proc usrsctp_set_ulpinfo*(a1: ptr socket; a2: pointer): cint {.importc, cdecl.}
proc usrsctp_get_ulpinfo*(a1: ptr socket; a2: ptr pointer): cint {.importc,
    cdecl.}
proc usrsctp_set_upcall*(so: ptr socket; upcall: proc (a1: ptr socket;
    a2: pointer; a3: cint) {.cdecl.}; arg: pointer): cint {.importc, cdecl.}
proc usrsctp_get_events*(so: ptr socket): cint {.importc, cdecl.}
proc usrsctp_handle_timers*(elapsed_milliseconds: uint32) {.importc, cdecl.}
proc usrsctp_dumppacket*(a1: pointer; a2: uint; a3: cint): cstring {.importc,
    cdecl.}
proc usrsctp_freedumpbuffer*(a1: cstring) {.importc, cdecl.}
proc usrsctp_enable_crc32c_offload*() {.importc, cdecl.}
proc usrsctp_disable_crc32c_offload*() {.importc, cdecl.}
proc usrsctp_crc32c*(a1: pointer; a2: uint): uint32 {.importc, cdecl.}
proc usrsctp_tunable_set_sctp_hashtblsize*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_hashtblsize*(): uint32 {.importc, cdecl.}
proc usrsctp_tunable_set_sctp_pcbtblsize*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_pcbtblsize*(): uint32 {.importc, cdecl.}
proc usrsctp_tunable_set_sctp_chunkscale*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_chunkscale*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_sendspace*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_sendspace*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_recvspace*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_recvspace*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_auto_asconf*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_auto_asconf*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_multiple_asconfs*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_multiple_asconfs*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_ecn_enable*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_ecn_enable*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_pr_enable*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_pr_enable*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_auth_enable*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_auth_enable*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_asconf_enable*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_asconf_enable*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_reconfig_enable*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_reconfig_enable*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_nrsack_enable*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_nrsack_enable*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_pktdrop_enable*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_pktdrop_enable*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_no_csum_on_loopback*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_no_csum_on_loopback*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_peer_chunk_oh*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_peer_chunk_oh*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_max_burst_default*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_max_burst_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_max_chunks_on_queue*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_max_chunks_on_queue*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_min_split_point*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_min_split_point*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_delayed_sack_time_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_delayed_sack_time_default*(): uint32 {.importc,
    cdecl.}
proc usrsctp_sysctl_set_sctp_sack_freq_default*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_sack_freq_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_system_free_resc_limit*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_system_free_resc_limit*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_asoc_free_resc_limit*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_asoc_free_resc_limit*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_heartbeat_interval_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_heartbeat_interval_default*(): uint32 {.importc,
    cdecl.}
proc usrsctp_sysctl_set_sctp_pmtu_raise_time_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_pmtu_raise_time_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_shutdown_guard_time_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_shutdown_guard_time_default*(): uint32 {.importc,
    cdecl.}
proc usrsctp_sysctl_set_sctp_secret_lifetime_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_secret_lifetime_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_rto_max_default*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_rto_max_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_rto_min_default*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_rto_min_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_rto_initial_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_rto_initial_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_init_rto_max_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_init_rto_max_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_valid_cookie_life_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_valid_cookie_life_default*(): uint32 {.importc,
    cdecl.}
proc usrsctp_sysctl_set_sctp_init_rtx_max_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_init_rtx_max_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_assoc_rtx_max_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_assoc_rtx_max_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_path_rtx_max_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_path_rtx_max_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_add_more_threshold*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_add_more_threshold*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_nr_incoming_streams_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_nr_incoming_streams_default*(): uint32 {.importc,
    cdecl.}
proc usrsctp_sysctl_set_sctp_nr_outgoing_streams_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_nr_outgoing_streams_default*(): uint32 {.importc,
    cdecl.}
proc usrsctp_sysctl_set_sctp_cmt_on_off*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_cmt_on_off*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_cmt_use_dac*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_cmt_use_dac*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_use_cwnd_based_maxburst*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_use_cwnd_based_maxburst*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_nat_friendly*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_nat_friendly*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_L2_abc_variable*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_L2_abc_variable*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_mbuf_threshold_count*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_mbuf_threshold_count*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_do_drain*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_do_drain*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_hb_maxburst*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_hb_maxburst*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_abort_if_one_2_one_hits_limit*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_abort_if_one_2_one_hits_limit*(): uint32 {.importc,
    cdecl.}
proc usrsctp_sysctl_set_sctp_min_residual*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_min_residual*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_max_retran_chunk*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_max_retran_chunk*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_logging_level*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_logging_level*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_default_cc_module*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_default_cc_module*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_default_frag_interleave*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_default_frag_interleave*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_mobility_base*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_mobility_base*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_mobility_fasthandoff*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_mobility_fasthandoff*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_inits_include_nat_friendly*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_inits_include_nat_friendly*(): uint32 {.importc,
    cdecl.}
proc usrsctp_sysctl_set_sctp_udp_tunneling_port*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_udp_tunneling_port*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_enable_sack_immediately*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_enable_sack_immediately*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_vtag_time_wait*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_vtag_time_wait*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_blackhole*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_blackhole*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_sendall_limit*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_sendall_limit*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_diag_info_code*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_diag_info_code*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_fr_max_burst_default*(value: uint32): cint {.
    importc, cdecl.}
proc usrsctp_sysctl_get_sctp_fr_max_burst_default*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_path_pf_threshold*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_path_pf_threshold*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_default_ss_module*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_default_ss_module*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_rttvar_bw*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_rttvar_bw*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_rttvar_rtt*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_rttvar_rtt*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_rttvar_eqret*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_rttvar_eqret*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_steady_step*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_steady_step*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_use_dccc_ecn*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_use_dccc_ecn*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_buffer_splitting*(value: uint32): cint {.importc,
    cdecl.}
proc usrsctp_sysctl_get_sctp_buffer_splitting*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_initial_cwnd*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_initial_cwnd*(): uint32 {.importc, cdecl.}
proc usrsctp_sysctl_set_sctp_debug_on*(value: uint32): cint {.importc, cdecl.}
proc usrsctp_sysctl_get_sctp_debug_on*(): uint32 {.importc, cdecl.}
  ## ```
                                                                   ##   More specific values can be found in sctp_constants, but
                                                                   ##    are not considered to be part of the API.
                                                                   ## ```
proc usrsctp_get_stat*(a1: ptr sctpstat) {.importc, cdecl.}
{.pop.}
