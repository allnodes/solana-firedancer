#ifndef HEADER_fd_src_discof_allnodes_fd_an_proto_h
#define HEADER_fd_src_discof_allnodes_fd_an_proto_h


#include "../../util/fd_util_base.h"


#define FD_AN_PROTO_SOCKADDR_V4_SZ (7UL)
#define FD_AN_PROTO_SOCKADDR_V6_SZ (19UL)
#define FD_AN_PROTO_SNAPSHOT_HASH_SZ (80UL)
#define FD_AN_PROTO_VERSION_MAX (64UL)


#define FD_AN_PROTO_OK        ( 0)
#define FD_AN_PROTO_ERR_DECODE (-1)
#define FD_AN_PROTO_ERR_NO_NODE (-2)
#define FD_AN_PROTO_ERR_IPV6   (-3)

struct fd_an_service_info {
  uint  shred_version;
  ulong capabilities;
  char  version[ FD_AN_PROTO_VERSION_MAX ];
};

typedef struct fd_an_service_info fd_an_service_info_t;

struct fd_an_snapshot_node {
  uchar  pubkey[ 32 ];
  uint   ip4;
  ushort port;
  ulong  full_slot;
  uchar  full_hash[ 32 ];
  ulong  incr_slot;
  uchar  incr_hash[ 32 ];
  int    has_incremental;
  ulong  latency_micros;
};

typedef struct fd_an_snapshot_node fd_an_snapshot_node_t;

FD_PROTOTYPES_BEGIN


ulong
fd_an_proto_encode_bootstrap_req( uchar * buf,
                                  ulong   buf_sz,
                                  uint    shred_version );


#define FD_AN_PROTO_HEARTBEAT_REQ_BUF_SZ (160UL)

ulong
fd_an_proto_encode_heartbeat_req( uchar *       buf,
                                  ulong         buf_sz,
                                  uchar const * identity,
                                  ulong         slot,
                                  uchar const * signature );


int
fd_an_proto_decode_service_info( fd_an_service_info_t * out,
                                 uchar const *          msg,
                                 ulong                  msg_sz );


int
fd_an_proto_decode_bootstrap( fd_an_snapshot_node_t * out,
                              uchar const *           msg,
                              ulong                   msg_sz );


FD_FN_CONST char const *
fd_an_proto_strerror( int err );

FD_PROTOTYPES_END

#endif
