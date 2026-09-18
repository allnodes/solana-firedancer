#ifndef HEADER_fd_src_discof_allnodes_fd_an_shared_h
#define HEADER_fd_src_discof_allnodes_fd_an_shared_h


#include "fd_an_proto.h"

#include "../../disco/topo/fd_topo.h"
#include "../../tango/dcache/fd_dcache.h"
#include "../../util/pod/fd_pod.h"

#define FD_AN_SHARED_MAGIC (0xa11d0de5c0ffee01UL)


#define FD_AN_HOLD_MILLIS        (10000UL)
#define FD_AN_HOLD_MARGIN_MILLIS ( 2000UL)
#define FD_AN_RPC_ATTEMPTS_MAX   (    5UL)


#define FD_AN_STATE_INIT        (0)
#define FD_AN_STATE_WAIT_SV     (1)
#define FD_AN_STATE_RESOLVE     (2)
#define FD_AN_STATE_PROBE       (3)
#define FD_AN_STATE_QUERY       (4)
#define FD_AN_STATE_IDLE        (5)
#define FD_AN_STATE_UNAVAILABLE (6)
#define FD_AN_STATE_DISABLED    (7)


#define FD_AN_FALLBACK_NONE             (0)
#define FD_AN_FALLBACK_DISABLED         (1)
#define FD_AN_FALLBACK_NO_CERTS         (2)
#define FD_AN_FALLBACK_NO_SHRED_VERSION (3)
#define FD_AN_FALLBACK_UNREACHABLE      (4)
#define FD_AN_FALLBACK_NO_MATCH         (5)
#define FD_AN_FALLBACK_NO_CAPABILITY    (6)
#define FD_AN_FALLBACK_RPC_FAILED       (7)
#define FD_AN_FALLBACK_DECODE           (8)
#define FD_AN_FALLBACK_NO_NODE          (9)
#define FD_AN_FALLBACK_IPV6             (10)
#define FD_AN_FALLBACK_BAD_ADDR         (11)
#define FD_AN_FALLBACK_BAD_NODE         (12)
#define FD_AN_FALLBACK_BLOCKED          (13)
#define FD_AN_FALLBACK_BANNED           (14)
#define FD_AN_FALLBACK_HOLD_EXPIRED     (15)
#define FD_AN_FALLBACK_HASH_MISMATCH    (16)
#define FD_AN_FALLBACK_LOCAL_SNAPSHOT   (17)
#define FD_AN_FALLBACK_NO_INCREMENTAL   (18)
#define FD_AN_FALLBACK_STALE_NODE       (19)


#define FD_AN_SNAPCT_STARTING (0)
#define FD_AN_SNAPCT_RUNNING  (1)
#define FD_AN_SNAPCT_DISABLED (2)
#define FD_AN_SNAPCT_DONE     (3)

struct __attribute__((aligned(128))) fd_an_shared {
  ulong magic;


  ulong seq;
  int   state;
  int   fallback;
  int   has_node;
  fd_an_snapshot_node_t node;

  ulong  probe_latency_micros;
  ulong  endpoints_valid;
  ushort selected_port;


  int   snapct_state;

  ulong nodes_injected;
  ulong nodes_rejected;
  ulong hash_mismatch;
  ulong hash_stale;
  ulong held_millis;
};

typedef struct fd_an_shared fd_an_shared_t;

FD_PROTOTYPES_BEGIN


#define FD_AN_SHARED_PROP_SNAPCT "allnodes"
#define FD_AN_SHARED_PROP_CLIENT "allnodes_client"


static inline fd_an_shared_t *
fd_an_shared_join_prop( fd_topo_t const * topo,
                        char const *      prop ) {
  ulong obj_id = fd_pod_query_ulong( topo->props, prop, ULONG_MAX );
  if( FD_UNLIKELY( obj_id==ULONG_MAX ) ) return NULL;
  uchar * dcache = fd_dcache_join( fd_topo_obj_laddr( topo, obj_id ) );
  if( FD_UNLIKELY( !dcache || fd_dcache_app_sz( dcache )<sizeof(fd_an_shared_t) ) ) return NULL;
  return (fd_an_shared_t *)fd_dcache_app_laddr( dcache );
}

static inline fd_an_shared_t *
fd_an_shared_join( fd_topo_t const * topo ) {
  return fd_an_shared_join_prop( topo, FD_AN_SHARED_PROP_SNAPCT );
}


static inline void
fd_an_shared_publish_begin( fd_an_shared_t * shared ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( shared->seq ) = shared->seq+1UL;
  FD_COMPILER_MFENCE();
}

static inline void
fd_an_shared_publish_end( fd_an_shared_t * shared ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( shared->seq ) = shared->seq+1UL;
  FD_COMPILER_MFENCE();
}


static inline int
fd_an_shared_read( fd_an_shared_t const * shared,
                   fd_an_shared_t *       out ) {
  for( int i=0; i<4; i++ ) {
    FD_COMPILER_MFENCE();
    ulong seq0 = FD_VOLATILE_CONST( shared->seq );
    FD_COMPILER_MFENCE();
    if( FD_UNLIKELY( seq0 & 1UL ) ) continue;

    out->state    = FD_VOLATILE_CONST( shared->state    );
    out->fallback = FD_VOLATILE_CONST( shared->fallback );
    out->has_node = FD_VOLATILE_CONST( shared->has_node );
    out->node     = shared->node;

    FD_COMPILER_MFENCE();
    ulong seq1 = FD_VOLATILE_CONST( shared->seq );
    FD_COMPILER_MFENCE();
    if( FD_LIKELY( seq0==seq1 ) ) return 1;
  }
  return 0;
}


FD_FN_CONST static inline char const *
fd_an_fallback_cstr( int reason ) {
  switch( reason ) {
  case FD_AN_FALLBACK_NONE:             return "none";
  case FD_AN_FALLBACK_DISABLED:         return "disabled";
  case FD_AN_FALLBACK_NO_CERTS:         return "no_certs";
  case FD_AN_FALLBACK_NO_SHRED_VERSION: return "no_shred_version";
  case FD_AN_FALLBACK_UNREACHABLE:      return "unreachable";
  case FD_AN_FALLBACK_NO_MATCH:         return "no_match";
  case FD_AN_FALLBACK_NO_CAPABILITY:    return "no_capability";
  case FD_AN_FALLBACK_RPC_FAILED:       return "rpc_failed";
  case FD_AN_FALLBACK_DECODE:           return "decode";
  case FD_AN_FALLBACK_NO_NODE:          return "no_node";
  case FD_AN_FALLBACK_IPV6:             return "ipv6";
  case FD_AN_FALLBACK_BAD_ADDR:         return "bad_addr";
  case FD_AN_FALLBACK_BAD_NODE:         return "bad_node";
  case FD_AN_FALLBACK_BLOCKED:          return "blocked";
  case FD_AN_FALLBACK_BANNED:           return "banned";
  case FD_AN_FALLBACK_HOLD_EXPIRED:     return "hold_expired";
  case FD_AN_FALLBACK_HASH_MISMATCH:    return "hash_mismatch";
  case FD_AN_FALLBACK_LOCAL_SNAPSHOT:   return "local_snapshot";
  case FD_AN_FALLBACK_NO_INCREMENTAL:   return "no_incremental";
  case FD_AN_FALLBACK_STALE_NODE:       return "stale_node";
  default:                              return "unknown";
  }
}

FD_PROTOTYPES_END

#endif
