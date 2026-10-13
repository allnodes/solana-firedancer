
#include "fd_an_client.h"
#include "fd_an_consts.h"
#include "fd_an_heartbeat.h"

#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/sleep/fd_sleep.h"
#include "../../disco/topo/fd_topo.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../waltz/resolv/fd_netdb.h"

#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "generated/fd_an_tile_seccomp.h"

#include "fd_an_version_generated.h"

FD_STATIC_ASSERT( sizeof(FD_AN_CLIENT_VERSION)-1UL<=FD_GRPC_CLIENT_VERSION_LEN_MAX, allnodes_client_version_too_long );

#define NAME "anclnt"


#define AN_PROBE_BUDGET_NANOS          ((long)2e9)
#define AN_REQUEST_TIMEOUT_NANOS       ((long)3e9)
#define AN_ATTEMPT_PAUSE_NANOS         ((long)200e6)
#define AN_SHRED_VERSION_TIMEOUT_NANOS ((long)30e9)


#define AN_JOIN_TIMEOUT_NANOS ((long)120e9)
#define AN_BOOT_MAX_NANOS     ((long)300e9)

#define AN_ADNS_REQS_MAX (32UL)


#define AN_HB_FIRST_ATTEMPTS       (FD_AN_RPC_ATTEMPTS_MAX+1UL)
#define AN_HB_OTHER_ATTEMPTS       (2UL)
#define AN_HB_INTERVAL_MIN_MICROS  (1000000UL)
#define AN_HB_DEFER_NANOS          ((long)1e9)
#define AN_HB_DEFER_MAX            (5UL)

FD_AN_CONST_ULONG( HEARTBEAT_INTERVAL, 300000000UL );


#define AN_IDLE_MILLIS (10)

struct fd_an_tile {
  fd_an_client_t *  client;
  fd_an_hb_t *      hb;
  fd_an_shared_t *  shared;
  fd_adns_t *       adns;
  fd_an_tls_ctx_t * tls_ctx;

  fd_an_routes_shared_t * routes_shared;
  ulong                   routes_seen;

  fd_an_consts_t * consts;
  int              consts_published;

  fd_an_flags_shared_t * flags;
  int                    flags_published;

  fd_netdb_fds_t netdb_fds[ 1 ];
  int            adns_epoll_fd;

  fd_keyswitch_t *     keyswitch;
  fd_keyguard_client_t keyguard[ 1 ];
  fd_sha512_t          sha[ 1 ];
  uchar                identity[ 32 ];

  volatile ulong const * replay_metrics;

  ulong  seed;
  ushort shred_version;

  int  disabled;
  int  bootstrap;
  int  boot_over;
  int  hb_started;
  ulong hb_defer_cnt;

  long start_nanos;

  fd_an_client_cfg_t cfg;
};

typedef struct fd_an_tile fd_an_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  ulong a = alignof(fd_an_tile_t);
  a = fd_ulong_max( a, fd_adns_align() );
  a = fd_ulong_max( a, fd_an_client_align() );
  a = fd_ulong_max( a, fd_an_hb_align() );
  a = fd_ulong_max( a, fd_an_conn_tls_ctx_align() );
  return a;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_an_tile_t),  sizeof(fd_an_tile_t)                  );
  l = FD_LAYOUT_APPEND( l, fd_adns_align(),        fd_adns_footprint( AN_ADNS_REQS_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_an_client_align(),   fd_an_client_footprint()              );
  l = FD_LAYOUT_APPEND( l, fd_an_hb_align(),       fd_an_hb_footprint()                  );
  l = FD_LAYOUT_APPEND( l, fd_an_conn_tls_ctx_align(), fd_an_conn_tls_ctx_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}


static void
disable( fd_an_tile_t * ctx,
         int            state,
         int            reason ) {
  ctx->disabled = 1;
  if( FD_UNLIKELY( !ctx->shared ) ) return;
  fd_an_shared_publish_begin( ctx->shared );
  ctx->shared->state    = state;
  ctx->shared->fallback = reason;
  fd_an_shared_publish_end( ctx->shared );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_an_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_an_tile_t), sizeof(fd_an_tile_t) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_adns_align(),      fd_adns_footprint( AN_ADNS_REQS_MAX ) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_an_client_align(), fd_an_client_footprint()              );
  FD_SCRATCH_ALLOC_APPEND( l, fd_an_hb_align(),     fd_an_hb_footprint()                  );
  void * tls_ctx_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_an_conn_tls_ctx_align(), fd_an_conn_tls_ctx_footprint() );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu", scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }

  memset( ctx, 0, sizeof(fd_an_tile_t) );

  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );

  if( FD_UNLIKELY( !fd_netdb_open_fds( ctx->netdb_fds ) ) ) FD_LOG_ERR(( "fd_netdb_open_fds failed" ));
  ctx->adns_epoll_fd = epoll_create1( EPOLL_CLOEXEC );
  if( FD_UNLIKELY( ctx->adns_epoll_fd<0 ) ) FD_LOG_ERR(( "epoll_create1 failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ctx->shared = fd_an_shared_join_prop( topo, FD_AN_SHARED_PROP_CLIENT );
  if( FD_UNLIKELY( !ctx->shared ) ) {
    ctx->disabled = 1;
    return;
  }
  ctx->shared->magic = FD_AN_SHARED_MAGIC;

  ulong obj_id = fd_pod_query_ulong( topo->props, FD_AN_SHARED_PROP_CLIENT, ULONG_MAX );
  FD_TEST( obj_id!=ULONG_MAX );
  char const * identity_path = fd_pod_queryf_cstr( topo->props, "", "obj.%lu.an_identity", obj_id );
  FD_TEST( identity_path[ 0 ] );
  fd_memcpy( ctx->identity, fd_keyload_load( identity_path, /* pubkey only: */ 1 ), 32UL );

  ctx->tls_ctx = fd_an_conn_tls_ctx_new( tls_ctx_mem );
  if( FD_UNLIKELY( !ctx->tls_ctx ) ) disable( ctx, FD_AN_STATE_UNAVAILABLE, FD_AN_FALLBACK_NO_CERTS );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_an_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_an_tile_t), sizeof(fd_an_tile_t) );
  void * adns_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_adns_align(),      fd_adns_footprint( AN_ADNS_REQS_MAX ) );
  void * client_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_an_client_align(), fd_an_client_footprint()              );
  void * hb_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_an_hb_align(),     fd_an_hb_footprint()                  );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->start_nanos = fd_log_wallclock();

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_anclnt", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "anclnt_sign", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX && sign_out_idx!=ULONG_MAX );
  fd_topo_link_t const * sign_in  = &topo->links[ tile->in_link_id [ sign_in_idx  ] ];
  fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];
  fd_sleep_t * sleep = NULL;
  if( FD_UNLIKELY( topo->sleep_obj_id!=ULONG_MAX ) ) {
    sleep = fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) );
    FD_TEST( sleep );
  }
  FD_TEST( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard,
                                                            sign_out->mcache, sign_out->dcache,
                                                            sign_in->mcache,  sign_in->dcache,
                                                            sign_out->mtu,    sign_in->mtu,
                                                            sleep, sign_out->id,
                                                            fd_topo_find_link_consumer( topo, sign_out ) ) ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );

  ulong replay_idx = fd_topo_find_tile( topo, "replay", 0UL );
  if( FD_LIKELY( replay_idx!=ULONG_MAX && topo->tiles[ replay_idx ].metrics ) ) {
    ctx->replay_metrics = fd_metrics_tile( topo->tiles[ replay_idx ].metrics );
  }

  ctx->routes_shared = fd_an_routes_shared_join( topo );

  ctx->consts = fd_an_consts_shared_join( topo );
  fd_an_consts_attach( ctx->consts );

  ctx->flags = fd_an_flags_shared_join( topo );

  if( FD_UNLIKELY( ctx->disabled ) ) return;

  ulong obj_id = fd_pod_query_ulong( topo->props, FD_AN_SHARED_PROP_CLIENT, ULONG_MAX );
  FD_TEST( obj_id!=ULONG_MAX );

  ctx->bootstrap = fd_pod_query_ulong( topo->props, FD_AN_SHARED_PROP_SNAPCT, ULONG_MAX )!=ULONG_MAX;

  ulong        shred_ver = fd_pod_queryf_ulong( topo->props, 0UL, "obj.%lu.an_shredver",   obj_id );
  char const * endpoints = fd_pod_queryf_cstr ( topo->props, "",  "obj.%lu.an_endpoints", obj_id );

  ctx->shred_version = (ushort)shred_ver;

  ctx->adns = fd_adns_join( fd_adns_new( adns_mem, AN_ADNS_REQS_MAX, ctx->adns_epoll_fd ) );
  if( FD_UNLIKELY( !ctx->adns ) ) {
    disable( ctx, FD_AN_STATE_UNAVAILABLE, FD_AN_FALLBACK_UNREACHABLE );
    return;
  }

  ctx->cfg = (fd_an_client_cfg_t){
    .endpoints                   = endpoints,
    .version                     = FD_AN_CLIENT_VERSION,
    .version_len                 = sizeof(FD_AN_CLIENT_VERSION)-1UL,
    .shred_version               = ctx->shred_version,
    .bootstrap                   = ctx->bootstrap,
    .shred_version_timeout_nanos = AN_SHRED_VERSION_TIMEOUT_NANOS,
    .probe_budget_nanos          = AN_PROBE_BUDGET_NANOS,
    .request_timeout_nanos       = AN_REQUEST_TIMEOUT_NANOS,
    .attempt_pause_nanos         = AN_ATTEMPT_PAUSE_NANOS,
    .max_attempts                = FD_AN_RPC_ATTEMPTS_MAX
  };

  ctx->client = fd_an_client_new( client_mem, &ctx->cfg, ctx->tls_ctx, ctx->adns, ctx->shared, ctx->seed );
  if( FD_UNLIKELY( !ctx->client ) ) {
    disable( ctx, FD_AN_STATE_DISABLED, FD_AN_FALLBACK_DISABLED );
    return;
  }

  fd_an_hb_cfg_t hb_cfg = {
    .version               = FD_AN_CLIENT_VERSION,
    .version_len           = sizeof(FD_AN_CLIENT_VERSION)-1UL,
    .request_timeout_nanos = AN_REQUEST_TIMEOUT_NANOS,
    .attempt_pause_nanos   = AN_ATTEMPT_PAUSE_NANOS,
    .first_attempts        = AN_HB_FIRST_ATTEMPTS,
    .other_attempts        = AN_HB_OTHER_ATTEMPTS
  };
  ctx->hb = fd_an_hb_new( hb_mem, &hb_cfg, ctx->tls_ctx, ctx->seed+FD_AN_ENDPOINT_MAX+1UL );
  FD_TEST( ctx->hb );

}

static void
during_housekeeping( fd_an_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_memcpy( ctx->identity, ctx->keyswitch->bytes, 32UL );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}


static int
snapct_gone( fd_an_tile_t const * ctx,
             long                 now ) {
  int state = FD_VOLATILE_CONST( ctx->shared->snapct_state );
  if( FD_UNLIKELY( state==FD_AN_SNAPCT_DISABLED || state==FD_AN_SNAPCT_DONE ) ) return 1;
  if( FD_UNLIKELY( state==FD_AN_SNAPCT_STARTING && now-ctx->start_nanos>AN_JOIN_TIMEOUT_NANOS ) ) return 1;
  return now-ctx->start_nanos>AN_BOOT_MAX_NANOS;
}



static void
consts_publish( fd_an_tile_t * ctx ) {
  if( FD_LIKELY( ctx->consts_published || !ctx->consts ) ) return;
  fd_an_consts_t const * consts = fd_an_client_consts( ctx->client );
  if( FD_LIKELY( !consts ) ) return;
  ctx->consts_published = 1;
  fd_an_consts_publish( ctx->consts, consts );
}


static void
flags_publish( fd_an_tile_t * ctx ) {
  if( FD_LIKELY( ctx->flags_published || !ctx->flags ) ) return;
  ulong word  = 0UL;
  int   state = ctx->disabled ? FD_AN_FLAGS_NONE : fd_an_client_flags_state( ctx->client, &word );
  if( FD_LIKELY( state==FD_AN_FLAGS_PENDING ) ) return;
  fd_an_flags_shared_publish( ctx->flags, state, word );
  ctx->flags_published = 1;
}


static void
routes_publish( fd_an_tile_t * ctx ) {
  ulong gen = fd_an_hb_routes_gen( ctx->hb );
  if( FD_LIKELY( gen==ctx->routes_seen ) ) return;
  ctx->routes_seen = gen;

  if( FD_LIKELY( ctx->routes_shared ) ) fd_an_routes_shared_publish( ctx->routes_shared, fd_an_hb_routes( ctx->hb ) );
}


static void
heartbeat( fd_an_tile_t * ctx,
           long           now,
           int *          charge_busy ) {
  if( FD_UNLIKELY( !ctx->hb_started ) ) {
    fd_an_endpoints_t const * eps = fd_an_client_endpoints( ctx->client );
    if( FD_LIKELY( eps->selected_group<0L ) ) return;
    fd_an_hb_start( ctx->hb, eps, fd_an_client_ep_ip4( ctx->client ), ctx->shred_version, now );
    ctx->hb_started = 1;
  }

  ulong interval_micros = fd_ulong_max( HEARTBEAT_INTERVAL(), AN_HB_INTERVAL_MIN_MICROS );
  int st = fd_an_hb_poll( ctx->hb, now, (long)fd_ulong_min( interval_micros, (ulong)LONG_MAX/1000UL )*1000L, charge_busy );
  routes_publish( ctx );
  if( FD_LIKELY( st!=FD_AN_HB_STATE_READY ) ) return;
  *charge_busy = 1;

  ulong slot = ctx->replay_metrics ? ctx->replay_metrics[ MIDX( GAUGE, REPLAY, RESET_SLOT ) ] : 0UL;
  if( FD_UNLIKELY( !slot ) ) {
    fd_an_hb_send( ctx->hb, NULL, 0UL, 0UL, now );
    return;
  }

  uchar msg[ FD_AN_HB_MSG_SZ ];
  fd_an_hb_msg( msg, ctx->identity, slot );
  uchar sig[ 64 ];
  fd_keyguard_client_sign( ctx->keyguard, sig, msg, sizeof(msg), FD_KEYGUARD_SIGN_TYPE_ED25519 );

  if( FD_UNLIKELY( fd_ed25519_verify( msg, sizeof(msg), sig, ctx->identity, ctx->sha )!=FD_ED25519_SUCCESS ) ) {
    if( FD_LIKELY( ++ctx->hb_defer_cnt<=AN_HB_DEFER_MAX ) ) {
      fd_an_hb_defer( ctx->hb, now, AN_HB_DEFER_NANOS );
    } else {
      ctx->hb_defer_cnt = 0UL;
      fd_an_hb_skip( ctx->hb, now );
    }
    return;
  }
  ctx->hb_defer_cnt = 0UL;

  uchar req[ FD_AN_PROTO_HEARTBEAT_REQ_BUF_SZ ];
  ulong req_sz = fd_an_proto_encode_heartbeat_req( req, sizeof(req), ctx->identity, slot, sig );
  if( FD_UNLIKELY( !req_sz ) ) { fd_an_hb_skip( ctx->hb, now ); return; }
  fd_an_hb_send( ctx->hb, req, req_sz, slot, now );
}

static void
before_credit( fd_an_tile_t *      ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  if( FD_UNLIKELY( ctx->disabled ) ) {
    flags_publish( ctx );
    fd_syscall_poll( NULL, 0U, AN_IDLE_MILLIS );
    return;
  }

  long now = fd_log_wallclock();

  fd_an_client_poll( ctx->client, now, charge_busy );
  consts_publish( ctx );
  flags_publish( ctx );


  if( FD_UNLIKELY( ctx->bootstrap && !ctx->boot_over && snapct_gone( ctx, now ) ) ) {
    ctx->boot_over = 1;
    fd_an_client_boot_over( ctx->client );
  }

  heartbeat( ctx, now, charge_busy );

  if( FD_LIKELY( !*charge_busy ) ) {
    int active = fd_an_client_busy( ctx->client ) || fd_an_hb_active( ctx->hb );
    fd_syscall_poll( NULL, 0U, active ? 1 : AN_IDLE_MILLIS );
  }
}

static void
after_frag( fd_an_tile_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sz; (void)tsorig; (void)tspub; (void)stem;

  if( FD_UNLIKELY( ctx->disabled || !sig || sig>USHORT_MAX ) ) return;
  if( FD_LIKELY( ctx->shred_version ) ) return;

  ctx->shred_version = (ushort)sig;
  fd_an_client_set_shred_version( ctx->client, ctx->shred_version );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_an_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  populate_sock_filter_policy_fd_an_tile( out_cnt, out,
                                          (uint)fd_log_private_logfile_fd(),
                                          (uint)ctx->netdb_fds->etc_hosts,
                                          (uint)ctx->netdb_fds->etc_resolv_conf,
                                          (uint)ctx->adns_epoll_fd );
  return sock_filter_policy_fd_an_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_an_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( out_fds_cnt<5UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2;
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  if( FD_LIKELY( ctx->netdb_fds->etc_hosts>=0 ) )    out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_hosts;
  out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_resolv_conf;
  out_fds[ out_cnt++ ] = ctx->adns_epoll_fd;
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)10e6)

#define STEM_NEVER_PARK 1

#define STEM_CALLBACK_CONTEXT_TYPE  fd_an_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_an_tile_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_anclnt = {
  .name                     = NAME,
  .rlimit_file_cnt          = 64UL,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .keep_host_networking     = 1,
  .allow_connect            = 1,
};
