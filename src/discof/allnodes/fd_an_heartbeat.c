#include "fd_an_heartbeat.h"
#include "fd_an_client.h"

#include "../../waltz/grpc/fd_grpc_client.h"
#include "../../waltz/resolv/fd_netdb.h"
#include "../../util/net/fd_ip4.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

static char const PATH_SERVICE_INFO[] = "/allnodes.v5.AllnodesService/GetServiceInfo";
static char const PATH_HEARTBEAT[]    = "/allnodes.v5.AllnodesService/Heartbeat";

struct fd_an_hb_private {
  int    state;
  ushort shred_version;

  long wait_from;
  long wait_nanos;
  int  deferred;

  fd_an_hb_cfg_t cfg;
  char  version[ FD_GRPC_CLIENT_VERSION_LEN_MAX+1UL ];
  ulong version_len;

  fd_an_ssl_ctx_t * ssl_ctx;
  fd_an_conn_t *    conn;

  fd_an_endpoints_t eps[ 1 ];
  uint              ep_ip4[ FD_AN_ENDPOINT_MAX ];

  ulong cursor;

  long  ep;
  long  started;
  int   sent;
  int   ended;
  int   ok;
  int   got_msg;
  uint  probe_shred_version;
  ulong probe_capabilities;

  uchar req[ FD_AN_PROTO_HEARTBEAT_REQ_BUF_SZ ];
  ulong req_sz;
  ulong attempts_left;
  long  pause_until;

  fd_an_hb_metrics_t metrics[ 1 ];
};


static void
cb_conn_established( void * ctx ) {
  (void)ctx;
}

static void
cb_conn_dead( void * ctx,
              uint   h2_err,
              int    closed_by ) {
  fd_an_hb_t * hb = ctx;
  fd_an_conn_kill( hb->conn, closed_by ? FD_AN_CONN_ERR_PEER : FD_AN_CONN_ERR_PROTO );
  FD_LOG_DEBUG(( "allnodes: heartbeat connection closed (h2 error %u, by %s)", h2_err, closed_by ? "peer" : "us" ));
}

static void
cb_tx_complete( void * ctx,
                ulong  request_ctx ) {
  (void)ctx; (void)request_ctx;
}

static void
cb_rx_start( void * ctx,
             ulong  request_ctx ) {
  (void)ctx; (void)request_ctx;
}

static void
cb_rx_msg( void *       ctx,
           void const * protobuf,
           ulong        protobuf_sz,
           ulong        request_ctx ) {
  (void)request_ctx;
  fd_an_hb_t * hb = ctx;
  if( hb->state!=FD_AN_HB_STATE_PROBE ) return;

  fd_an_service_info_t info[ 1 ];
  if( FD_UNLIKELY( fd_an_proto_decode_service_info( info, protobuf, protobuf_sz )!=FD_AN_PROTO_OK ) ) return;
  hb->got_msg             = 1;
  hb->probe_shred_version = info->shred_version;
  hb->probe_capabilities  = info->capabilities;
}

static void
cb_rx_end( void *                ctx,
           ulong                 request_ctx,
           fd_grpc_resp_hdrs_t * resp ) {
  (void)request_ctx;
  fd_an_hb_t * hb = ctx;
  if( FD_UNLIKELY( !hb->sent ) ) return;
  hb->sent  = 0;
  hb->ended = 1;
  hb->ok    = resp->h2_status==200 && resp->grpc_status==FD_GRPC_STATUS_OK;
  if( FD_UNLIKELY( !hb->ok && hb->state==FD_AN_HB_STATE_CALL ) ) {
    FD_LOG_DEBUG(( "Allnodes server call failed: h2 %u, grpc %u, %lu attempts left",
                   resp->h2_status, resp->grpc_status, hb->attempts_left ));
  }
}

static void
cb_rx_timeout( void * ctx,
               ulong  request_ctx,
               int    deadline_kind ) {
  (void)request_ctx; (void)deadline_kind;
  fd_an_hb_t * hb = ctx;
  if( FD_UNLIKELY( !hb->sent ) ) return;
  hb->sent  = 0;
  hb->ended = 1;
  hb->ok    = 0;
}

static void
cb_ping_ack( void * ctx ) {
  (void)ctx;
}

static fd_grpc_client_callbacks_t const AN_HB_CALLBACKS = {
  .conn_established = cb_conn_established,
  .conn_dead        = cb_conn_dead,
  .tx_complete      = cb_tx_complete,
  .rx_start         = cb_rx_start,
  .rx_msg           = cb_rx_msg,
  .rx_end           = cb_rx_end,
  .rx_timeout       = cb_rx_timeout,
  .ping_ack         = cb_ping_ack
};


ulong
fd_an_hb_align( void ) {
  return fd_ulong_max( 128UL, fd_an_conn_align() );
}

ulong
fd_an_hb_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_an_hb_align(),   sizeof(fd_an_hb_t)                              );
  l = FD_LAYOUT_APPEND( l, fd_an_conn_align(), fd_an_conn_footprint( FD_AN_CLIENT_QUERY_BUF_MAX ) );
  return FD_LAYOUT_FINI( l, fd_an_hb_align() );
}

fd_an_hb_t *
fd_an_hb_new( void *                 mem,
              fd_an_hb_cfg_t const * cfg,
              fd_an_ssl_ctx_t *      ssl_ctx,
              ulong                  rng_seed ) {
  if( FD_UNLIKELY( !mem || !cfg || !ssl_ctx ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_an_hb_align() ) ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_an_hb_t * hb       = FD_SCRATCH_ALLOC_APPEND( l, fd_an_hb_align(),   sizeof(fd_an_hb_t)                              );
  void *       conn_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_an_conn_align(), fd_an_conn_footprint( FD_AN_CLIENT_QUERY_BUF_MAX ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_an_hb_align() );

  memset( hb, 0, sizeof(fd_an_hb_t) );
  hb->cfg     = *cfg;
  hb->ssl_ctx = ssl_ctx;
  hb->state   = FD_AN_HB_STATE_OFF;
  hb->ep      = -1L;

  hb->version_len = fd_ulong_min( cfg->version_len, FD_GRPC_CLIENT_VERSION_LEN_MAX );
  if( FD_LIKELY( cfg->version && hb->version_len ) ) memcpy( hb->version, cfg->version, hb->version_len );
  hb->version[ hb->version_len ] = '\0';

  hb->conn = fd_an_conn_new( conn_mem, FD_AN_CLIENT_QUERY_BUF_MAX, &AN_HB_CALLBACKS, hb, rng_seed );
  if( FD_UNLIKELY( !hb->conn ) ) return NULL;

  return hb;
}

static void
wait_begin( fd_an_hb_t * hb,
            long         now ) {
  hb->state     = FD_AN_HB_STATE_WAIT;
  hb->wait_from = now;
  hb->deferred  = 0;
}

void
fd_an_hb_start( fd_an_hb_t *              hb,
                fd_an_endpoints_t const * eps,
                uint const *              ep_ip4,
                ushort                    shred_version,
                long                      now ) {
  if( FD_UNLIKELY( hb->state!=FD_AN_HB_STATE_OFF || eps->selected_group<0L ) ) return;
  *hb->eps = *eps;
  memcpy( hb->ep_ip4, ep_ip4, sizeof(hb->ep_ip4) );
  hb->shred_version = shred_version;
  wait_begin( hb, now );
}


static int
callable( fd_an_hb_t const * hb,
          ulong              i ) {
  fd_an_endpoint_t const * ep = &hb->eps->ep[ i ];
  return ep->group==(ulong)hb->eps->selected_group && !( ep->probed && !ep->valid );
}


static void
conn_start( fd_an_hb_t * hb,
            long         now ) {
  hb->started = now;
  hb->sent    = 0;
  hb->ended   = 0;
  hb->ok      = 0;
  hb->got_msg = 0;

  fd_an_endpoint_t const * ep = &hb->eps->ep[ hb->ep ];
  fd_an_conn_start( hb->conn, hb->ep_ip4[ hb->ep ], ep->port, ep->host,
                    ep->tls ? FD_AN_CONN_TLS : FD_AN_CONN_CLEARTEXT,
                    hb->ssl_ctx, hb->version, hb->version_len,
                    now, now + hb->cfg.request_timeout_nanos );
}


static int
conn_advance( fd_an_hb_t *  hb,
              char const *  path,
              ulong         path_sz,
              uchar const * req,
              ulong         req_sz,
              long          now,
              int *         charge_busy ) {
  if( FD_UNLIKELY( now<hb->started ) ) fd_an_conn_kill( hb->conn, FD_AN_CONN_ERR_TIMEOUT );

  int st = fd_an_conn_poll( hb->conn, now, charge_busy );

  if( FD_UNLIKELY( hb->ended ) ) {
    fd_an_conn_close( hb->conn );
    *charge_busy = 1;
    return 1;
  }

  if( st==FD_AN_CONN_STATE_READY && !hb->sent ) {
    fd_grpc_client_t * grpc = fd_an_conn_grpc( hb->conn );
    if( fd_grpc_client_request_is_blocked( grpc ) ) return 0;
    fd_grpc_h2_stream_t * stream = fd_grpc_client_request_start1( grpc, path, path_sz, 0UL, req, req_sz, NULL, 0UL, 0 );
    if( FD_UNLIKELY( !stream ) ) return 0;
    fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_RX_END, now + hb->cfg.request_timeout_nanos );
    hb->sent = 1;
    *charge_busy = 1;
    return 0;
  }

  if( FD_UNLIKELY( st==FD_AN_CONN_STATE_DEAD ) ) {
    FD_LOG_DEBUG(( "allnodes: %s to %s failed: %s", path, hb->eps->ep[ hb->ep ].uri,
                   fd_an_conn_strreason( fd_an_conn_reason( hb->conn ) ) ));
    hb->ok = 0;
    fd_an_conn_close( hb->conn );
    *charge_busy = 1;
    return 1;
  }
  return 0;
}



static void
advance_resolve( fd_an_hb_t * hb,
                 int *        charge_busy ) {
  for( ; hb->cursor<hb->eps->cnt; hb->cursor++ ) {
    ulong                    i  = hb->cursor;
    fd_an_endpoint_t const * ep = &hb->eps->ep[ i ];
    if( !callable( hb, i ) ) continue;

    uint literal;
    if( FD_UNLIKELY( fd_cstr_to_ip4_addr( ep->host, &literal ) ) ) continue;

    int dup = 0;
    for( ulong j=0UL; j<i; j++ ) {
      if( callable( hb, j ) && !strcmp( hb->eps->ep[ j ].host, ep->host ) ) { dup = 1; break; }
    }
    if( FD_UNLIKELY( dup ) ) continue;

    hb->cursor++;
    *charge_busy = 1;

    fd_addrinfo_t   hints   = { .ai_family = AF_INET };
    fd_addrinfo_t * res     = NULL;
    uchar           scratch[ 4096 ];
    void *          pscratch = scratch;
    int err = fd_getaddrinfo( ep->host, &hints, &res, &pscratch, sizeof(scratch) );
    if( FD_UNLIKELY( err || !res || !res->ai_addr ) ) {
      FD_LOG_DEBUG(( "allnodes: could not refresh %s (%s), keeping its address", ep->host, fd_gai_strerror( err ) ));
      return;
    }
    uint addr = ((struct sockaddr_in const *)res->ai_addr)->sin_addr.s_addr;
    for( ulong k=0UL; k<hb->eps->cnt; k++ ) {
      if( !strcmp( hb->eps->ep[ k ].host, ep->host ) ) hb->ep_ip4[ k ] = addr;
    }
    return;
  }

  hb->cursor = 0UL;
  hb->state  = FD_AN_HB_STATE_PROBE;
  hb->ep     = -1L;
}



static void
advance_probe( fd_an_hb_t * hb,
               long         now,
               int *        charge_busy ) {
  if( FD_UNLIKELY( hb->ep>=0L ) ) {
    static uchar const empty[ 1 ] = { 0 };
    if( !conn_advance( hb, PATH_SERVICE_INFO, sizeof(PATH_SERVICE_INFO)-1UL, empty, 0UL, now, charge_busy ) ) return;

    int   valid   = hb->ok && hb->got_msg && hb->probe_shred_version==(uint)hb->shred_version;
    ulong latency = (ulong)( fd_long_max( now - hb->started, 0L ) / 1000L );
    fd_an_endpoints_probe_result( hb->eps, (ulong)hb->ep, valid, valid ? latency : ULONG_MAX, valid ? hb->probe_capabilities : 0UL );
    FD_LOG_DEBUG(( "allnodes: late probe %s %s", hb->eps->ep[ hb->ep ].uri, valid ? "ok" : "rejected" ));
    hb->ep = -1L;
    return;
  }

  for( ; hb->cursor<hb->eps->cnt; hb->cursor++ ) {
    ulong i = hb->cursor;
    if( !callable( hb, i ) || hb->eps->ep[ i ].probed ) continue;
    if( FD_UNLIKELY( !hb->ep_ip4[ i ] ) ) {
      fd_an_endpoints_probe_result( hb->eps, i, 0, ULONG_MAX, 0UL );
      continue;
    }
    hb->cursor++;
    hb->ep = (long)i;
    conn_start( hb, now );
    *charge_busy = 1;
    return;
  }

  hb->cursor = 0UL;
  hb->state  = FD_AN_HB_STATE_READY;
}


static void
call_done( fd_an_hb_t * hb,
           long         now ) {
  hb->ep          = -1L;
  hb->pause_until = 0L;
  wait_begin( hb, now );
}

static void
attempt_start( fd_an_hb_t * hb,
               long         now ) {
  hb->attempts_left--;
  hb->metrics->calls++;
  conn_start( hb, now );
}


static void
attempt_failed( fd_an_hb_t * hb,
                long         now ) {
  if( FD_UNLIKELY( !hb->attempts_left ) ) {
    long next = fd_an_endpoints_next( hb->eps, hb->ep, FD_AN_CAP_HEARTBEAT );
    if( FD_UNLIKELY( next<0L ) ) {
      FD_LOG_DEBUG(( "Failed to send heartbeat to Allnodes service: all endpoints returned errors" ));
      hb->metrics->fail++;
      call_done( hb, now );
      return;
    }
    FD_LOG_DEBUG(( "Failed to call Allnodes server %s", hb->eps->ep[ hb->ep ].uri ));
    hb->ep            = next;
    hb->attempts_left = hb->cfg.other_attempts;
  }
  hb->pause_until = now + hb->cfg.attempt_pause_nanos;
}

static void
advance_call( fd_an_hb_t * hb,
              long         now,
              int *        charge_busy ) {
  if( FD_UNLIKELY( hb->pause_until ) ) {
    if( now<hb->pause_until && hb->pause_until-now<=hb->cfg.attempt_pause_nanos ) return;
    hb->pause_until = 0L;
    attempt_start( hb, now );
    *charge_busy = 1;
    return;
  }

  if( !conn_advance( hb, PATH_HEARTBEAT, sizeof(PATH_HEARTBEAT)-1UL, hb->req, hb->req_sz, now, charge_busy ) ) return;

  if( FD_LIKELY( hb->ok ) ) {
    hb->metrics->ok++;
    call_done( hb, now );
  } else {
    attempt_failed( hb, now );
  }
}


int
fd_an_hb_poll( fd_an_hb_t * hb,
               long         now,
               long         interval_nanos,
               int *        charge_busy ) {

  switch( hb->state ) {

  case FD_AN_HB_STATE_WAIT: {
    if( FD_UNLIKELY( now<hb->wait_from ) ) hb->wait_from = now;
    long wait = hb->deferred ? hb->wait_nanos : interval_nanos;
    if( FD_UNLIKELY( now-hb->wait_from>=wait ) ) {
      hb->cursor = 0UL;
      hb->state  = FD_AN_HB_STATE_RESOLVE;
      *charge_busy = 1;
    }
    break;
  }

  case FD_AN_HB_STATE_RESOLVE:
    advance_resolve( hb, charge_busy );
    break;

  case FD_AN_HB_STATE_PROBE:
    advance_probe( hb, now, charge_busy );
    break;

  case FD_AN_HB_STATE_CALL:
    advance_call( hb, now, charge_busy );
    break;

  default:
    break;
  }

  return hb->state;
}

void
fd_an_hb_send( fd_an_hb_t *  hb,
               uchar const * req,
               ulong         req_sz,
               ulong         slot,
               long          now ) {
  if( FD_UNLIKELY( hb->state!=FD_AN_HB_STATE_READY ) ) return;
  if( FD_UNLIKELY( req_sz>sizeof(hb->req) ) ) { fd_an_hb_skip( hb, now ); return; }

  long ep = fd_an_endpoints_next( hb->eps, -1L, FD_AN_CAP_HEARTBEAT );
  if( FD_UNLIKELY( ep<0L ) ) {
    fd_an_hb_skip( hb, now );
    return;
  }

  if( FD_LIKELY( req_sz ) ) memcpy( hb->req, req, req_sz );
  hb->req_sz        = req_sz;
  hb->ep            = ep;
  hb->attempts_left = hb->cfg.first_attempts;
  hb->pause_until   = 0L;
  hb->metrics->slot = slot;
  hb->state         = FD_AN_HB_STATE_CALL;
  attempt_start( hb, now );
}

void
fd_an_hb_defer( fd_an_hb_t * hb,
                long         now,
                long         delay_nanos ) {
  if( FD_UNLIKELY( hb->state!=FD_AN_HB_STATE_READY ) ) return;
  wait_begin( hb, now );
  hb->deferred   = 1;
  hb->wait_nanos = delay_nanos;
}

void
fd_an_hb_skip( fd_an_hb_t * hb,
               long         now ) {
  if( FD_UNLIKELY( hb->state!=FD_AN_HB_STATE_READY ) ) return;
  hb->metrics->skip++;
  call_done( hb, now );
}

int
fd_an_hb_active( fd_an_hb_t const * hb ) {
  return hb->state==FD_AN_HB_STATE_RESOLVE || hb->state==FD_AN_HB_STATE_PROBE || hb->state==FD_AN_HB_STATE_CALL;
}

fd_an_hb_metrics_t const *
fd_an_hb_metrics( fd_an_hb_t const * hb ) {
  return hb->metrics;
}
