#include "fd_an_client.h"

#include "../../waltz/grpc/fd_grpc_client.h"
#include "../../util/net/fd_ip4.h"

#include <string.h>

static char const PATH_SERVICE_INFO[] = "/allnodes.v5.AllnodesService/GetServiceInfo";
static char const PATH_BOOTSTRAP[]    = "/allnodes.v5.AllnodesService/GetBootstrapInfo";


#define AN_SLOT_QUERY (FD_AN_ENDPOINT_MAX)

struct fd_an_slot {
  fd_an_client_t * client;
  ulong            idx;
};

typedef struct fd_an_slot fd_an_slot_t;

struct fd_an_probe {
  int   started;
  int   sent;
  int   done;
  int   got_msg;
  uint  shred_version;
  ulong capabilities;
};

typedef struct fd_an_probe fd_an_probe_t;

struct fd_an_client_private {
  int  state;
  int  fallback;
  long now;
  long t0;
  long phase_deadline;
  long pause_until;

  ushort shred_version;
  int    boot_wanted;

  fd_an_client_cfg_t cfg;
  char  version[ FD_GRPC_CLIENT_VERSION_LEN_MAX+1UL ];
  ulong version_len;

  fd_an_ssl_ctx_t * ssl_ctx;
  fd_adns_t *       adns;
  fd_an_shared_t *  shared;

  fd_an_endpoints_t eps[ 1 ];
  uint              ep_ip4[ FD_AN_ENDPOINT_MAX ];
  fd_an_probe_t     probe[ FD_AN_ENDPOINT_MAX ];
  fd_an_slot_t      slot[ FD_AN_ENDPOINT_MAX+1UL ];
  fd_an_conn_t *    conn[ FD_AN_ENDPOINT_MAX ];
  fd_an_conn_t *    qconn;

  int   dns_started;

  long  query_ep;
  long  last_query_ep;
  int   query_sent;
  int   query_ended;
  int   query_final;
  int   query_got_msg;
  int   query_result;
  ulong attempts_used;
  uchar query_req[ 64 ];
  ulong query_req_sz;

  fd_an_snapshot_node_t cand;
  fd_an_snapshot_node_t node;
  int                   node_valid;

  fd_an_client_metrics_t metrics[ 1 ];
};


static fd_an_conn_t *
slot_conn( fd_an_client_t * client,
           ulong            idx ) {
  return idx==AN_SLOT_QUERY ? client->qconn : client->conn[ idx ];
}


static void
publish( fd_an_client_t * client ) {
  fd_an_shared_t * sh = client->shared;

  fd_an_shared_publish_begin( sh );
  sh->state    = client->state;
  sh->fallback = client->fallback;
  if( FD_LIKELY( client->node_valid ) ) {
    sh->node     = client->node;
    sh->has_node = 1;
  }
  if( FD_LIKELY( client->eps->selected_group>=0L ) ) {
    ulong g = (ulong)client->eps->selected_group;
    ulong valid = 0UL;
    ulong best  = ULONG_MAX;
    ushort port = 0;
    for( ulong i=0UL; i<client->eps->cnt; i++ ) {
      fd_an_endpoint_t const * ep = &client->eps->ep[ i ];
      if( ep->group!=g || !ep->valid ) continue;
      valid++;
      if( ep->latency_micros<best ) { best = ep->latency_micros; port = ep->port; }
    }
    sh->endpoints_valid      = valid;
    sh->probe_latency_micros = best==ULONG_MAX ? 0UL : best;
    sh->selected_port        = port;
  }
  fd_an_shared_publish_end( sh );
}


static void
terminal( fd_an_client_t * client,
          int              state,
          int              fallback ) {
  client->state    = state;
  client->fallback = fallback;

  for( ulong i=0UL; i<FD_AN_ENDPOINT_MAX; i++ ) {
    if( FD_UNLIKELY( client->conn[ i ] ) ) fd_an_conn_close( client->conn[ i ] );
  }
  if( FD_LIKELY( client->qconn ) ) fd_an_conn_close( client->qconn );

  publish( client );
}


static void
cb_conn_established( void * ctx ) {
  (void)ctx;
}

static void
cb_conn_dead( void * ctx,
              uint   h2_err,
              int    closed_by ) {
  fd_an_slot_t *   slot   = ctx;
  fd_an_client_t * client = slot->client;
  fd_an_conn_t *   conn   = slot_conn( client, slot->idx );
  if( FD_UNLIKELY( !conn ) ) return;
  fd_an_conn_kill( conn, closed_by ? FD_AN_CONN_ERR_PEER : FD_AN_CONN_ERR_PROTO );
  FD_LOG_DEBUG(( "allnodes: connection closed (h2 error %u, by %s)", h2_err, closed_by ? "peer" : "us" ));
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
  fd_an_slot_t *   slot   = ctx;
  fd_an_client_t * client = slot->client;

  if( slot->idx!=AN_SLOT_QUERY ) {
    fd_an_service_info_t info[ 1 ];
    if( FD_UNLIKELY( fd_an_proto_decode_service_info( info, protobuf, protobuf_sz )!=FD_AN_PROTO_OK ) ) {
      FD_LOG_DEBUG(( "allnodes: mirror %s sent an undecodable service info", client->eps->ep[ slot->idx ].uri ));
      return;
    }
    fd_an_probe_t * p = &client->probe[ slot->idx ];
    p->got_msg      = 1;
    p->shred_version = info->shred_version;
    p->capabilities  = info->capabilities;
    return;
  }

  client->query_got_msg = 1;
  client->query_result  = fd_an_proto_decode_bootstrap( &client->cand, protobuf, protobuf_sz );
  if( FD_LIKELY( client->query_result==FD_AN_PROTO_OK ) ) return;

  if(      client->query_result==FD_AN_PROTO_ERR_NO_NODE ) client->metrics->no_node++;
  else if( client->query_result==FD_AN_PROTO_ERR_DECODE  ) client->metrics->rpc_decode_fail++;
  FD_LOG_DEBUG(( "allnodes: %s answered without a usable node (%s)",
                client->query_ep>=0L ? client->eps->ep[ client->query_ep ].uri : "service",
                fd_an_proto_strerror( client->query_result ) ));
}

static void
cb_rx_end( void *                ctx,
           ulong                 request_ctx,
           fd_grpc_resp_hdrs_t * resp ) {
  (void)request_ctx;
  fd_an_slot_t *   slot   = ctx;
  fd_an_client_t * client = slot->client;

  int ok = resp->h2_status==200 && resp->grpc_status==FD_GRPC_STATUS_OK;

  if( slot->idx!=AN_SLOT_QUERY ) {
    fd_an_probe_t *    p  = &client->probe[ slot->idx ];
    fd_an_endpoint_t * ep = &client->eps->ep[ slot->idx ];
    if( FD_UNLIKELY( p->done ) ) return;
    p->done = 1;

    int valid = ok && p->got_msg && p->shred_version==(uint)client->shred_version;
    ulong latency = (ulong)( fd_long_max( client->now - client->t0, 0L ) / 1000L );
    fd_an_endpoints_probe_result( client->eps, slot->idx, valid, latency, p->capabilities );
    if( valid ) client->metrics->probe_ok++;
    else        client->metrics->probe_fail++;
    if( FD_UNLIKELY( valid && !fd_an_cap_supported( p->capabilities, FD_AN_CAP_GET_BOOTSTRAP_INFO ) ) ) {
      client->metrics->capability_skip++;
    }
    FD_LOG_DEBUG(( "allnodes: probe %s %s (h2 %u, grpc %u, shred version %u, %lu us)",
                  ep->uri, valid ? "ok" : "rejected", resp->h2_status, resp->grpc_status,
                  p->shred_version, latency ));
    return;
  }

  if( FD_UNLIKELY( !client->query_sent ) ) return;
  client->query_sent  = 0;
  client->query_ended = 1;

  if( FD_LIKELY( ok && client->query_got_msg && client->query_result==FD_AN_PROTO_OK ) ) {
    client->node       = client->cand;
    client->node_valid = 1;
    client->metrics->nodes_received++;
    return;
  }

  if( FD_UNLIKELY( ok && client->query_got_msg &&
                   ( client->query_result==FD_AN_PROTO_ERR_NO_NODE || client->query_result==FD_AN_PROTO_ERR_IPV6 ) ) ) {
    client->query_final = 1;
  }

  if( FD_UNLIKELY( ok && !client->query_got_msg ) ) {
    client->query_result = FD_AN_PROTO_ERR_DECODE;
    client->metrics->rpc_decode_fail++;
  }

  if( FD_UNLIKELY( !ok ) ) {
    if( resp->h2_status!=200 ) client->metrics->rpc_transport_fail++;
    else                       client->metrics->rpc_status_fail++;
    FD_LOG_DEBUG(( "allnodes: GetBootstrapInfo failed (h2 %u, grpc %u)", resp->h2_status, resp->grpc_status ));
  }
}

static void
cb_rx_timeout( void * ctx,
               ulong  request_ctx,
               int    deadline_kind ) {
  (void)request_ctx; (void)deadline_kind;
  fd_an_slot_t *   slot   = ctx;
  fd_an_client_t * client = slot->client;

  if( slot->idx!=AN_SLOT_QUERY ) {
    fd_an_probe_t * p = &client->probe[ slot->idx ];
    if( FD_UNLIKELY( p->done ) ) return;
    p->done = 1;
    fd_an_endpoints_probe_result( client->eps, slot->idx, 0, ULONG_MAX, 0UL );
    client->metrics->probe_fail++;
    return;
  }

  if( FD_LIKELY( client->query_sent ) ) {
    client->query_sent  = 0;
    client->query_ended = 1;
    client->metrics->rpc_timeout++;
  }
}

static void
cb_ping_ack( void * ctx ) {
  (void)ctx;
}

static fd_grpc_client_callbacks_t const AN_CALLBACKS = {
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
fd_an_client_align( void ) {
  return fd_ulong_max( 128UL, fd_an_conn_align() );
}

ulong
fd_an_client_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_an_client_align(), sizeof(fd_an_client_t) );
  for( ulong i=0UL; i<FD_AN_ENDPOINT_MAX; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_an_conn_align(), fd_an_conn_footprint( FD_AN_CLIENT_PROBE_BUF_MAX ) );
  }
  l = FD_LAYOUT_APPEND( l, fd_an_conn_align(), fd_an_conn_footprint( FD_AN_CLIENT_QUERY_BUF_MAX ) );
  return FD_LAYOUT_FINI( l, fd_an_client_align() );
}

fd_an_client_t *
fd_an_client_new( void *                     mem,
                  fd_an_client_cfg_t const * cfg,
                  fd_an_ssl_ctx_t *          ssl_ctx,
                  fd_adns_t *                adns,
                  fd_an_shared_t *           shared,
                  ulong                      rng_seed ) {

  if( FD_UNLIKELY( !mem || !cfg || !ssl_ctx || !adns || !shared ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_an_client_align() ) ) ) {
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_an_client_t * client = FD_SCRATCH_ALLOC_APPEND( l, fd_an_client_align(), sizeof(fd_an_client_t) );
  memset( client, 0, sizeof(fd_an_client_t) );

  client->cfg     = *cfg;
  client->ssl_ctx = ssl_ctx;
  client->adns    = adns;
  client->shared  = shared;
  client->state   = FD_AN_STATE_INIT;
  client->query_ep      = -1L;
  client->last_query_ep = -1L;
  client->shred_version = cfg->shred_version;
  client->boot_wanted   = !!cfg->bootstrap;

  client->version_len = fd_ulong_min( cfg->version_len, FD_GRPC_CLIENT_VERSION_LEN_MAX );
  if( FD_LIKELY( cfg->version && client->version_len ) ) {
    memcpy( client->version, cfg->version, client->version_len );
  }
  client->version[ client->version_len ] = '\0';

  if( FD_UNLIKELY( !fd_an_endpoints_init( client->eps, cfg->endpoints ) ) ) {
    return NULL;
  }

  for( ulong i=0UL; i<FD_AN_ENDPOINT_MAX; i++ ) {
    client->slot[ i ].client = client;
    client->slot[ i ].idx    = i;
    void * cmem = FD_SCRATCH_ALLOC_APPEND( l, fd_an_conn_align(), fd_an_conn_footprint( FD_AN_CLIENT_PROBE_BUF_MAX ) );
    client->conn[ i ] = fd_an_conn_new( cmem, FD_AN_CLIENT_PROBE_BUF_MAX, &AN_CALLBACKS, &client->slot[ i ], rng_seed+i );
    if( FD_UNLIKELY( !client->conn[ i ] ) ) return NULL;
  }

  client->slot[ AN_SLOT_QUERY ].client = client;
  client->slot[ AN_SLOT_QUERY ].idx    = AN_SLOT_QUERY;
  void * qmem = FD_SCRATCH_ALLOC_APPEND( l, fd_an_conn_align(), fd_an_conn_footprint( FD_AN_CLIENT_QUERY_BUF_MAX ) );
  client->qconn = fd_an_conn_new( qmem, FD_AN_CLIENT_QUERY_BUF_MAX, &AN_CALLBACKS, &client->slot[ AN_SLOT_QUERY ], rng_seed+AN_SLOT_QUERY );
  if( FD_UNLIKELY( !client->qconn ) ) return NULL;

  FD_SCRATCH_ALLOC_FINI( l, fd_an_client_align() );

  return client;
}

void
fd_an_client_set_shred_version( fd_an_client_t * client,
                                ushort           shred_version ) {
  if( FD_UNLIKELY( !shred_version || client->shred_version ) ) return;
  client->shred_version = shred_version;
}


static void
start_resolve( fd_an_client_t * client,
               long             now ) {
  client->t0             = now;
  client->phase_deadline = now + client->cfg.probe_budget_nanos;
  client->state          = FD_AN_STATE_RESOLVE;

  for( ulong i=0UL; i<client->eps->cnt; i++ ) {
    fd_an_endpoint_t * ep = &client->eps->ep[ i ];

    uint literal;
    if( FD_UNLIKELY( fd_cstr_to_ip4_addr( ep->host, &literal ) ) ) {
      client->ep_ip4[ i ] = literal;
      continue;
    }

    int dup = 0;
    for( ulong j=0UL; j<i; j++ ) {
      if( !strcmp( client->eps->ep[ j ].host, ep->host ) ) { dup = 1; break; }
    }
    if( FD_UNLIKELY( dup ) ) continue;

    if( FD_UNLIKELY( fd_adns_resolve( client->adns, ep->host, i ) ) ) {
    }
  }
  client->dns_started = 1;
}

static void
advance_dns( fd_an_client_t * client,
             long             now,
             int *            charge_busy ) {
  fd_adns_result_t res[ 1 ];
  while( fd_adns_advance( client->adns, now, res ) ) {
    *charge_busy = 1;
    if( FD_UNLIKELY( res->req_id>=client->eps->cnt ) ) continue;

    char const * host = client->eps->ep[ res->req_id ].host;
    if( FD_UNLIKELY( res->err || !res->addr_cnt ) ) {
      FD_LOG_DEBUG(( "allnodes: could not resolve %s (%d)", host, res->err ));
      for( ulong i=0UL; i<client->eps->cnt; i++ ) {
        if( !client->ep_ip4[ i ] && !strcmp( client->eps->ep[ i ].host, host ) ) {
          fd_an_endpoints_probe_result( client->eps, i, 0, ULONG_MAX, 0UL );
          client->metrics->probe_fail++;
        }
      }
      continue;
    }

    for( ulong i=0UL; i<client->eps->cnt; i++ ) {
      if( FD_LIKELY( !client->ep_ip4[ i ] ) && !strcmp( client->eps->ep[ i ].host, host ) ) {
        client->ep_ip4[ i ] = res->addrs[ 0 ];
      }
    }
  }
}

static void
advance_probes( fd_an_client_t * client,
                long             now,
                int *            charge_busy ) {

  for( ulong i=0UL; i<client->eps->cnt; i++ ) {
    fd_an_endpoint_t * ep = &client->eps->ep[ i ];
    fd_an_probe_t *    p  = &client->probe[ i ];
    fd_an_conn_t *     c  = client->conn[ i ];

    if( FD_UNLIKELY( p->done ) ) continue;

    if( FD_UNLIKELY( !p->started ) ) {
      if( !client->ep_ip4[ i ] ) continue;
      p->started = 1;
      *charge_busy = 1;
      fd_an_conn_start( c, client->ep_ip4[ i ], ep->port, ep->host,
                        ep->tls ? FD_AN_CONN_TLS : FD_AN_CONN_CLEARTEXT,
                        client->ssl_ctx, client->version, client->version_len,
                        now, client->phase_deadline );
      client->state = FD_AN_STATE_PROBE;
      continue;
    }

    int st = fd_an_conn_poll( c, now, charge_busy );

    if( FD_UNLIKELY( st==FD_AN_CONN_STATE_DEAD ) ) {
      if( FD_LIKELY( !p->done ) ) {
        p->done = 1;
        fd_an_endpoints_probe_result( client->eps, i, 0, ULONG_MAX, 0UL );
        client->metrics->probe_fail++;
        FD_LOG_DEBUG(( "allnodes: probe %s failed (%s)", ep->uri, fd_an_conn_strreason( fd_an_conn_reason( c ) ) ));
      }
      fd_an_conn_close( c );
      continue;
    }

    if( st==FD_AN_CONN_STATE_READY && !p->sent ) {
      fd_grpc_client_t * grpc = fd_an_conn_grpc( c );
      if( fd_grpc_client_request_is_blocked( grpc ) ) continue;
      static uchar const empty[ 1 ] = { 0 };
      fd_grpc_h2_stream_t * stream = fd_grpc_client_request_start1( grpc, PATH_SERVICE_INFO, sizeof(PATH_SERVICE_INFO)-1UL,
                                                                    i, empty, 0UL, NULL, 0UL, 0 );
      if( FD_UNLIKELY( !stream ) ) continue;
      fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_RX_END, client->phase_deadline );
      p->sent = 1;
      *charge_busy = 1;
    }
  }
}


static void
settle_probes( fd_an_client_t * client,
               long             now ) {

  ulong elapsed = (ulong)( fd_long_max( now - client->t0, 0L ) / 1000L );
  int decided = fd_an_endpoints_select( client->eps, elapsed );

  int expired = now>=client->phase_deadline;
  if( !decided && !expired && fd_an_endpoints_pending( client->eps ) ) return;

  if( FD_UNLIKELY( !decided ) ) {
    int any_probed = 0;
    for( ulong i=0UL; i<client->eps->cnt; i++ ) any_probed |= client->probe[ i ].got_msg;
    terminal( client, FD_AN_STATE_UNAVAILABLE,
              any_probed ? FD_AN_FALLBACK_NO_MATCH : FD_AN_FALLBACK_UNREACHABLE );
    return;
  }

  for( ulong i=0UL; i<client->eps->cnt; i++ ) {
    if( FD_UNLIKELY( !client->probe[ i ].started ) ) fd_an_endpoints_probe_result( client->eps, i, 0, ULONG_MAX, 0UL );
  }

  for( ulong i=0UL; i<client->eps->cnt; i++ ) fd_an_conn_close( client->conn[ i ] );

  if( FD_UNLIKELY( !client->boot_wanted ) ) {
    client->state = FD_AN_STATE_IDLE;
    publish( client );
    FD_LOG_DEBUG(( "allnodes: service group %lu selected (%lu us), no node needed",
                  (ulong)client->eps->selected_group, elapsed ));
    return;
  }

  client->query_ep      = -1L;
  client->last_query_ep = -1L;
  client->attempts_used = 0UL;
  client->pause_until   = 0L;
  client->state         = FD_AN_STATE_QUERY;

  FD_LOG_DEBUG(( "allnodes: service group %lu selected (%lu us)",
                (ulong)client->eps->selected_group, elapsed ));
}


static int
query_fallback( int proto_result ) {
  switch( proto_result ) {
  case FD_AN_PROTO_ERR_NO_NODE: return FD_AN_FALLBACK_NO_NODE;
  case FD_AN_PROTO_ERR_IPV6:    return FD_AN_FALLBACK_IPV6;
  case FD_AN_PROTO_ERR_DECODE:  return FD_AN_FALLBACK_DECODE;
  default:                      return FD_AN_FALLBACK_RPC_FAILED;
  }
}

static void
begin_attempt( fd_an_client_t * client,
               long             now ) {

  long next = fd_an_endpoints_next( client->eps, client->last_query_ep, FD_AN_CAP_GET_BOOTSTRAP_INFO );
  if( FD_UNLIKELY( next<0L ) ) next = fd_an_endpoints_next( client->eps, -1L, FD_AN_CAP_GET_BOOTSTRAP_INFO );
  if( FD_UNLIKELY( next<0L ) ) {
    terminal( client, FD_AN_STATE_UNAVAILABLE, FD_AN_FALLBACK_NO_CAPABILITY );
    return;
  }

  client->last_query_ep = next;
  client->query_ep      = next;
  client->query_sent    = 0;
  client->query_ended   = 0;
  client->query_final   = 0;
  client->query_got_msg = 0;
  client->attempts_used++;
  client->metrics->rpc_calls++;

  fd_an_endpoint_t * ep = &client->eps->ep[ next ];
  fd_an_conn_start( client->qconn, client->ep_ip4[ next ], ep->port, ep->host,
                    ep->tls ? FD_AN_CONN_TLS : FD_AN_CONN_CLEARTEXT,
                    client->ssl_ctx, client->version, client->version_len,
                    now, now + client->cfg.request_timeout_nanos );
}

static void
advance_query( fd_an_client_t * client,
               long             now,
               int *            charge_busy ) {

  if( FD_UNLIKELY( client->query_ep<0L ) ) {
    if( now<client->pause_until ) return;
    if( FD_UNLIKELY( client->attempts_used>=client->cfg.max_attempts ) ) {
      terminal( client, FD_AN_STATE_UNAVAILABLE, query_fallback( client->query_result ) );
      return;
    }
    begin_attempt( client, now );
    *charge_busy = 1;
    return;
  }

  int st = fd_an_conn_poll( client->qconn, now, charge_busy );

  if( FD_UNLIKELY( client->node_valid ) ) {
    fd_an_endpoint_t * ep = &client->eps->ep[ client->query_ep ];
    FD_LOG_DEBUG(( "allnodes: snapshot node " FD_IP4_ADDR_FMT ":%u full=%lu incr=%lu from %s",
                    FD_IP4_ADDR_FMT_ARGS( client->node.ip4 ), client->node.port,
                    client->node.full_slot,
                    client->node.has_incremental ? client->node.incr_slot : 0UL,
                    ep->uri ));
    client->state    = FD_AN_STATE_IDLE;
    client->query_ep = -1L;
    fd_an_conn_close( client->qconn );
    publish( client );
    return;
  }

  if( st==FD_AN_CONN_STATE_READY && !client->query_sent && !client->query_ended ) {
    fd_grpc_client_t * grpc = fd_an_conn_grpc( client->qconn );
    if( fd_grpc_client_request_is_blocked( grpc ) ) return;

    if( FD_UNLIKELY( !client->query_req_sz ) ) {
      client->query_req_sz = fd_an_proto_encode_bootstrap_req( client->query_req, sizeof(client->query_req),
                                                               (uint)client->shred_version );
      if( FD_UNLIKELY( !client->query_req_sz ) ) {
        terminal( client, FD_AN_STATE_UNAVAILABLE, FD_AN_FALLBACK_DECODE );
        return;
      }
    }

    fd_grpc_h2_stream_t * stream = fd_grpc_client_request_start1( grpc, PATH_BOOTSTRAP, sizeof(PATH_BOOTSTRAP)-1UL,
                                                                  AN_SLOT_QUERY, client->query_req, client->query_req_sz,
                                                                  NULL, 0UL, 0 );
    if( FD_UNLIKELY( !stream ) ) return;
    fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_RX_END, now + client->cfg.request_timeout_nanos );
    client->query_sent = 1;
    *charge_busy = 1;
    return;
  }

  if( FD_UNLIKELY( st==FD_AN_CONN_STATE_DEAD || client->query_ended ) ) {
    if( FD_UNLIKELY( st==FD_AN_CONN_STATE_DEAD && !client->query_ended ) ) {
      if( client->query_sent && fd_an_conn_reason( client->qconn )==FD_AN_CONN_ERR_TIMEOUT ) client->metrics->rpc_timeout++;
      else                                                                                   client->metrics->rpc_transport_fail++;
    }
    if( FD_UNLIKELY( client->query_final || client->attempts_used>=client->cfg.max_attempts ) ) {
      terminal( client, FD_AN_STATE_UNAVAILABLE, query_fallback( client->query_result ) );
      return;
    }
    fd_an_conn_close( client->qconn );
    client->query_ep    = -1L;
    client->pause_until = now + client->cfg.attempt_pause_nanos;
    *charge_busy = 1;
  }
}


int
fd_an_client_poll( fd_an_client_t * client,
                   long             now,
                   int *            charge_busy ) {

  client->now = now;

  switch( client->state ) {

  case FD_AN_STATE_INIT:
    if( FD_LIKELY( client->shred_version ) ) start_resolve( client, now );
    else {
      client->state          = FD_AN_STATE_WAIT_SV;
      client->phase_deadline = now + client->cfg.shred_version_timeout_nanos;
    }
    break;

  case FD_AN_STATE_WAIT_SV:
    if( FD_UNLIKELY( client->shred_version ) ) start_resolve( client, now );
    else if( FD_UNLIKELY( now>=client->phase_deadline ) ) {
      terminal( client, FD_AN_STATE_UNAVAILABLE, FD_AN_FALLBACK_NO_SHRED_VERSION );
    }
    break;

  case FD_AN_STATE_RESOLVE:
  case FD_AN_STATE_PROBE:
    advance_dns   ( client, now, charge_busy );
    advance_probes( client, now, charge_busy );
    settle_probes ( client, now );
    break;

  case FD_AN_STATE_QUERY:
    advance_query( client, now, charge_busy );
    break;

  default:
    break;
  }

  return client->state;
}

void
fd_an_client_boot_over( fd_an_client_t * client ) {
  client->boot_wanted = 0;
  if( FD_UNLIKELY( client->state==FD_AN_STATE_QUERY ) ) terminal( client, FD_AN_STATE_DISABLED, FD_AN_FALLBACK_DISABLED );
}

int
fd_an_client_state( fd_an_client_t const * client ) {
  return client->state;
}

int
fd_an_client_is_terminal( fd_an_client_t const * client ) {
  return client->state==FD_AN_STATE_UNAVAILABLE || client->state==FD_AN_STATE_DISABLED;
}

int
fd_an_client_busy( fd_an_client_t const * client ) {
  return client->state==FD_AN_STATE_RESOLVE || client->state==FD_AN_STATE_PROBE || client->state==FD_AN_STATE_QUERY;
}

fd_an_endpoints_t const *
fd_an_client_endpoints( fd_an_client_t const * client ) {
  return client->eps;
}

uint const *
fd_an_client_ep_ip4( fd_an_client_t const * client ) {
  return client->ep_ip4;
}

fd_an_client_metrics_t const *
fd_an_client_metrics( fd_an_client_t const * client ) {
  return client->metrics;
}
