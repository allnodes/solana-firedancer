
#include "fd_an_consts.h"
#include "fd_an_peers.h"
#include "fd_an_shared.h"

#define FD_AN_TXSEND_REFRESH_NANOS (100L*1000L*1000L)

#define FD_AN_TXSEND_WANTED_MAX (FD_AN_PEERS_SLOTS)

FD_AN_CONST_ULONG( UPCOMING_LEADER_FANOUT_SLOTS, 3UL );
#define FD_AN_TXSEND_WINDOW_MAX (4UL*FD_EPOCH_SLOTS_PER_ROTATION)

#define FD_AN_TXSEND_SENT_MAX (256UL)

FD_STATIC_ASSERT( FD_AN_PEERS_MAX<=sizeof(((fd_txsend_tile_t *)NULL)->conns)/sizeof(quic_entry_t), an_peers_max );

static fd_an_target_t const an_stock[] = {
  { .relative = 1, .port_type = FD_AN_PORT_TPU_VOTE, .secondary = 0 },
  { .relative = 1, .port_type = FD_AN_PORT_TPU,      .secondary = 0 },
  { .relative = 1, .port_type = FD_AN_PORT_TPU_VOTE, .secondary = 1 },
  { .relative = 1, .port_type = FD_AN_PORT_TPU,      .secondary = 1 }
};
#define AN_STOCK_CNT (sizeof(an_stock)/sizeof(an_stock[0]))

struct fd_an_dest {
  fd_an_sock_t sock;
  int          secondary;
};

typedef struct fd_an_dest fd_an_dest_t;

struct fd_an_txsend {
  int                           enabled;
  fd_an_routes_shared_t const * shared;

  ulong          live;
  ulong          seen;
  fd_an_routes_t routes[ 2 ];

  ulong        sent_cnt;
  fd_an_dest_t sent[ FD_AN_TXSEND_SENT_MAX ];

  fd_an_peers_t        peers [ 1 ];
  fd_an_peers_change_t change[ 1 ];
  fd_an_sock_t         wanted[ FD_AN_TXSEND_WANTED_MAX ];

  fd_pubkey_t identity;
  ulong voted_slot;
  long  refreshed;

};

typedef struct fd_an_txsend fd_an_txsend_t;

static fd_an_txsend_t fd_an_txsend[ 1 ];


static void
send_udp( fd_txsend_tile_t * ctx,
          uint               ip4,
          ushort             port,
          uchar const *      payload,
          ulong              payload_sz ) {
  fd_ip4_hdr_t * ip4_hdr = ctx->packet_hdr->ip4;
  fd_udp_hdr_t * udp_hdr = ctx->packet_hdr->udp;

  ip4_hdr->daddr       = ip4;
  ip4_hdr->net_tot_len = fd_ushort_bswap( (ushort)(payload_sz+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  ip4_hdr->net_id      = fd_ushort_bswap( ctx->net_id++ );
  ip4_hdr->check       = 0;
  ip4_hdr->check       = fd_ip4_hdr_check_fast( ip4_hdr );

  udp_hdr->net_dport = fd_ushort_bswap( port );
  udp_hdr->net_len   = fd_ushort_bswap( (ushort)( payload_sz+sizeof(fd_udp_hdr_t) ) );
  send_to_net( ctx, ip4_hdr, udp_hdr, payload, payload_sz, fd_clock_tile_now( ctx->clock ) );
}


static void
send_quic( fd_quic_conn_t * conn,
           uchar const *    payload,
           ulong            payload_sz ) {
  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  if( FD_UNLIKELY( !stream ) ) return;

  fd_quic_stream_send( stream, payload, payload_sz, 1 );
}


static int
an_resolve( peer_entry_t const *   peer,
            fd_an_target_t const * target,
            fd_an_sock_t *         sock ) {
  if( !target->relative ) {
    *sock = (fd_an_sock_t){ .ip4 = target->ip4, .port = target->port };
  } else {
    ulong idx;
    switch( target->port_type ) {
    case FD_AN_PORT_TPU_VOTE: idx = 0UL; break;
    case FD_AN_PORT_TPU:      idx = 1UL; break;
    default:                  return 0;
    }
    if( FD_UNLIKELY( !peer ) ) return 0;
    if( target->secondary ) *sock = (fd_an_sock_t){ .ip4 = peer->quic_conns[ idx ].quic_ip_addr, .port = peer->quic_conns[ idx ].quic_port };
    else                    *sock = (fd_an_sock_t){ .ip4 = peer->udp_ip_addrs[ idx ],            .port = peer->udp_ports[ idx ]          };
  }
  return sock->ip4 && sock->port;
}


static fd_an_routes_t const *
an_routes( fd_an_txsend_t * an ) {
  ulong next = an->live^1UL;
  if( FD_UNLIKELY( fd_an_routes_shared_read( an->shared, &an->routes[ next ], &an->seen ) ) ) an->live = next;
  return &an->routes[ an->live ];
}


static int
an_first( fd_an_txsend_t * an,
          fd_an_dest_t     dest ) {
  for( ulong i=0UL; i<an->sent_cnt; i++ ) {
    fd_an_dest_t const * d = &an->sent[ i ];
    if( d->sock.ip4==dest.sock.ip4 && d->sock.port==dest.sock.port && d->secondary==dest.secondary ) return 0;
  }
  if( FD_LIKELY( an->sent_cnt<FD_AN_TXSEND_SENT_MAX ) ) an->sent[ an->sent_cnt++ ] = dest;
  return 1;
}


static void
an_send( fd_txsend_tile_t *     ctx,
         fd_an_txsend_t *       an,
         peer_entry_t const *   peer,
         fd_an_target_t const * target,
         uchar const *          payload,
         ulong                  payload_sz ) {
  fd_an_dest_t dest = { .secondary = target->secondary };
  if( FD_UNLIKELY( !an_resolve( peer, target, &dest.sock ) || !an_first( an, dest ) ) ) return;
  if( !dest.secondary ) {
    send_udp( ctx, dest.sock.ip4, dest.sock.port, payload, payload_sz );
    return;
  }
  fd_quic_conn_t * conn = fd_an_peers_conn( an->peers, dest.sock );
  if( FD_LIKELY( conn ) ) send_quic( conn, payload, payload_sz );
}


static void
an_wanted_add( peer_entry_t const *   peer,
               fd_an_target_t const * targets,
               ulong                  cnt,
               fd_an_sock_t *         wanted,
               ulong *                wanted_cnt ) {
  for( ulong i=0UL; i<cnt && *wanted_cnt<FD_AN_TXSEND_WANTED_MAX; i++ ) {
    if( targets[ i ].secondary && an_resolve( peer, &targets[ i ], &wanted[ *wanted_cnt ] ) ) (*wanted_cnt)++;
  }
}


static ulong
an_wanted( fd_txsend_tile_t const * ctx,
           fd_an_routes_t const *   routes,
           fd_an_sock_t *           wanted ) {
  ulong wanted_cnt = 0UL;
  for( ulong i=0UL; i<FD_AN_PEERS_LOOKAHEAD; i++ ) {
    ulong               slot   = ctx->voted_slot+1UL + i*FD_EPOCH_SLOTS_PER_ROTATION;
    fd_pubkey_t const * leader = fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, slot );
    if( FD_UNLIKELY( !leader ) ) continue;
    peer_entry_t const * peer = peer_map_ele_query_const( ctx->peer_map, leader, NULL, ctx->peers );

    an_wanted_add( peer, an_stock, AN_STOCK_CNT, wanted, &wanted_cnt );
    fd_an_route_t const * route = fd_an_routes_lookup( routes, slot );
    if( route ) an_wanted_add( peer, fd_an_route_targets( routes, route ), route->target_cnt, wanted, &wanted_cnt );
  }
  return wanted_cnt;
}


static void
an_close( fd_txsend_tile_t *           ctx,
          fd_an_peers_change_t const * change ) {
  if( FD_LIKELY( !change->close_cnt ) ) return;
  for( ulong i=0UL; i<change->close_cnt; i++ ) fd_quic_conn_close( change->close[ i ], 0U );
  fd_quic_service( ctx->quic, fd_clock_tile_now( ctx->clock ) );
}


static void
an_init( fd_txsend_tile_t const *      ctx,
         fd_an_routes_shared_t const * shared ) {
  fd_an_txsend_t * an = fd_an_txsend;
  memset( an, 0, sizeof(fd_an_txsend_t) );
  fd_an_peers_init( an->peers );
  if( FD_UNLIKELY( !shared ) ) return;

  an->shared     = shared;
  an->enabled    = 1;
  an->identity   = *ctx->identity_key;
  an->voted_slot = ULONG_MAX;
}

static void
fd_an_txsend_join( fd_txsend_tile_t const * ctx,
                   fd_topo_t const *        topo ) {
  an_init( ctx, fd_an_routes_shared_join( topo ) );
  fd_an_consts_attach( fd_an_consts_shared_join( topo ) );
}

static void
fd_an_txsend_conn_final( fd_quic_conn_t * conn ) {
  if( FD_UNLIKELY( !fd_an_txsend->enabled ) ) return;
  fd_an_peers_forget( fd_an_txsend->peers, conn );
}


static int
fd_an_txsend_conns( fd_txsend_tile_t * ctx ) {
  fd_an_txsend_t * an = fd_an_txsend;
  if( FD_UNLIKELY( !an->enabled ) ) return 0;

  long now   = fd_clock_tile_now( ctx->clock );
  long since = now - an->refreshed;
  if( FD_LIKELY( ctx->voted_slot==an->voted_slot && since>=0L && since<FD_AN_TXSEND_REFRESH_NANOS ) ) return 1;
  an->voted_slot = ctx->voted_slot;
  an->refreshed  = now;

  fd_an_routes_t const * routes = an_routes( an );

  if( FD_UNLIKELY( !fd_pubkey_eq( &an->identity, ctx->identity_key ) ) ) {
    an->identity = *ctx->identity_key;
    fd_an_peers_reset( an->peers, an->change );
    an_close( ctx, an->change );
  }

  ulong wanted_cnt = an_wanted( ctx, routes, an->wanted );
  fd_an_peers_update( an->peers, an->wanted, wanted_cnt, now, an->change );
  an_close( ctx, an->change );
  for( ulong i=0UL; i<an->change->dial_cnt; i++ ) {
    fd_an_peer_t * peer = an->change->dial[ i ];
    fd_quic_conn_t * conn = fd_quic_connect( ctx->quic, peer->sock.ip4, peer->sock.port, ctx->src_ip_addr, ctx->src_port, now );
    fd_an_peers_dialed( peer, conn, now );
  }
  return 1;
}


static int
fd_an_txsend_vote( fd_txsend_tile_t *  ctx,
                   fd_pubkey_t const * leader,
                   uchar const *       payload,
                   ulong               payload_sz ) {
  fd_an_txsend_t * an = fd_an_txsend;
  if( FD_UNLIKELY( !an->enabled ) ) return 0;

  peer_entry_t const * peer = peer_map_ele_query_const( ctx->peer_map, leader, NULL, ctx->peers );
  for( ulong i=0UL; i<AN_STOCK_CNT; i++ ) an_send( ctx, an, peer, &an_stock[ i ], payload, payload_sz );
  return 1;
}


static void
fd_an_txsend_vote_routes( fd_txsend_tile_t * ctx,
                          ulong              vote_slot,
                          uchar const *      payload,
                          ulong              payload_sz ) {
  fd_an_txsend_t * an = fd_an_txsend;
  if( FD_UNLIKELY( !an->enabled ) ) return;

  fd_an_routes_t const * routes = an_routes( an );
  ulong                  window = fd_ulong_min( UPCOMING_LEADER_FANOUT_SLOTS(), FD_AN_TXSEND_WINDOW_MAX );

  fd_pubkey_t const * seen[ FD_AN_TXSEND_WINDOW_MAX ];
  ulong               seen_cnt = 0UL;
  for( ulong n=0UL; n<window; n++ ) {
    ulong               slot   = vote_slot+1UL + n;
    fd_pubkey_t const * leader = fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, slot );
    if( FD_UNLIKELY( !leader ) ) continue;

    int again = 0;
    for( ulong i=0UL; i<seen_cnt; i++ ) again |= fd_pubkey_eq( seen[ i ], leader );
    if( again ) continue;
    seen[ seen_cnt++ ] = leader;

    fd_an_route_t const * route = fd_an_routes_lookup( routes, slot );
    if( !route ) continue;

    peer_entry_t const *   peer    = peer_map_ele_query_const( ctx->peer_map, leader, NULL, ctx->peers );
    fd_an_target_t const * targets = fd_an_route_targets( routes, route );
    for( ulong i=0UL; i<route->target_cnt; i++ ) an_send( ctx, an, peer, &targets[ i ], payload, payload_sz );
  }

  an->sent_cnt = 0UL;
}
