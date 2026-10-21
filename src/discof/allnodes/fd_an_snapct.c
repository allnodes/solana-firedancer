
#include "fd_an_shared.h"


#define FD_AN_SNAPCT_TICK_MAX_NANOS (1000L*1000L*1000L)

struct fd_an_snapct {
  int              enabled;
  fd_an_shared_t * shared;

  long  held_nanos;
  long  last_call_nanos;

  int   finished;
  int   taken;
  int   released;

  fd_an_snapshot_node_t node;
  int                   reason;

  int   prog_state;
  long  prog_nanos;
  ulong prog_bytes;
};

typedef struct fd_an_snapct fd_an_snapct_t;


static fd_an_snapct_t fd_an_snapct[ 1 ];


#define FD_AN_PROGRESS_INTERVAL_NANOS (6L*1000L*1000L*1000L)
#define FD_AN_PROGRESS_STATE_NONE     (-1)


static int
fd_an_snapct_progress( fd_snapct_tile_t const * ctx,
                       long                     now ) {
  fd_an_snapct_t * an = fd_an_snapct;

  int full = ctx->state==FD_SNAPCT_STATE_READING_FULL_HTTP;
  int incr = ctx->state==FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP;
  if( FD_LIKELY( !full && !incr ) ) {
    an->prog_state = FD_AN_PROGRESS_STATE_NONE;
    return 0;
  }

  ulong read  = full ? ctx->metrics.full.bytes_read  : ctx->metrics.incremental.bytes_read;
  ulong total = full ? ctx->metrics.full.bytes_total : ctx->metrics.incremental.bytes_total;

  if( FD_UNLIKELY( ctx->state!=an->prog_state || read<an->prog_bytes ) ) {
    an->prog_state = ctx->state;
    an->prog_nanos = now;
    an->prog_bytes = read;
    return 0;
  }

  long dt = now - an->prog_nanos;
  if( FD_LIKELY( dt<FD_AN_PROGRESS_INTERVAL_NANOS ) ) return 0;

  double rate = (double)( read-an->prog_bytes )/( (double)dt/1e9 );

  an->prog_nanos = now;
  an->prog_bytes = read;

  if( FD_LIKELY( total ) ) {
    FD_LOG_INFO(( "downloaded %lu bytes %.1f%% %.1f bytes/s", read, 100.*(double)read/(double)total, rate ));
  } else {
    FD_LOG_INFO(( "downloaded %lu bytes %.1f bytes/s", read, rate ));
  }
  return 1;
}


static void
fd_an_snapct_release( fd_an_snapct_t * an ) {
  if( FD_LIKELY( an->released ) ) return;
  an->released = 1;
  FD_VOLATILE( an->shared->snapct_state ) = FD_AN_SNAPCT_DONE;
}


static void
fd_an_snapct_give_up( fd_an_snapct_t * an,
                      int              reason ) {
  an->finished = 1;
  an->reason   = reason;
  fd_an_snapct_release( an );
}


static int
fd_an_snapct_hold( fd_an_snapct_t *         an,
                   fd_snapct_tile_t const * ctx,
                   long                     now ) {
  long budget = (long)( FD_AN_HOLD_MILLIS*1000000UL );
  long margin = (long)( FD_AN_HOLD_MARGIN_MILLIS*1000000UL );
  if( FD_UNLIKELY( an->held_nanos>=budget || now>=ctx->deadline_nanos-margin ) ) {
    fd_an_snapct_give_up( an, FD_AN_FALLBACK_HOLD_EXPIRED );
    return 0;
  }
  return 1;
}


static void
fd_an_snapct_join( fd_snapct_tile_t *     ctx,
                   fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_an_snapct_t * an = fd_an_snapct;
  fd_memset( an, 0, sizeof(fd_an_snapct_t) );
  an->prog_state = FD_AN_PROGRESS_STATE_NONE;

  an->shared = fd_an_shared_join( topo );
  if( FD_LIKELY( !an->shared ) ) return;

  if( FD_UNLIKELY( !ctx->gossip_enabled ) ) {
    FD_VOLATILE( an->shared->snapct_state ) = FD_AN_SNAPCT_DISABLED;
    return;
  }

  if( FD_UNLIKELY( tile->snapct.sources.servers_cnt*FD_TOPO_MAX_RESOLVED_ADDRS>=FD_TOPO_SNAPSHOTS_SERVERS_MAX_RESOLVED ) ) {
    FD_VOLATILE( an->shared->snapct_state ) = FD_AN_SNAPCT_DISABLED;
    return;
  }

  an->enabled = 1;
  FD_VOLATILE( an->shared->snapct_state ) = FD_AN_SNAPCT_RUNNING;
}


struct fd_an_snapct_vetted {
  fd_ip4_port_t   addr;
  fd_sspeer_key_t key;
  ulong           incr_slot;
};

typedef struct fd_an_snapct_vetted fd_an_snapct_vetted_t;


static int
fd_an_snapct_vet( fd_snapct_tile_t *            ctx,
                  fd_an_snapshot_node_t const * node,
                  fd_an_snapct_vetted_t *       out ) {
  out->addr.addr = node->ip4;
  out->addr.port = fd_ushort_bswap( node->port );

  fd_memset( &out->key, 0, sizeof(fd_sspeer_key_t) );
  fd_memcpy( out->key.pubkey->uc, node->pubkey, sizeof(out->key.pubkey->uc) );
  out->key.is_url = 0;

  int pubkey_zero = 1;
  for( ulong i=0UL; i<sizeof(node->pubkey); i++ ) {
    if( FD_LIKELY( node->pubkey[ i ] ) ) { pubkey_zero = 0; break; }
  }

  out->incr_slot = FD_SSPEER_SLOT_UNKNOWN;
  if( FD_LIKELY( node->has_incremental &&
                 node->incr_slot>=node->full_slot &&
                 node->incr_slot<FD_SSPEER_PLAUSIBLE_MAX_SLOT ) ) {
    out->incr_slot = node->incr_slot;
  }

  int   incr_on   = ctx->config.incremental_snapshots;
  ulong node_slot = ( incr_on && out->incr_slot!=FD_SSPEER_SLOT_UNKNOWN ) ? out->incr_slot : node->full_slot;

  fd_sspeer_selector_process_cluster_slot( ctx->selector );
  fd_sscluster_slot_t cluster = fd_sspeer_selector_cluster_slot( ctx->selector );
  ulong cluster_slot = ( incr_on && cluster.incremental!=FD_SSPEER_SLOT_UNKNOWN ) ? cluster.incremental : cluster.full;

  if( FD_UNLIKELY( !node->ip4 || !fd_ip4_addr_is_public( node->ip4 ) ||
                   fd_ip4_addr_is_mcast( node->ip4 ) || fd_ip4_addr_is_bcast( node->ip4 ) ||
                   !node->port ) ) {
    return FD_AN_FALLBACK_BAD_ADDR;
  }
  if( FD_UNLIKELY( pubkey_zero || !node->full_slot || node->full_slot>=FD_SSPEER_PLAUSIBLE_MAX_SLOT ) ) {
    return FD_AN_FALLBACK_BAD_NODE;
  }
  if( FD_UNLIKELY( incr_on && out->incr_slot==FD_SSPEER_SLOT_UNKNOWN ) ) {
    return FD_AN_FALLBACK_NO_INCREMENTAL;
  }
  if( FD_UNLIKELY( cluster_slot!=FD_SSPEER_SLOT_UNKNOWN &&
                   node_slot<fd_ulong_sat_sub( cluster_slot, ctx->config.sources.max_local_full_effective_age ) ) ) {
    return FD_AN_FALLBACK_STALE_NODE;
  }
  if( FD_UNLIKELY( wfs_short_of_target( ctx, node_slot ) ) ) {
    return FD_AN_FALLBACK_STALE_NODE;
  }
  if( FD_UNLIKELY( ctx->resolved_servers_cnt>=FD_TOPO_SNAPSHOTS_SERVERS_MAX_RESOLVED ) ) {
    return FD_AN_FALLBACK_DISABLED;
  }
  if( FD_UNLIKELY( blacklist_map_ele_query( ctx->blacklist_map, &out->key, NULL, ctx->blacklist_pool ) ) ) {
    return FD_AN_FALLBACK_BANNED;
  }
  if( FD_UNLIKELY( ctx->ssping && fd_ssping_is_invalidated( ctx->ssping, out->addr ) ) ) {
    return FD_AN_FALLBACK_BANNED;
  }

  for( ulong i=0UL; i<ctx->config.sources.gossip.block_list_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( ctx->config.sources.gossip.block_list[ i ].uc, node->pubkey, sizeof(node->pubkey) ) ) ) {
      return FD_AN_FALLBACK_BLOCKED;
    }
  }

  if( FD_UNLIKELY( ctx->local_in.full_snapshot_slot!=ULONG_MAX ) ) {
    ulong local_slot = ctx->local_in.full_snapshot_slot;
    if( incr_on && ctx->local_in.incremental_snapshot_slot!=ULONG_MAX ) local_slot = ctx->local_in.incremental_snapshot_slot;
    if( ctx->local_in.full_snapshot_slot>=node->full_slot ||
        local_slot>=fd_ulong_sat_sub( node_slot, ctx->config.sources.max_local_full_effective_age ) ) {
      return FD_AN_FALLBACK_LOCAL_SNAPSHOT;
    }
    if( incr_on ) {
      fd_sspeer_t best_incr = fd_sspeer_selector_best( ctx->selector, 1, ctx->local_in.full_snapshot_slot, wfs_floor( ctx ) );
      if( best_incr.addr.l && best_incr.incr_slot>=fd_ulong_sat_sub( node_slot, ctx->config.sources.max_local_full_effective_age ) ) {
        return FD_AN_FALLBACK_LOCAL_SNAPSHOT;
      }
    }
  }

  return FD_AN_FALLBACK_NONE;
}


static int
fd_an_snapct_try_start( fd_snapct_tile_t *  ctx,
                        fd_stem_context_t * stem,
                        long                now ) {
  fd_an_snapct_t * an = fd_an_snapct;
  if( FD_LIKELY( !an->enabled ) ) return 0;

  if( FD_LIKELY( an->finished ) ) {
    fd_an_snapct_release( an );
    return 0;
  }

  if( FD_UNLIKELY( an->last_call_nanos && now>ctx->deadline_nanos ) ) ctx->deadline_nanos = now;

  long dt = an->last_call_nanos ? now-an->last_call_nanos : 0L;
  an->last_call_nanos = now;
  if( FD_LIKELY( dt>0L && dt<FD_AN_SNAPCT_TICK_MAX_NANOS ) ) an->held_nanos += dt;

  fd_an_shared_t * sh = an->shared;
  fd_an_shared_t   answer[ 1 ];

  if( FD_UNLIKELY( FD_VOLATILE_CONST( sh->magic )!=FD_AN_SHARED_MAGIC || !fd_an_shared_read( sh, answer ) ) ) {
    return fd_an_snapct_hold( an, ctx, now );
  }

  if( FD_LIKELY( !answer->has_node ) ) {
    if( FD_UNLIKELY( answer->state==FD_AN_STATE_UNAVAILABLE || answer->state==FD_AN_STATE_DISABLED ) ) {
      fd_an_snapct_give_up( an, answer->fallback );
      return 0;
    }
    return fd_an_snapct_hold( an, ctx, now );
  }

  fd_an_snapshot_node_t const * node = &answer->node;
  fd_an_snapct_vetted_t         v[ 1 ];

  int reason = fd_an_snapct_vet( ctx, node, v );

  ulong score = FD_SSPEER_SCORE_INVALID;
  if( FD_LIKELY( reason==FD_AN_FALLBACK_NONE ) ) {
    ulong idx = ctx->resolved_servers_cnt++;
    ctx->resolved_servers[ idx ].addr          = v->addr;
    ctx->resolved_servers[ idx ].is_https      = 0;
    ctx->resolved_servers[ idx ].hostname[ 0 ] = '\0';

    score = fd_sspeer_selector_add( ctx->selector, &v->key, v->addr, FD_SSPEER_LATENCY_UNKNOWN,
                                    node->full_slot, v->incr_slot, node->full_hash,
                                    v->incr_slot!=FD_SSPEER_SLOT_UNKNOWN ? node->incr_hash : NULL );
    if( FD_UNLIKELY( score==FD_SSPEER_SCORE_INVALID ) ) {
      ctx->resolved_servers_cnt--;
      reason = FD_AN_FALLBACK_BAD_NODE;
    } else {
      fd_sspeer_selector_process_cluster_slot( ctx->selector );
    }
  }

  if( FD_UNLIKELY( reason!=FD_AN_FALLBACK_NONE ) ) {
    if( FD_UNLIKELY( reason==FD_AN_FALLBACK_BANNED ) ) {
      FD_BASE58_ENCODE_32_BYTES( node->pubkey, node_b58 );
      FD_LOG_WARNING(( "Skipping RPC node that is blacklisted: %s, will use standard algorithm", node_b58 ));
    }
    fd_an_snapct_give_up( an, reason );
    return 0;
  }

  int   incr_on  = ctx->config.incremental_snapshots;
  ulong sel_incr = v->incr_slot;
  fd_ip4_port_t addr = v->addr;

  ctx->predicted_incremental.full_slot = node->full_slot;
  if( FD_LIKELY( incr_on && sel_incr!=FD_SSPEER_SLOT_UNKNOWN ) ) {
    ctx->predicted_incremental.slot = sel_incr;
    send_expected_slot( ctx, stem, sel_incr );
  } else {
    send_expected_slot( ctx, stem, node->full_slot );
  }

  fd_memset( &ctx->peer, 0, sizeof(fd_sspeer_t) );
  ctx->peer.key       = v->key;
  ctx->peer.addr      = addr;
  ctx->peer.full_slot = node->full_slot;
  ctx->peer.incr_slot = sel_incr;
  ctx->peer.score     = score;
  fd_memcpy( ctx->peer.full_hash, node->full_hash, FD_HASH_FOOTPRINT );
  if( FD_LIKELY( sel_incr!=FD_SSPEER_SLOT_UNKNOWN ) ) fd_memcpy( ctx->peer.incr_hash, node->incr_hash, FD_HASH_FOOTPRINT );

  ctx->state = FD_SNAPCT_STATE_READING_FULL_HTTP;
  init_load( ctx, stem, 1, 0 );

  if( FD_LIKELY( ctx->config.max_retry_abort<UINT_MAX ) ) ctx->config.max_retry_abort++;

  an->finished = 1;
  an->taken    = 1;
  an->node     = *node;

  FD_LOG_DEBUG(( "Using RPC node returned by Allnodes service: " FD_IP4_ADDR_FMT ":%hu",
                 FD_IP4_ADDR_FMT_ARGS( addr.addr ), node->port ));

  return 1;
}


static void
fd_an_snapct_meta( fd_snapct_tile_t *       ctx,
                   fd_ssctrl_meta_t const * meta,
                   int                      full ) {
  fd_an_snapct_t * an = fd_an_snapct;
  if( FD_LIKELY( !an->taken || an->released || !full ) ) return;

  if( FD_UNLIKELY( ctx->state!=FD_SNAPCT_STATE_READING_FULL_HTTP || ctx->peer.key.is_url ||
                   memcmp( ctx->peer.key.pubkey->uc, an->node.pubkey, sizeof(an->node.pubkey) ) ) ) {
    fd_an_snapct_release( an );
    return;
  }

  ulong slot = meta->resolved_slot;

  if( FD_UNLIKELY( slot==ULONG_MAX || slot<an->node.full_slot ) ) {
    fd_an_snapct_release( an );
    return;
  }

  if( FD_UNLIKELY( slot>an->node.full_slot ) ) {
    ctx->predicted_incremental.full_slot = slot;
    fd_an_snapct_release( an );
    return;
  }

  if( FD_LIKELY( !memcmp( meta->resolved_hash, an->node.full_hash, FD_HASH_FOOTPRINT ) ) ) {
    fd_an_snapct_release( an );
    return;
  }

  ctx->malformed = 1;
  fd_an_snapct_release( an );
}
