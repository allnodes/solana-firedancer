#include "fd_an_topo.h"
#include "fd_an_endpoints.h"
#include "fd_an_shared.h"

#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/topo/fd_topob.h"
#include "../../util/pod/fd_pod_format.h"

#include <stdlib.h>

void
fd_an_topo_build( fd_topo_t *      topo,
                  config_t const * config ) {
  if( FD_UNLIKELY( !config->gossip.entrypoints_cnt ) ) {
    return;
  }

  ulong sign_idx  = fd_topo_find_tile( topo, "sign",  0UL );
  ulong admin_idx = fd_topo_find_tile( topo, "admin", 0UL );
  if( FD_UNLIKELY( sign_idx==ULONG_MAX || admin_idx==ULONG_MAX ) ) {
    return;
  }

  char const * endpoints = getenv( "SOLANA_ALLNODES_ENDPOINTS_OVERRIDE" );
  if( FD_LIKELY( !endpoints ) ) endpoints = "";
  if( FD_UNLIKELY( fd_cstr_nlen( endpoints, FD_AN_OVERRIDE_MAX+1UL )>FD_AN_OVERRIDE_MAX ) ) {
    FD_LOG_DEBUG(( "Failed to read `SOLANA_ALLNODES_ENDPOINTS_OVERRIDE` env var: longer than %lu bytes", FD_AN_OVERRIDE_MAX ));
    endpoints = "";
  }

  fd_topob_wksp( topo, "an_shared" );
  fd_topo_obj_t * obj = fd_topob_obj( topo, "dcache", "an_shared" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, 0UL,                    "obj.%lu.data_sz", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, sizeof(fd_an_shared_t), "obj.%lu.app_sz",  obj->id ) );
  FD_TEST( fd_pod_insert_ulong( topo->props, FD_AN_SHARED_PROP_CLIENT, obj->id ) );

  FD_TEST( fd_pod_insertf_ulong( topo->props, (ulong)config->consensus.expected_shred_version,
                                                                     "obj.%lu.an_shredver", obj->id ) );
  FD_TEST( fd_pod_insertf_cstr ( topo->props, endpoints,             "obj.%lu.an_endpoints", obj->id ) );

  FD_TEST( fd_pod_insertf_cstr ( topo->props, config->paths.identity_key, "obj.%lu.an_identity", obj->id ) );

  fd_topob_wksp( topo, "anclnt" );
  fd_topo_tile_t * tile = fd_topob_tile( topo, "anclnt", "anclnt", "metric_in", ULONG_MAX, 0, 1, 0, 0 );

  if( FD_LIKELY( fd_topo_find_link( topo, "ipecho_out", 0UL )!=ULONG_MAX ) ) {
    fd_topob_tile_in( topo, "anclnt", 0UL, "metric_in", "ipecho_out", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  } else if( FD_UNLIKELY( !config->consensus.expected_shred_version ) ) {
  }

  fd_topob_wksp( topo, "anclnt_sign" );
  fd_topob_wksp( topo, "sign_anclnt" );
  fd_topob_link( topo, "anclnt_sign", "anclnt_sign", 128UL, FD_KEYGUARD_ALLNODES_HB_SZ, 1UL );
  fd_topob_link( topo, "sign_anclnt", "sign_anclnt", 128UL, 64UL,                       1UL );
  fd_topob_tile_in ( topo, "sign",   0UL, "metric_in", "anclnt_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  fd_topob_tile_out( topo, "anclnt", 0UL,              "anclnt_sign", 0UL                                         );
  fd_topob_tile_in ( topo, "anclnt", 0UL, "metric_in", "sign_anclnt", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topob_tile_out( topo, "sign",   0UL,              "sign_anclnt", 0UL                                         );

  fd_topob_tile_uses( topo, &topo->tiles[ admin_idx ], &topo->objs[ tile->id_keyswitch_obj_id ], FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_tile_uses( topo, tile, obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_wksp( topo, "an_consts" );
  fd_topo_obj_t * consts = fd_topob_obj( topo, "dcache", "an_consts" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, 0UL,                    "obj.%lu.data_sz", consts->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, sizeof(fd_an_consts_t), "obj.%lu.app_sz",  consts->id ) );
  FD_TEST( fd_pod_insert_ulong( topo->props, FD_AN_SHARED_PROP_CONSTS, consts->id ) );
  fd_topob_tile_uses( topo, tile, consts, FD_SHMEM_JOIN_MODE_READ_WRITE );

  ulong snapct_idx = fd_topo_find_tile( topo, "snapct", 0UL );
  if( FD_UNLIKELY( snapct_idx==ULONG_MAX ) ) {
    return;
  }
  if( FD_UNLIKELY( !config->firedancer.snapshots.sources.gossip.allow_any &&
                   !config->firedancer.snapshots.sources.gossip.allow_list_cnt ) ) {
    return;
  }

  FD_TEST( fd_pod_insert_ulong( topo->props, FD_AN_SHARED_PROP_SNAPCT, obj->id ) );
  fd_topob_tile_uses( topo, &topo->tiles[ snapct_idx ], obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
}
