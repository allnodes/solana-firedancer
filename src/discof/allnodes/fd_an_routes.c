#include "fd_an_routes.h"

#include "../../util/bits/fd_bits.h"

#include <string.h>

fd_an_route_t const *
fd_an_routes_lookup( fd_an_routes_t const * routes,
                     ulong                  slot ) {
  ulong lo = 0UL;
  ulong hi = routes->route_cnt;
  while( lo<hi ) {
    ulong mid = lo + (hi-lo)/2UL;
    if( routes->route[ mid ].slot_from<=slot ) lo = mid+1UL;
    else                                       hi = mid;
  }
  if( FD_UNLIKELY( !lo ) ) return NULL;
  fd_an_route_t const * route = &routes->route[ lo-1UL ];
  return slot<=route->slot_to ? route : NULL;
}

int
fd_an_routes_valid( fd_an_routes_t const * routes ) {
  if( FD_UNLIKELY( routes->route_cnt >FD_AN_ROUTES_MAX  ) ) return 0;
  if( FD_UNLIKELY( routes->target_cnt>FD_AN_TARGETS_MAX ) ) return 0;
  for( ulong i=0UL; i<routes->route_cnt; i++ ) {
    fd_an_route_t const * r = &routes->route[ i ];
    if( FD_UNLIKELY( r->slot_to<r->slot_from ) ) return 0;
    if( FD_UNLIKELY( i && r->slot_from<=routes->route[ i-1UL ].slot_to ) ) return 0;
    if( FD_UNLIKELY( (ulong)r->target_off+(ulong)r->target_cnt>routes->target_cnt ) ) return 0;
  }
  return 1;
}

void
fd_an_routes_copy( fd_an_routes_t *       dst,
                   fd_an_routes_t const * src ) {
  ulong route_cnt  = fd_ulong_min( FD_VOLATILE_CONST( src->route_cnt  ), FD_AN_ROUTES_MAX  );
  ulong target_cnt = fd_ulong_min( FD_VOLATILE_CONST( src->target_cnt ), FD_AN_TARGETS_MAX );
  dst->route_cnt  = route_cnt;
  dst->target_cnt = target_cnt;
  dst->dropped    = FD_VOLATILE_CONST( src->dropped );
  memcpy( dst->route,  src->route,  route_cnt *sizeof(fd_an_route_t)  );
  memcpy( dst->target, src->target, target_cnt*sizeof(fd_an_target_t) );
}
