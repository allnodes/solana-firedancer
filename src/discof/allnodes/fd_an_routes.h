#ifndef HEADER_fd_src_discof_allnodes_fd_an_routes_h
#define HEADER_fd_src_discof_allnodes_fd_an_routes_h


#include "../../util/fd_util_base.h"

#define FD_AN_PORT_TPU          (0)
#define FD_AN_PORT_TPU_FORWARDS (1)
#define FD_AN_PORT_TPU_VOTE     (2)
#define FD_AN_PORT_TVU          (3)

struct fd_an_target {
  uchar  relative;
  uchar  port_type;
  uchar  secondary;
  uint   ip4;
  ushort port;
};

typedef struct fd_an_target fd_an_target_t;

struct fd_an_route {
  ulong slot_from;
  ulong slot_to;
  ulong flags;
  uint  target_off;
  uint  target_cnt;
};

typedef struct fd_an_route fd_an_route_t;

#define FD_AN_ROUTES_MAX  (2048UL)
#define FD_AN_TARGETS_MAX (16384UL)

struct fd_an_routes {
  ulong          route_cnt;
  ulong          target_cnt;
  ulong          dropped;
  fd_an_route_t  route [ FD_AN_ROUTES_MAX  ];
  fd_an_target_t target[ FD_AN_TARGETS_MAX ];
};

typedef struct fd_an_routes fd_an_routes_t;

FD_PROTOTYPES_BEGIN


FD_FN_PURE fd_an_route_t const *
fd_an_routes_lookup( fd_an_routes_t const * routes,
                     ulong                  slot );


FD_FN_PURE static inline fd_an_target_t const *
fd_an_route_targets( fd_an_routes_t const * routes,
                     fd_an_route_t const *  route ) {
  return &routes->target[ route->target_off ];
}


FD_FN_PURE int
fd_an_routes_valid( fd_an_routes_t const * routes );


void
fd_an_routes_copy( fd_an_routes_t *       dst,
                   fd_an_routes_t const * src );

FD_PROTOTYPES_END

#endif
