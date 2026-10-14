#ifndef HEADER_fd_src_discof_allnodes_fd_an_client_h
#define HEADER_fd_src_discof_allnodes_fd_an_client_h


#include "fd_an_conn.h"
#include "fd_an_endpoints.h"
#include "fd_an_proto.h"
#include "fd_an_shared.h"

#include "../../waltz/resolv/fd_adns.h"


#define FD_AN_CLIENT_PROBE_BUF_MAX (32UL<<10)
#define FD_AN_CLIENT_QUERY_BUF_MAX (256UL<<10)

struct fd_an_client_cfg {
  char const * endpoints;
  char const * version;
  ulong        version_len;

  ushort shred_version;

  int    bootstrap;

  long  shred_version_timeout_nanos;
  long  probe_budget_nanos;
  long  request_timeout_nanos;
  long  attempt_pause_nanos;
  ulong max_attempts;
};

typedef struct fd_an_client_cfg fd_an_client_cfg_t;

struct fd_an_client_private;
typedef struct fd_an_client_private fd_an_client_t;

FD_PROTOTYPES_BEGIN

ulong
fd_an_client_align( void );

ulong
fd_an_client_footprint( void );


fd_an_client_t *
fd_an_client_new( void *                     mem,
                  fd_an_client_cfg_t const * cfg,
                  fd_an_tls_ctx_t *          tls_ctx,
                  fd_adns_t *                adns,
                  fd_an_shared_t *           shared,
                  ulong                      rng_seed );


void
fd_an_client_set_shred_version( fd_an_client_t * client,
                                ushort           shred_version );


int
fd_an_client_poll( fd_an_client_t * client,
                   long             now,
                   int *            charge_busy );


void
fd_an_client_boot_over( fd_an_client_t * client );

FD_FN_PURE int
fd_an_client_state( fd_an_client_t const * client );


FD_FN_PURE int
fd_an_client_is_terminal( fd_an_client_t const * client );


FD_FN_PURE int
fd_an_client_busy( fd_an_client_t const * client );


FD_FN_CONST fd_an_endpoints_t const *
fd_an_client_endpoints( fd_an_client_t const * client );

FD_FN_CONST uint const *
fd_an_client_ep_ip4( fd_an_client_t const * client );


FD_FN_PURE fd_an_consts_t const *
fd_an_client_consts( fd_an_client_t const * client );


int
fd_an_client_flags_state( fd_an_client_t const * client,
                          ulong *                flags );

FD_PROTOTYPES_END

#endif
