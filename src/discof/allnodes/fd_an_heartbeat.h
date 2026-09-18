#ifndef HEADER_fd_src_discof_allnodes_fd_an_heartbeat_h
#define HEADER_fd_src_discof_allnodes_fd_an_heartbeat_h


#include "fd_an_conn.h"
#include "fd_an_endpoints.h"

#include "../../disco/keyguard/fd_keyguard.h"


#define FD_AN_HB_MSG_SZ (FD_KEYGUARD_ALLNODES_HB_SZ)

#define FD_AN_HB_STATE_OFF     (0)
#define FD_AN_HB_STATE_WAIT    (1)
#define FD_AN_HB_STATE_RESOLVE (2)
#define FD_AN_HB_STATE_PROBE   (3)
#define FD_AN_HB_STATE_READY   (4)
#define FD_AN_HB_STATE_CALL    (5)

struct fd_an_hb_cfg {
  char const * version;
  ulong        version_len;

  long  request_timeout_nanos;
  long  attempt_pause_nanos;
  ulong first_attempts;
  ulong other_attempts;
};

typedef struct fd_an_hb_cfg fd_an_hb_cfg_t;

struct fd_an_hb_metrics {
  ulong ok;
  ulong fail;
  ulong skip;
  ulong calls;
  ulong slot;
};

typedef struct fd_an_hb_metrics fd_an_hb_metrics_t;

struct fd_an_hb_private;
typedef struct fd_an_hb_private fd_an_hb_t;

FD_PROTOTYPES_BEGIN


static inline void
fd_an_hb_msg( uchar         msg[ FD_AN_HB_MSG_SZ ],
              uchar const   identity[ 32 ],
              ulong         slot ) {
  fd_memcpy( msg, FD_KEYGUARD_ALLNODES_HB_DOMAIN, FD_KEYGUARD_ALLNODES_HB_DOMAIN_SZ );
  fd_memcpy( msg+FD_KEYGUARD_ALLNODES_HB_DOMAIN_SZ, identity, 32UL );
  FD_STORE( ulong, msg+FD_KEYGUARD_ALLNODES_HB_DOMAIN_SZ+32UL, slot );
}

ulong
fd_an_hb_align( void );

ulong
fd_an_hb_footprint( void );


fd_an_hb_t *
fd_an_hb_new( void *                 mem,
              fd_an_hb_cfg_t const * cfg,
              fd_an_ssl_ctx_t *      ssl_ctx,
              ulong                  rng_seed );


void
fd_an_hb_start( fd_an_hb_t *              hb,
                fd_an_endpoints_t const * eps,
                uint const *              ep_ip4,
                ushort                    shred_version,
                long                      now );


int
fd_an_hb_poll( fd_an_hb_t * hb,
               long         now,
               long         interval_nanos,
               int *        charge_busy );


void
fd_an_hb_send( fd_an_hb_t *  hb,
               uchar const * req,
               ulong         req_sz,
               ulong         slot,
               long          now );


void
fd_an_hb_defer( fd_an_hb_t * hb,
                long         now,
                long         delay_nanos );

void
fd_an_hb_skip( fd_an_hb_t * hb,
               long         now );


FD_FN_PURE int
fd_an_hb_active( fd_an_hb_t const * hb );

FD_FN_CONST fd_an_hb_metrics_t const *
fd_an_hb_metrics( fd_an_hb_t const * hb );

FD_PROTOTYPES_END

#endif
