#ifndef HEADER_fd_src_discof_allnodes_fd_an_conn_h
#define HEADER_fd_src_discof_allnodes_fd_an_conn_h


#include "../../waltz/grpc/fd_grpc_client.h"
#include "../../util/alloc/fd_alloc.h"


struct ssl_ctx_st;
typedef struct ssl_ctx_st fd_an_ssl_ctx_t;


#define FD_AN_CONN_STATE_IDLE       (0)
#define FD_AN_CONN_STATE_CONNECTING (1)
#define FD_AN_CONN_STATE_HANDSHAKE  (2)
#define FD_AN_CONN_STATE_READY      (3)
#define FD_AN_CONN_STATE_DEAD       (4)


#define FD_AN_CONN_ERR_NONE    (0)
#define FD_AN_CONN_ERR_LOCAL   (1)
#define FD_AN_CONN_ERR_CONNECT (2)
#define FD_AN_CONN_ERR_TLS     (3)
#define FD_AN_CONN_ERR_ALPN    (4)
#define FD_AN_CONN_ERR_PROTO   (5)
#define FD_AN_CONN_ERR_PEER    (6)
#define FD_AN_CONN_ERR_TIMEOUT (7)


#define FD_AN_CONN_CLEARTEXT (0)
#define FD_AN_CONN_TLS       (1)


#define FD_AN_CONN_BUF_MAX_MIN (4096UL)

struct fd_an_conn_private;
typedef struct fd_an_conn_private fd_an_conn_t;

FD_PROTOTYPES_BEGIN


ulong
fd_an_conn_align( void );

ulong
fd_an_conn_footprint( ulong buf_max );


fd_an_conn_t *
fd_an_conn_new( void *                             mem,
                ulong                              buf_max,
                fd_grpc_client_callbacks_t const * cb,
                void *                             cb_ctx,
                ulong                              rng_seed );

fd_an_conn_t *
fd_an_conn_join( void * mem );


fd_an_ssl_ctx_t *
fd_an_conn_tls_ctx_new( fd_alloc_t * alloc );

void *
fd_an_conn_leave( fd_an_conn_t * conn );


void *
fd_an_conn_delete( void * mem );


int
fd_an_conn_start( fd_an_conn_t *     conn,
                  uint               ip4,
                  ushort             port,
                  char const *       host,
                  int                tls,
                  fd_an_ssl_ctx_t *  ssl_ctx,
                  char const *       version,
                  ulong              version_len,
                  long               now,
                  long               deadline );


int
fd_an_conn_poll( fd_an_conn_t * conn,
                 long           now,
                 int *          charge_busy );


void
fd_an_conn_set_deadline( fd_an_conn_t * conn,
                         long           deadline );


void
fd_an_conn_kill( fd_an_conn_t * conn,
                 int            reason );


void
fd_an_conn_close( fd_an_conn_t * conn );


FD_FN_PURE int
fd_an_conn_state( fd_an_conn_t const * conn );

FD_FN_PURE int
fd_an_conn_reason( fd_an_conn_t const * conn );

FD_FN_PURE int
fd_an_conn_errno( fd_an_conn_t const * conn );

FD_FN_PURE int
fd_an_conn_fd( fd_an_conn_t const * conn );

fd_grpc_client_t *
fd_an_conn_grpc( fd_an_conn_t * conn );

fd_grpc_client_metrics_t *
fd_an_conn_metrics( fd_an_conn_t * conn );


FD_FN_CONST char const *
fd_an_conn_strerror( int state );

FD_FN_CONST char const *
fd_an_conn_strreason( int reason );

FD_PROTOTYPES_END

#endif
