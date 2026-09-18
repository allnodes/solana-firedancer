
#define _GNU_SOURCE

#include "fd_an_conn.h"

#include "../../waltz/h2/fd_h2_conn.h"
#include "../../util/fd_util.h"
#include "../../util/log/fd_log.h"
#include "../../util/io/fd_io.h"
#include "../../util/net/fd_ip4.h"

#include "../../waltz/openssl/fd_openssl.h"
#include "../../waltz/openssl/fd_openssl_tile.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#define FD_AN_CONN_MAGIC (0xa11d0de5c04e0c01UL)

struct fd_an_conn_private {
  ulong magic;

  fd_grpc_client_t *       grpc;
  fd_grpc_client_metrics_t metrics[ 1 ];

  int    state;
  int    reason;
  int    err;

  int    sock;
  int    tls;
  uint   ip4;
  ushort port;

  long   deadline;
  long   started;

  char   host[ FD_FQDN_BUF_MAX ];
  ulong  host_len;
  char   version[ FD_GRPC_CLIENT_VERSION_LEN_MAX+1UL ];
  ulong  version_len;

  SSL *  ssl;
};


static uchar const fd_an_conn_alpn_h2[ 3 ] = { 2, 'h', '2' };


ulong
fd_an_conn_align( void ) {
  return fd_ulong_max( alignof(fd_an_conn_t), fd_grpc_client_align() );
}

ulong
fd_an_conn_footprint( ulong buf_max ) {
  if( FD_UNLIKELY( buf_max<FD_AN_CONN_BUF_MAX_MIN ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_an_conn_t), sizeof(fd_an_conn_t) );
  l = FD_LAYOUT_APPEND( l, fd_grpc_client_align(), fd_grpc_client_footprint( buf_max ) );
  return FD_LAYOUT_FINI( l, fd_an_conn_align() );
}

fd_an_conn_t *
fd_an_conn_new( void *                             mem,
                ulong                              buf_max,
                fd_grpc_client_callbacks_t const * cb,
                void *                             cb_ctx,
                ulong                              rng_seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_an_conn_align() ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( buf_max<FD_AN_CONN_BUF_MAX_MIN ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !cb ) ) {
    return NULL;
  }

  if( FD_UNLIKELY( !cb->conn_established || !cb->conn_dead || !cb->tx_complete ||
                   !cb->rx_start || !cb->rx_msg || !cb->rx_end ||
                   !cb->rx_timeout || !cb->ping_ack ) ) {
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_an_conn_t * conn =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_an_conn_t), sizeof(fd_an_conn_t) );
  void * grpc_mem =
    FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_client_align(), fd_grpc_client_footprint( buf_max ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_an_conn_align() );

  memset( conn, 0, sizeof(fd_an_conn_t) );
  conn->state    = FD_AN_CONN_STATE_IDLE;
  conn->reason   = FD_AN_CONN_ERR_NONE;
  conn->sock     = -1;
  conn->deadline = LONG_MAX;

  conn->grpc = fd_grpc_client_new( grpc_mem, cb, conn->metrics, cb_ctx, buf_max, rng_seed );
  if( FD_UNLIKELY( !conn->grpc ) ) return NULL;

  FD_COMPILER_MFENCE();
  conn->magic = FD_AN_CONN_MAGIC;
  FD_COMPILER_MFENCE();

  return conn;
}

fd_an_conn_t *
fd_an_conn_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_an_conn_align() ) ) ) {
    return NULL;
  }
  fd_an_conn_t * conn = mem;
  if( FD_UNLIKELY( conn->magic!=FD_AN_CONN_MAGIC ) ) {
    return NULL;
  }
  return conn;
}

void *
fd_an_conn_leave( fd_an_conn_t * conn ) {
  if( FD_UNLIKELY( !conn ) ) {
    return NULL;
  }
  return conn;
}

void *
fd_an_conn_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  fd_an_conn_t * conn = mem;
  if( FD_UNLIKELY( conn->magic!=FD_AN_CONN_MAGIC ) ) {
    return NULL;
  }

  fd_an_conn_close( conn );
  fd_grpc_client_delete( conn->grpc );
  conn->grpc = NULL;

  FD_COMPILER_MFENCE();
  conn->magic = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}



static int
fd_an_conn_die( fd_an_conn_t * conn,
                int            reason,
                int            err ) {
  if( FD_LIKELY( conn->state!=FD_AN_CONN_STATE_DEAD ) ) {
    conn->state  = FD_AN_CONN_STATE_DEAD;
    conn->reason = reason;
    conn->err    = err;
  }
  return conn->state;
}



static int
fd_an_conn_ssl_open( fd_an_conn_t * conn,
                     SSL_CTX *      ssl_ctx ) {

  BIO * bio = fd_openssl_bio_new_socket( conn->sock, BIO_NOCLOSE );
  if( FD_UNLIKELY( !bio ) ) {
    return 0;
  }

  SSL * ssl = SSL_new( ssl_ctx );
  if( FD_UNLIKELY( !ssl ) ) {
    BIO_free( bio );
    return 0;
  }

  SSL_set_bio( ssl, bio, bio );
  SSL_set_connect_state( ssl );

  if( FD_UNLIKELY( !SSL_set_tlsext_host_name( ssl, conn->host ) ) ) {
    SSL_free( ssl );
    return 0;
  }

  if( FD_UNLIKELY( !SSL_set1_host( ssl, conn->host ) ) ) {
    SSL_free( ssl );
    return 0;
  }

  SSL_set_verify( ssl, SSL_VERIFY_PEER, NULL );

  if( FD_UNLIKELY( 0!=SSL_set_alpn_protos( ssl, fd_an_conn_alpn_h2,
                                           (uint)sizeof(fd_an_conn_alpn_h2) ) ) ) {
    SSL_free( ssl );
    return 0;
  }

  conn->ssl = ssl;
  return 1;
}


static int
fd_an_conn_alpn_ok( fd_an_conn_t const * conn ) {
  uchar const * alpn    = NULL;
  uint          alpn_sz = 0U;
  SSL_get0_alpn_selected( conn->ssl, &alpn, &alpn_sz );
  return alpn && alpn_sz==2U && alpn[ 0 ]=='h' && alpn[ 1 ]=='2';
}


fd_an_ssl_ctx_t *
fd_an_conn_tls_ctx_new( fd_alloc_t * alloc ) {
  DIR * certs = opendir( "/etc/ssl/certs" );
  if( FD_UNLIKELY( !certs ) ) {
    return NULL;
  }
  closedir( certs );

  fd_ossl_tile_init( alloc );

  SSL_CTX * ssl_ctx = SSL_CTX_new( TLS_client_method() );
  if( FD_UNLIKELY( !ssl_ctx ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !SSL_CTX_set_min_proto_version( ssl_ctx, TLS1_2_VERSION ) ) ) {
    SSL_CTX_free( ssl_ctx );
    return NULL;
  }
  SSL_CTX_set_mode( ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_AUTO_RETRY );
  fd_ossl_load_certs( ssl_ctx );
  return ssl_ctx;
}


void
fd_an_conn_close( fd_an_conn_t * conn ) {
  if( FD_UNLIKELY( !conn ) ) return;

  if( FD_UNLIKELY( conn->ssl ) ) {
    SSL_free( conn->ssl );
    conn->ssl = NULL;
  }

  if( FD_UNLIKELY( conn->sock>=0 ) ) {
    if( FD_UNLIKELY( 0!=close( conn->sock ) ) ) {
    }
    conn->sock = -1;
  }

  conn->state    = FD_AN_CONN_STATE_IDLE;
  conn->reason   = FD_AN_CONN_ERR_NONE;
  conn->err      = 0;
  conn->tls      = FD_AN_CONN_CLEARTEXT;
  conn->ip4      = 0U;
  conn->port     = (ushort)0;
  conn->deadline = LONG_MAX;

  if( FD_LIKELY( conn->grpc ) ) fd_grpc_client_reset( conn->grpc );
}

int
fd_an_conn_start( fd_an_conn_t *    conn,
                  uint              ip4,
                  ushort            port,
                  char const *      host,
                  int               tls,
                  fd_an_ssl_ctx_t * ssl_ctx,
                  char const *      version,
                  ulong             version_len,
                  long              now,
                  long              deadline ) {

  if( FD_UNLIKELY( !conn || conn->magic!=FD_AN_CONN_MAGIC ) ) {
    return FD_AN_CONN_STATE_DEAD;
  }

  fd_an_conn_close( conn );

  if( FD_UNLIKELY( !host || !host[ 0 ] ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, 0 );
  }
  ulong host_len = strlen( host );
  if( FD_UNLIKELY( host_len>=FD_FQDN_BUF_MAX ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, 0 );
  }
  if( FD_UNLIKELY( !version || version_len>FD_GRPC_CLIENT_VERSION_LEN_MAX ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, 0 );
  }
  if( FD_UNLIKELY( !port ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, 0 );
  }
  if( FD_UNLIKELY( !ip4 ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, 0 );
  }
  if( FD_UNLIKELY( tls!=FD_AN_CONN_TLS && tls!=FD_AN_CONN_CLEARTEXT ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, 0 );
  }

  if( FD_UNLIKELY( tls==FD_AN_CONN_TLS && !ssl_ctx ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, 0 );
  }

  memcpy( conn->host, host, host_len );
  conn->host[ host_len ] = '\0';
  conn->host_len         = host_len;
  memcpy( conn->version, version, version_len );
  conn->version[ version_len ] = '\0';
  conn->version_len            = version_len;

  conn->tls      = tls;
  conn->ip4      = ip4;
  conn->port     = port;
  conn->deadline = deadline;
  conn->started  = now;

  fd_grpc_client_set_version  ( conn->grpc, conn->version, conn->version_len );
  fd_grpc_client_set_authority( conn->grpc, conn->host, conn->host_len, port );

  int sock = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( sock<0 ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, errno );
  }
  conn->sock = sock;

  int nodelay = 1;
  if( FD_UNLIKELY( 0!=setsockopt( sock, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(int) ) ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, errno );
  }

  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = ip4,
    .sin_port        = fd_ushort_bswap( port )
  };
  if( connect( sock, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) )==-1 ) {
    int connect_err = errno;
    if( FD_UNLIKELY( connect_err!=EINPROGRESS ) ) {
      FD_LOG_DEBUG(( "allnodes: connect(" FD_IP4_ADDR_FMT ":%hu) failed (%i-%s)",
                    FD_IP4_ADDR_FMT_ARGS( ip4 ), port,
                    connect_err, fd_io_strerror( connect_err ) ));
      return fd_an_conn_die( conn, FD_AN_CONN_ERR_CONNECT, connect_err );
    }
  }

  if( tls==FD_AN_CONN_TLS ) {
    if( FD_UNLIKELY( !fd_an_conn_ssl_open( conn, ssl_ctx ) ) ) {
      return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, 0 );
    }
  }

  FD_LOG_DEBUG(( "allnodes: connecting to %s://" FD_IP4_ADDR_FMT ":%hu (%s)",
                tls==FD_AN_CONN_TLS ? "https" : "http",
                FD_IP4_ADDR_FMT_ARGS( ip4 ), port, conn->host ));

  conn->state = FD_AN_CONN_STATE_CONNECTING;
  return conn->state;
}



static int
fd_an_conn_poll_connect( fd_an_conn_t * conn,
                         int *          charge_busy ) {

  struct pollfd pfd[ 1 ] = { { .fd = conn->sock, .events = POLLOUT } };
  int poll_res = fd_syscall_poll( pfd, 1U, 0 );
  if( FD_UNLIKELY( poll_res<0 ) ) {
    if( FD_LIKELY( errno==EINTR || errno==EAGAIN ) ) return conn->state;
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, errno );
  }
  if( FD_LIKELY( poll_res==0 ) ) return conn->state;

  if( FD_UNLIKELY( !( pfd[ 0 ].revents & (POLLOUT|POLLERR|POLLHUP|POLLNVAL) ) ) ) {
    return conn->state;
  }

  int       so_err    = 0;
  socklen_t so_err_sz = sizeof(so_err);
  if( FD_UNLIKELY( getsockopt( conn->sock, SOL_SOCKET, SO_ERROR, &so_err, &so_err_sz )==-1 ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, errno );
  }
  if( FD_UNLIKELY( so_err ) ) {
    FD_LOG_DEBUG(( "allnodes: connect to " FD_IP4_ADDR_FMT ":%hu failed (%i-%s)",
                  FD_IP4_ADDR_FMT_ARGS( conn->ip4 ), conn->port,
                  so_err, fd_io_strerror( so_err ) ));
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_CONNECT, so_err );
  }

  *charge_busy = 1;

  conn->state = ( conn->tls==FD_AN_CONN_TLS ) ? FD_AN_CONN_STATE_HANDSHAKE
                                              : FD_AN_CONN_STATE_READY;
  return conn->state;
}

static int
fd_an_conn_poll_handshake( fd_an_conn_t * conn,
                           int *          charge_busy ) {

  ERR_clear_error();
  int res = SSL_do_handshake( conn->ssl );
  if( res<=0 ) {
    int ssl_err = SSL_get_error( conn->ssl, res );
    if( FD_LIKELY( ssl_err==SSL_ERROR_WANT_READ || ssl_err==SSL_ERROR_WANT_WRITE ) ) {
      return conn->state;
    }

    long verify = SSL_get_verify_result( conn->ssl );
    if( ssl_err==SSL_ERROR_SSL && verify!=X509_V_OK ) {
      FD_LOG_DEBUG(( "allnodes: certificate verification failed for %s: %s",
                    conn->host, X509_verify_cert_error_string( verify ) ));
    } else {
      FD_LOG_DEBUG(( "allnodes: TLS handshake with %s failed (%i-%s)",
                    conn->host, ssl_err, fd_openssl_ssl_strerror( ssl_err ) ));
    }
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_TLS, ssl_err );
  }

  if( FD_UNLIKELY( !fd_an_conn_alpn_ok( conn ) ) ) {
    FD_LOG_DEBUG(( "allnodes: %s did not negotiate ALPN h2", conn->host ));
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_ALPN, 0 );
  }

  *charge_busy = 1;

  conn->state = FD_AN_CONN_STATE_READY;
  return conn->state;
}

static int
fd_an_conn_poll_ready( fd_an_conn_t * conn,
                       long           now,
                       int *          charge_busy ) {

  int rc;
  if( conn->tls==FD_AN_CONN_TLS ) {
    rc = fd_grpc_client_rxtx_ossl( conn->grpc, conn->ssl, now, charge_busy );
  } else
  {
    rc = fd_grpc_client_rxtx_socket( conn->grpc, conn->sock, now, charge_busy );
  }

  if( FD_UNLIKELY( rc<0 ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_PROTO, errno );
  }

  fd_h2_conn_t const * h2_conn = fd_grpc_client_h2_conn( conn->grpc );
  if( FD_UNLIKELY( h2_conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) {
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_PEER, 0 );
  }

  return conn->state;
}

int
fd_an_conn_poll( fd_an_conn_t * conn,
                 long           now,
                 int *          charge_busy ) {

  if( FD_UNLIKELY( !conn || conn->magic!=FD_AN_CONN_MAGIC ) ) {
    return FD_AN_CONN_STATE_DEAD;
  }

  if( conn->state==FD_AN_CONN_STATE_IDLE || conn->state==FD_AN_CONN_STATE_DEAD ) {
    return conn->state;
  }

  if( FD_UNLIKELY( now>=conn->deadline ) ) {
    FD_LOG_DEBUG(( "allnodes: %s:%hu timed out in state %s after %li ms",
                  conn->host, conn->port, fd_an_conn_strerror( conn->state ),
                  ( now-conn->started )/1000000L ));
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_TIMEOUT, 0 );
  }

  switch( conn->state ) {

  case FD_AN_CONN_STATE_CONNECTING:
    return fd_an_conn_poll_connect( conn, charge_busy );

  case FD_AN_CONN_STATE_HANDSHAKE:
    return fd_an_conn_poll_handshake( conn, charge_busy );

  case FD_AN_CONN_STATE_READY:
    return fd_an_conn_poll_ready( conn, now, charge_busy );

  default:
    return fd_an_conn_die( conn, FD_AN_CONN_ERR_LOCAL, 0 );
  }
}

void
fd_an_conn_set_deadline( fd_an_conn_t * conn,
                         long           deadline ) {
  if( FD_UNLIKELY( !conn ) ) return;
  conn->deadline = deadline;
}

void
fd_an_conn_kill( fd_an_conn_t * conn,
                 int            reason ) {
  if( FD_UNLIKELY( !conn ) ) return;
  fd_an_conn_die( conn, reason, 0 );
}


FD_FN_PURE int
fd_an_conn_state( fd_an_conn_t const * conn ) {
  return conn->state;
}

FD_FN_PURE int
fd_an_conn_reason( fd_an_conn_t const * conn ) {
  return conn->reason;
}

FD_FN_PURE int
fd_an_conn_errno( fd_an_conn_t const * conn ) {
  return conn->err;
}

FD_FN_PURE int
fd_an_conn_fd( fd_an_conn_t const * conn ) {
  return conn->sock;
}

fd_grpc_client_t *
fd_an_conn_grpc( fd_an_conn_t * conn ) {
  return conn->grpc;
}

fd_grpc_client_metrics_t *
fd_an_conn_metrics( fd_an_conn_t * conn ) {
  return conn->metrics;
}

FD_FN_CONST char const *
fd_an_conn_strerror( int state ) {
  switch( state ) {
  case FD_AN_CONN_STATE_IDLE:       return "idle";
  case FD_AN_CONN_STATE_CONNECTING: return "connecting";
  case FD_AN_CONN_STATE_HANDSHAKE:  return "handshake";
  case FD_AN_CONN_STATE_READY:      return "ready";
  case FD_AN_CONN_STATE_DEAD:       return "dead";
  default:                          return "unknown";
  }
}

FD_FN_CONST char const *
fd_an_conn_strreason( int reason ) {
  switch( reason ) {
  case FD_AN_CONN_ERR_NONE:    return "none";
  case FD_AN_CONN_ERR_LOCAL:   return "local";
  case FD_AN_CONN_ERR_CONNECT: return "connect";
  case FD_AN_CONN_ERR_TLS:     return "tls";
  case FD_AN_CONN_ERR_ALPN:    return "alpn";
  case FD_AN_CONN_ERR_PROTO:   return "proto";
  case FD_AN_CONN_ERR_PEER:    return "peer_closed";
  case FD_AN_CONN_ERR_TIMEOUT: return "timeout";
  default:                     return "unknown";
  }
}
