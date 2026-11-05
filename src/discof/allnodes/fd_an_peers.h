#ifndef HEADER_fd_src_discof_allnodes_fd_an_peers_h
#define HEADER_fd_src_discof_allnodes_fd_an_peers_h


#include "../../util/fd_util_base.h"

#define FD_AN_PEERS_LOOKAHEAD   (7UL)
#define FD_AN_PEERS_MAX         (128UL)
#define FD_AN_PEERS_RETRY_NANOS (2000000000L)
#define FD_AN_PEERS_SLOTS       (2UL*FD_AN_PEERS_MAX)

struct fd_an_sock {
  uint   ip4;
  ushort port;
};

typedef struct fd_an_sock fd_an_sock_t;

struct fd_an_peer {
  fd_an_sock_t sock;
  int          kept;
  long         last_dial;
  void *       conn;
};

typedef struct fd_an_peer fd_an_peer_t;

struct fd_an_peers {
  ulong        kept_cnt;
  fd_an_peer_t peer[ FD_AN_PEERS_SLOTS ];
};

typedef struct fd_an_peers fd_an_peers_t;


struct fd_an_peers_change {
  ulong          close_cnt;
  void *         close[ FD_AN_PEERS_SLOTS ];
  ulong          dial_cnt;
  fd_an_peer_t * dial[ FD_AN_PEERS_MAX ];
};

typedef struct fd_an_peers_change fd_an_peers_change_t;

FD_PROTOTYPES_BEGIN

void
fd_an_peers_init( fd_an_peers_t * peers );


void
fd_an_peers_update( fd_an_peers_t *        peers,
                    fd_an_sock_t const *   wanted,
                    ulong                  wanted_cnt,
                    long                   now,
                    fd_an_peers_change_t * change );


void
fd_an_peers_dialed( fd_an_peer_t * peer,
                    void *         conn,
                    long           now );


void
fd_an_peers_forget( fd_an_peers_t * peers,
                    void *          conn );


void
fd_an_peers_reset( fd_an_peers_t *        peers,
                   fd_an_peers_change_t * change );


FD_FN_PURE void *
fd_an_peers_conn( fd_an_peers_t const * peers,
                  fd_an_sock_t          sock );


FD_FN_PURE ulong
fd_an_peers_conn_cnt( fd_an_peers_t const * peers );

FD_PROTOTYPES_END

#endif
