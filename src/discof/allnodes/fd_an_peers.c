#include "fd_an_peers.h"

static inline int
sock_eq( fd_an_sock_t a,
         fd_an_sock_t b ) {
  return a.ip4==b.ip4 && a.port==b.port;
}


static inline int
held( fd_an_peer_t const * peer,
      long                 now ) {
  if( peer->last_dial==LONG_MIN ) return 0;
  long since = now - peer->last_dial;
  return since>=0L && since<FD_AN_PEERS_RETRY_NANOS;
}

static inline int
in_use( fd_an_peer_t const * peer ) {
  return peer->kept || peer->last_dial!=LONG_MIN;
}

static fd_an_peer_t *
find( fd_an_peers_t * peers,
      fd_an_sock_t    sock ) {
  for( ulong i=0UL; i<FD_AN_PEERS_SLOTS; i++ ) {
    fd_an_peer_t * peer = &peers->peer[ i ];
    if( in_use( peer ) && sock_eq( peer->sock, sock ) ) return peer;
  }
  return NULL;
}

static int
wanted_has( fd_an_sock_t const * wanted,
            ulong                wanted_cnt,
            fd_an_sock_t         sock ) {
  for( ulong i=0UL; i<wanted_cnt; i++ ) {
    if( sock_eq( wanted[ i ], sock ) ) return 1;
  }
  return 0;
}

void
fd_an_peers_init( fd_an_peers_t * peers ) {
  peers->kept_cnt = 0UL;
  for( ulong i=0UL; i<FD_AN_PEERS_SLOTS; i++ ) {
    peers->peer[ i ] = (fd_an_peer_t){ .last_dial = LONG_MIN };
  }
}

void
fd_an_peers_update( fd_an_peers_t *        peers,
                    fd_an_sock_t const *   wanted,
                    ulong                  wanted_cnt,
                    long                   now,
                    fd_an_peers_change_t * change ) {
  change->close_cnt = 0UL;
  change->dial_cnt  = 0UL;

  for( ulong i=0UL; i<FD_AN_PEERS_SLOTS; i++ ) {
    fd_an_peer_t * peer = &peers->peer[ i ];
    if( !held( peer, now ) ) peer->last_dial = LONG_MIN;
    if( !peer->kept || wanted_has( wanted, wanted_cnt, peer->sock ) ) continue;
    peer->kept = 0;
    peers->kept_cnt--;
    if( peer->conn ) {
      change->close[ change->close_cnt++ ] = peer->conn;
      peer->conn = NULL;
    }
  }

  for( ulong i=0UL; i<wanted_cnt; i++ ) {
    if( wanted_has( wanted, i, wanted[ i ] ) ) continue;

    fd_an_peer_t * peer = find( peers, wanted[ i ] );
    if( peer && held( peer, now ) ) continue;

    if( !peer || !peer->kept ) {
      if( peers->kept_cnt>=FD_AN_PEERS_MAX ) continue;
      if( !peer ) {
        for( ulong j=0UL; j<FD_AN_PEERS_SLOTS; j++ ) {
          if( in_use( &peers->peer[ j ] ) ) continue;
          peer = &peers->peer[ j ];
          peer->sock = wanted[ i ];
          break;
        }
        if( FD_UNLIKELY( !peer ) ) continue;
      }
      peer->kept = 1;
      peers->kept_cnt++;
    }

    if( !peer->conn ) change->dial[ change->dial_cnt++ ] = peer;
  }
}

void
fd_an_peers_dialed( fd_an_peer_t * peer,
                    void *         conn,
                    long           now ) {
  peer->conn      = conn;
  peer->last_dial = now;
}

void
fd_an_peers_forget( fd_an_peers_t * peers,
                    void *          conn ) {
  if( FD_UNLIKELY( !conn ) ) return;
  for( ulong i=0UL; i<FD_AN_PEERS_SLOTS; i++ ) {
    if( peers->peer[ i ].conn==conn ) peers->peer[ i ].conn = NULL;
  }
}

void
fd_an_peers_reset( fd_an_peers_t *        peers,
                   fd_an_peers_change_t * change ) {
  change->close_cnt = 0UL;
  change->dial_cnt  = 0UL;
  for( ulong i=0UL; i<FD_AN_PEERS_SLOTS; i++ ) {
    fd_an_peer_t * peer = &peers->peer[ i ];
    if( peer->conn ) change->close[ change->close_cnt++ ] = peer->conn;
  }
  fd_an_peers_init( peers );
}

void *
fd_an_peers_conn( fd_an_peers_t const * peers,
                  fd_an_sock_t          sock ) {
  for( ulong i=0UL; i<FD_AN_PEERS_SLOTS; i++ ) {
    fd_an_peer_t const * peer = &peers->peer[ i ];
    if( peer->conn && sock_eq( peer->sock, sock ) ) return peer->conn;
  }
  return NULL;
}

ulong
fd_an_peers_conn_cnt( fd_an_peers_t const * peers ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<FD_AN_PEERS_SLOTS; i++ ) cnt += !!peers->peer[ i ].conn;
  return cnt;
}
