
#include "../allnodes/fd_an_shared.h"
#include "../allnodes/fd_an_vote.h"

#include <sys/stat.h>

struct fd_an_tower {
  fd_an_vote_t vote[1];

  int present;
  int configured;

  fd_an_flags_shared_t const * flags;
  int                          resolved;

  char path[ PATH_MAX ];
  int  fd;
  int  open_err;
  int  created;
  int  save_err;

  int  checked;
  long checked_nanos;
  char text[ FD_AN_VOTE_CFG_FILE_MAX ];
};

typedef struct fd_an_tower fd_an_tower_t;

static fd_an_tower_t fd_an_tower[ 1 ] = {{ .fd = -1 }};

static void
fd_an_tower_privileged_init( fd_topo_t const *      topo,
                             fd_topo_tile_t const * tile ) {
  fd_an_tower_t * an = fd_an_tower;
  fd_an_vote_init( an->vote );
  an->fd = -1;
  fd_cstr_ncpy( an->path, FD_AN_VOTE_CFG_PATH_DEFAULT, sizeof(an->path) );

  ulong enabled = fd_pod_query_ulong( topo->props, FD_AN_VOTE_PROP_ENABLED, ULONG_MAX );
  if( FD_UNLIKELY( enabled==ULONG_MAX ) ) return;
  an->present = 1;

  char const * path = fd_pod_query_cstr( topo->props, FD_AN_VOTE_PROP_PATH, "" );
  if( !enabled ) {
    if( FD_UNLIKELY( path[ 0 ] ) ) FD_LOG_ERR(( "[tiles.tower.mostly_confirmed_threshold_config] cannot be used with [tiles.tower.mostly_confirmed_threshold] = false" ));
    return;
  }
  if( path[ 0 ] ) {
    struct stat st;
    if( FD_UNLIKELY( stat( path, &st ) ) ) FD_LOG_ERR(( "[tiles.tower.mostly_confirmed_threshold_config] File not found: %s", path ));
    if( FD_UNLIKELY( !S_ISREG( st.st_mode ) ) ) FD_LOG_ERR(( "[tiles.tower.mostly_confirmed_threshold_config] Must be a file: %s", path ));
    fd_cstr_ncpy( an->path, path, sizeof(an->path) );
  }
  an->configured = 1;

  if( fd_pod_query_ulong( topo->props, FD_AN_SHARED_PROP_FLAGS, ULONG_MAX )==ULONG_MAX ) return;

  an->fd = open( an->path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( an->fd<0 && errno==ENOENT ) ) {
    an->created = 1;
    char  text[ 64 ];
    ulong text_sz = fd_an_vote_cfg_cstr( &an->vote->cfg, text, sizeof(text) );
    int   wfd     = open( an->path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666 );
    if( FD_UNLIKELY( wfd<0 ) ) {
      an->save_err = errno;
    } else {
      if( FD_UNLIKELY( fchown( wfd, tile->tower.target_uid, tile->tower.target_gid ) ) ) an->save_err = errno;
      ulong wsz;
      int   err = fd_io_write( wfd, text, text_sz, text_sz, &wsz );
      if( FD_UNLIKELY( err && !an->save_err ) ) an->save_err = err>0 ? err : EIO;
      if( FD_UNLIKELY( close( wfd ) && !an->save_err ) ) an->save_err = errno;
    }
    an->fd = open( an->path, O_RDONLY|O_CLOEXEC );
  }
  if( FD_UNLIKELY( an->fd<0 ) ) an->open_err = errno;
}


static void
fd_an_tower_check( fd_an_tower_t * an ) {
  if( FD_LIKELY( !an->vote->enable ) ) return;
  long now = fd_log_wallclock();
  if( FD_LIKELY( an->checked && now-an->checked_nanos<FD_AN_VOTE_CFG_CHECK_NANOS ) ) return;
  int first_run = !an->checked;
  an->checked       = 1;
  an->checked_nanos = now;

  FD_LOG_WARNING(( "Checking for change to mostly_confirmed_threshold" ));

  int   created = first_run && an->created;
  int   err     = created ? ENOENT : ( an->fd<0 ? an->open_err : 0 );
  ulong sz      = 0UL;
  while( !err && sz<FD_AN_VOTE_CFG_FILE_MAX ) {
    long r = pread( an->fd, an->text+sz, FD_AN_VOTE_CFG_FILE_MAX-sz, (off_t)sz );
    if( FD_UNLIKELY( r<0L ) ) { if( errno!=EINTR ) err = errno; continue; }
    if( !r ) break;
    sz += (ulong)r;
  }
  if( FD_UNLIKELY( err==ENOENT ) ) {
    FD_LOG_DEBUG(( "File not found: %s", an->path ));
    if( FD_UNLIKELY( created && an->save_err ) ) {
      FD_LOG_WARNING(( "Can not save mostly_confirmed_threshold config to %s: %s (os error %i)", an->path, fd_io_strerror( an->save_err ), an->save_err ));
    }
    return;
  }
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Can not read data from %s: %s (os error %i)", an->path, fd_io_strerror( err ), err ));
    return;
  }
  fd_an_vote_cfg_update( &an->vote->cfg, an->text, sz, an->path, first_run );
}


static void
fd_an_tower_resolve( fd_an_tower_t * an ) {
  if( FD_LIKELY( an->resolved || !an->present ) ) return;
  int   state = FD_AN_FLAGS_NONE;
  ulong word  = 0UL;
  if( FD_LIKELY( an->configured && an->flags ) ) {
    state = fd_an_flags_shared_read( an->flags, &word );
    if( FD_LIKELY( state==FD_AN_FLAGS_PENDING ) ) return;
  }
  an->resolved = 1;

  if( an->configured ) {
    if( FD_LIKELY( state==FD_AN_FLAGS_SET ) ) {
      an->vote->enable = 1;
      an->vote->flags  = word;
    } else {
      FD_LOG_DEBUG(( "Allnodes service hasn't returned any flags" ));
      FD_LOG_WARNING(( "Voting patch is disabled" ));
    }
  }
  fd_an_tower_check( an );

  char cfg[ 1024 ];
  FD_LOG_WARNING(( "Voting patch initialized: VotingPatch { enable: %s, config_path: \"%s\", config: %s }",
                   an->vote->enable ? "true" : "false", an->path, fd_an_vote_cfg_debug( &an->vote->cfg, cfg, sizeof(cfg) ) ));
}

static void
fd_an_tower_join( fd_topo_t const * topo ) {
  fd_an_tower_t * an = fd_an_tower;
  if( FD_UNLIKELY( !an->present ) ) return;
  an->flags = fd_an_flags_shared_join( topo );
  fd_an_tower_resolve( an );
}

static void
fd_an_tower_mark( fd_tower_tile_t * ctx,
                  fd_ghost_blk_t *  ghost_blk,
                  fd_tower_blk_t *  eqvoc_tower_blk ) {
  fd_an_tower_t * an = fd_an_tower;
  fd_an_tower_resolve( an );
  if( FD_UNLIKELY( eqvoc_tower_blk ) ) {
    eqvoc_tower_blk->mostly_confirmed = 0;
    eqvoc_tower_blk->replay_confirmed = 0;
  }
  fd_an_vote_mark( an->vote, ctx->tower, ctx->ghost, ghost_blk, ghost_blk->total_stake );
}

static uchar
fd_an_tower_vote_and_reset( fd_tower_t * tower,
                            fd_ghost_t * ghost,
                            fd_votes_t * votes,
                            ulong *      reset_slot,
                            fd_hash_t *  reset_block_id,
                            ulong *      reset_bank_seq,
                            ulong *      vote_slot,
                            fd_hash_t *  vote_block_id,
                            fd_hash_t *  vote_bank_hash,
                            ulong *      root_slot,
                            fd_hash_t *  root_block_id ) {
  fd_an_tower_t * an = fd_an_tower;
  fd_an_tower_check( an );
  return fd_an_vote_and_reset( an->vote, tower, ghost, votes, reset_slot, reset_block_id, reset_bank_seq,
                               vote_slot, vote_block_id, vote_bank_hash, root_slot, root_block_id );
}


static ulong
fd_an_tower_fds( int * out_fds,
                 ulong out_cnt,
                 ulong out_max ) {
  if( FD_LIKELY( fd_an_tower->fd<0 ) ) return out_cnt;
  if( FD_UNLIKELY( out_cnt>=out_max ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_max ));
  out_fds[ out_cnt++ ] = fd_an_tower->fd;
  return out_cnt;
}

static inline int
fd_an_tower_fd( void ) {
  return fd_an_tower->fd;
}
