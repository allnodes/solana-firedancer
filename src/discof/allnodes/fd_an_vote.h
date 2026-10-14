#ifndef HEADER_fd_src_discof_allnodes_fd_an_vote_h
#define HEADER_fd_src_discof_allnodes_fd_an_vote_h


#include "../../choreo/ghost/fd_ghost.h"
#include "../../choreo/tower/fd_tower.h"


#define FD_AN_VOTE_PROP_ENABLED "allnodes_vote_enabled"
#define FD_AN_VOTE_PROP_PATH    "allnodes_vote_path"
#define FD_AN_VOTE_PROP_UID     "allnodes_vote_uid"
#define FD_AN_VOTE_PROP_GID     "allnodes_vote_gid"

#define FD_AN_VOTE_CFG_PATH_DEFAULT "./mostly_confirmed_threshold"

#define FD_AN_VOTE_CFG_CHECK_NANOS (60L*1000L*1000L*1000L)

#define FD_AN_VOTE_CFG_FILE_MAX (65536UL)

#define FD_AN_VOTE_CHAIN_MAX (8192UL)


struct fd_an_vote_cfg {
  double mostly_confirmed_threshold;
  ulong  threshold_ahead_count;
  ulong  after_skip_threshold;
  ulong  threshold_escape_count;
};

typedef struct fd_an_vote_cfg fd_an_vote_cfg_t;

struct fd_an_vote {
  int              enable;
  ulong            flags;
  fd_an_vote_cfg_t cfg;

  fd_ghost_blk_t * chain[ FD_AN_VOTE_CHAIN_MAX ];
  ulong            stake[ FD_AN_VOTE_CHAIN_MAX ];
  ulong            cand [ FD_AN_VOTE_CHAIN_MAX ];
  ulong            win  [ FD_AN_VOTE_CHAIN_MAX ];
  ulong            slots[ FD_AN_VOTE_CHAIN_MAX ];
};

typedef struct fd_an_vote fd_an_vote_t;

FD_PROTOTYPES_BEGIN


void
fd_an_vote_init( fd_an_vote_t * vote );

void
fd_an_vote_cfg_default( fd_an_vote_cfg_t * cfg );


ulong
fd_an_vote_cfg_cstr( fd_an_vote_cfg_t const * cfg,
                     char *                   buf,
                     ulong                    buf_sz );


char *
fd_an_vote_cfg_debug( fd_an_vote_cfg_t const * cfg,
                      char *                   buf,
                      ulong                    buf_sz );


void
fd_an_vote_cfg_update( fd_an_vote_cfg_t * cfg,
                       char const *       text,
                       ulong              text_sz,
                       char const *       path,
                       int                first_run );


void
fd_an_vote_mark( fd_an_vote_t *   vote,
                 fd_tower_t *     tower,
                 fd_ghost_t *     ghost,
                 fd_ghost_blk_t * blk,
                 ulong            total_stake );


uchar
fd_an_vote_and_reset( fd_an_vote_t * vote,
                      fd_tower_t *   tower,
                      fd_ghost_t *   ghost,
                      fd_votes_t *   votes,
                      ulong *        reset_slot,
                      fd_hash_t *    reset_block_id,
                      ulong *        reset_bank_seq,
                      ulong *        vote_slot,
                      fd_hash_t *    vote_block_id,
                      fd_hash_t *    vote_bank_hash,
                      ulong *        root_slot,
                      fd_hash_t *    root_block_id );

FD_PROTOTYPES_END

#endif
