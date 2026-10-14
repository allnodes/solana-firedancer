#include "fd_an_vote.h"

#include "../tower/fd_tower_tile.h"
#include "../../ballet/utf8/fd_utf8.h"

#include <float.h>
#include <math.h>
#include <stdlib.h>
#include <strings.h>

#define AN_LIST_MAX  (64UL)
#define AN_LIST_SLOT (22UL)


struct an_vs {
  fd_tower_vote_t v[ FD_TOWER_VOTE_MAX ];
  ulong           cnt;
};

typedef struct an_vs an_vs_t;


static inline ulong
an_bit( ulong flags,
        ulong off ) {
  return ( flags>>off ) & 1UL;
}

static inline ulong
an_value( ulong flags,
          ulong off,
          ulong bits ) {
  return ( flags>>off ) & ( ULONG_MAX>>( 64UL-bits ) );
}

void
fd_an_vote_cfg_default( fd_an_vote_cfg_t * cfg ) {
  cfg->mostly_confirmed_threshold = 0.45;
  cfg->threshold_ahead_count      = 4UL;
  cfg->after_skip_threshold       = 0UL;
  cfg->threshold_escape_count     = 24UL;
}

void
fd_an_vote_init( fd_an_vote_t * vote ) {
  vote->enable = 0;
  vote->flags  = (ulong)( fd_log_wallclock()/1000000L );
  fd_an_vote_cfg_default( &vote->cfg );
}



static char *
an_f64_cstr( double v,
             int    debug,
             char * buf,
             ulong  buf_sz ) {
  if( FD_UNLIKELY( isnan( v ) ) ) { fd_cstr_printf( buf, buf_sz, NULL, "NaN" ); return buf; }
  if( FD_UNLIKELY( isinf( v ) ) ) { fd_cstr_printf( buf, buf_sz, NULL, "%sinf", v<0.0 ? "-" : "" ); return buf; }
  int p = 1;
  for( ; p<DBL_DECIMAL_DIG; p++ ) {
    char tmp[ 64 ];
    fd_cstr_printf( tmp, sizeof(tmp), NULL, "%.*g", p, v );
    if( strtod( tmp, NULL )==v ) break;
  }
  int exp10 = 0;
  if( v!=0.0 ) {
    char tmp[ 64 ];
    fd_cstr_printf( tmp, sizeof(tmp), NULL, "%.*e", p-1, v );
    exp10 = atoi( strchr( tmp, 'e' )+1 );
  }
  int decimals = fd_int_max( 0, p-1-exp10 );
  fd_cstr_printf( buf, buf_sz, NULL, "%.*f", decimals, v );
  if( debug && !strchr( buf, '.' ) ) {
    ulong len = strlen( buf );
    if( len+2UL<buf_sz ) fd_memcpy( buf+len, ".0", 3UL );
  }
  return buf;
}


static int
an_parse_f64( char const * s,
              ulong        n,
              double *     out ) {
  if( FD_UNLIKELY( !n || n>FD_AN_VOTE_CFG_FILE_MAX ) ) return 0;
  ulong i = 0UL;
  if( s[ i ]=='+' || s[ i ]=='-' ) i++;
  ulong rest = n-i;
  static char const * const words[] = { "inf", "infinity", "nan" };
  for( ulong w=0UL; w<3UL; w++ ) {
    if( rest==strlen( words[ w ] ) && !strncasecmp( s+i, words[ w ], rest ) ) {
      double v = w==2UL ? (double)NAN : (double)INFINITY;
      *out = s[ 0 ]=='-' ? -v : v;
      return 1;
    }
  }
  ulong digits = 0UL;
  int   point  = 0;
  for( ; i<n; i++ ) {
    if( s[ i ]>='0' && s[ i ]<='9' ) { digits++; continue; }
    if( s[ i ]=='.' && !point ) { point = 1; continue; }
    break;
  }
  if( FD_UNLIKELY( !digits ) ) return 0;
  if( i<n ) {
    if( s[ i ]!='e' && s[ i ]!='E' ) return 0;
    i++;
    if( i<n && ( s[ i ]=='+' || s[ i ]=='-' ) ) i++;
    ulong exp_digits = 0UL;
    for( ; i<n && s[ i ]>='0' && s[ i ]<='9'; i++ ) exp_digits++;
    if( FD_UNLIKELY( !exp_digits || i<n ) ) return 0;
  }
  static char buf[ FD_AN_VOTE_CFG_FILE_MAX+1UL ];
  fd_memcpy( buf, s, n );
  buf[ n ] = '\0';
  *out = strtod( buf, NULL );
  return 1;
}


static char const *
an_parse_u64( char const * s,
              ulong        n,
              ulong *      out ) {
  if( FD_UNLIKELY( !n ) ) return "cannot parse integer from empty string";
  ulong i = 0UL;
  if( s[ 0 ]=='+' ) {
    i = 1UL;
    if( FD_UNLIKELY( n==1UL ) ) return "invalid digit found in string";
  }
  ulong v = 0UL;
  for( ; i<n; i++ ) {
    if( FD_UNLIKELY( s[ i ]<'0' || s[ i ]>'9' ) ) return "invalid digit found in string";
    ulong d = (ulong)( s[ i ]-'0' );
    if( FD_UNLIKELY( v>( ULONG_MAX-d )/10UL ) ) return "number too large to fit in target type";
    v = v*10UL + d;
  }
  *out = v;
  return NULL;
}

static inline int
an_space( char c ) {
  return c==' ' || c=='\t' || c=='\n' || c=='\v' || c=='\f' || c=='\r';
}


static char *
an_tokens_debug( char *       p,
                 char *       end,
                 char const * text,
                 ulong        sz ) {
#define AN_PUT(c) do { if( p<end ) *p++ = (c); } while(0)
  AN_PUT( '[' );
  int first = 1;
  ulong i = 0UL;
  while( i<sz ) {
    while( i<sz && an_space( text[ i ] ) ) i++;
    if( i>=sz ) break;
    if( !first ) { AN_PUT( ',' ); AN_PUT( ' ' ); }
    first = 0;
    AN_PUT( '"' );
    for( ; i<sz && !an_space( text[ i ] ); i++ ) {
      uchar c = (uchar)text[ i ];
      if( c=='"' || c=='\\' ) { AN_PUT( '\\' ); AN_PUT( (char)c ); }
      else if( !c ) { AN_PUT( '\\' ); AN_PUT( '0' ); }
      else if( c<0x20U || c==0x7fU ) {
        char hex[ 16 ];
        fd_cstr_printf( hex, sizeof(hex), NULL, "\\u{%x}", (uint)c );
        for( char * h=hex; *h; h++ ) AN_PUT( *h );
      }
      else AN_PUT( (char)c );
    }
    AN_PUT( '"' );
  }
  AN_PUT( ']' );
#undef AN_PUT
  return p;
}


static char const *
an_next( char const * text,
         ulong        sz,
         ulong *      off,
         ulong *      len ) {
  ulong i = *off;
  while( i<sz && an_space( text[ i ] ) ) i++;
  if( i>=sz ) { *off = i; return NULL; }
  ulong j = i;
  while( j<sz && !an_space( text[ j ] ) ) j++;
  *off = j;
  *len = j-i;
  return text+i;
}

static void
an_next_f64( char const * text,
             ulong        sz,
             ulong *      off,
             char const * name,
             double *     field,
             double       lo,
             double       hi,
             int          first_run ) {
  ulong        len;
  char const * tok = an_next( text, sz, off, &len );
  if( FD_UNLIKELY( !tok ) ) { FD_LOG_WARNING(( "`%s` wasn't found in config file", name )); return; }
  double v;
  if( FD_UNLIKELY( !an_parse_f64( tok, len, &v ) ) ) {
    FD_LOG_WARNING(( "Unable to parse `%s` from config file: invalid float literal", name ));
    return;
  }
  if( *field==v ) return;
  char vs[ 512 ];
  if( FD_UNLIKELY( !( lo<=v && v<=hi ) ) ) {
    char los[ 64 ]; char his[ 64 ];
    FD_LOG_WARNING(( "Invalid `%s` from config file: %s. Value must be in range: [%s..%s]", name,
                     an_f64_cstr( v, 0, vs, sizeof(vs) ), an_f64_cstr( lo, 0, los, sizeof(los) ), an_f64_cstr( hi, 0, his, sizeof(his) ) ));
    return;
  }
  *field = v;
  if( !first_run ) FD_LOG_WARNING(( "Using new `%s` from config file: %s", name, an_f64_cstr( v, 0, vs, sizeof(vs) ) ));
}

static void
an_next_u64( char const * text,
             ulong        sz,
             ulong *      off,
             char const * name,
             ulong *      field,
             ulong        lo,
             ulong        hi,
             int          first_run ) {
  ulong        len;
  char const * tok = an_next( text, sz, off, &len );
  if( FD_UNLIKELY( !tok ) ) { FD_LOG_WARNING(( "`%s` wasn't found in config file", name )); return; }
  ulong        v;
  char const * err = an_parse_u64( tok, len, &v );
  if( FD_UNLIKELY( err ) ) { FD_LOG_WARNING(( "Unable to parse `%s` from config file: %s", name, err )); return; }
  if( *field==v ) return;
  if( FD_UNLIKELY( v<lo || v>hi ) ) {
    FD_LOG_WARNING(( "Invalid `%s` from config file: %lu. Value must be in range: [%lu..%lu]", name, v, lo, hi ));
    return;
  }
  *field = v;
  if( !first_run ) FD_LOG_WARNING(( "Using new `%s` from config file: %lu", name, v ));
}

ulong
fd_an_vote_cfg_cstr( fd_an_vote_cfg_t const * cfg,
                     char *                   buf,
                     ulong                    buf_sz ) {
  ulong len;
  if( FD_UNLIKELY( !fd_cstr_printf_check( buf, buf_sz, &len, "%.2f %lu %lu %lu", cfg->mostly_confirmed_threshold,
                                          cfg->threshold_ahead_count, cfg->after_skip_threshold, cfg->threshold_escape_count ) ) ) return 0UL;
  return len;
}

char *
fd_an_vote_cfg_debug( fd_an_vote_cfg_t const * cfg,
                      char *                   buf,
                      ulong                    buf_sz ) {
  char a[ 512 ];
  fd_cstr_printf( buf, buf_sz, NULL, "VotingPatchConfig { mostly_confirmed_threshold: %s, threshold_ahead_count: %lu, after_skip_threshold: %lu, threshold_escape_count: %lu }",
                  an_f64_cstr( cfg->mostly_confirmed_threshold, 1, a, sizeof(a) ),
                  cfg->threshold_ahead_count, cfg->after_skip_threshold, cfg->threshold_escape_count );
  return buf;
}

void
fd_an_vote_cfg_update( fd_an_vote_cfg_t * cfg,
                       char const *       text,
                       ulong              text_sz,
                       char const *       path,
                       int                first_run ) {
  if( FD_UNLIKELY( !fd_utf8_verify( text, text_sz ) ) ) {
    FD_LOG_WARNING(( "Can not read data from %s: stream did not contain valid UTF-8", path ));
    return;
  }

  static char data[ 2UL*FD_AN_VOTE_CFG_FILE_MAX+16UL ];
  char * end = an_tokens_debug( data, data+sizeof(data)-1UL, text, text_sz );
  *end = '\0';
  FD_LOG_WARNING(( "mostly_confirmed_threshold data: %s", data ));

  ulong off = 0UL;
  an_next_f64( text, text_sz, &off, "mostly_confirmed_threshold", &cfg->mostly_confirmed_threshold, 0.0, 1.0, first_run );
  an_next_u64( text, text_sz, &off, "threshold_ahead_count",      &cfg->threshold_ahead_count,      0UL, 32UL,  first_run );
  an_next_u64( text, text_sz, &off, "after_skip_threshold",       &cfg->after_skip_threshold,       0UL, 2UL,   first_run );
  an_next_u64( text, text_sz, &off, "threshold_escape_count",     &cfg->threshold_escape_count,     0UL, 128UL, first_run );

  if( first_run ) {
    char dbg[ 1024 ];
    FD_LOG_WARNING(( "Initialized mostly_confirmed_threshold config from file (%s): %s", path, fd_an_vote_cfg_debug( cfg, dbg, sizeof(dbg) ) ));
  }
}


static void
an_vs_load( an_vs_t *               vs,
            fd_tower_vote_t const * votes ) {
  vs->cnt = 0UL;
  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init( votes );
                                  !fd_tower_vote_iter_done( votes, iter );
                            iter = fd_tower_vote_iter_next( votes, iter ) ) {
    vs->v[ vs->cnt++ ] = *fd_tower_vote_iter_ele_const( votes, iter );
  }
}

static void
an_vs_store( an_vs_t const * vs,
             fd_tower_t *    tower ) {
  fd_tower_vote_remove_all( tower->votes );
  for( ulong i=0UL; i<vs->cnt; i++ ) fd_tower_vote_push_tail( tower->votes, vs->v[ i ] );
}

static inline ulong
an_last_locked_out( fd_tower_vote_t const * vote ) {
  return vote->conf>=64UL ? ULONG_MAX : fd_ulong_sat_add( vote->slot, 1UL<<vote->conf );
}

static inline int
an_locked_out_at( fd_tower_vote_t const * vote,
                  ulong                   slot ) {
  return an_last_locked_out( vote )>=slot;
}

static void
an_vs_expire( an_vs_t * vs,
              ulong     slot ) {
  while( vs->cnt && !an_locked_out_at( &vs->v[ vs->cnt-1UL ], slot ) ) vs->cnt--;
}


static ulong
an_vs_push( an_vs_t * vs,
            ulong     slot,
            int       pop_expired ) {
  if( FD_UNLIKELY( vs->cnt && slot<=vs->v[ vs->cnt-1UL ].slot ) ) return ULONG_MAX;
  if( pop_expired ) an_vs_expire( vs, slot );
  ulong root = ULONG_MAX;
  if( vs->cnt==FD_TOWER_VOTE_MAX ) {
    root = vs->v[ 0 ].slot;
    memmove( vs->v, vs->v+1UL, ( FD_TOWER_VOTE_MAX-1UL )*sizeof(fd_tower_vote_t) );
    vs->cnt--;
  }
  vs->v[ vs->cnt++ ] = (fd_tower_vote_t){ .slot = slot, .conf = 1UL };
  for( ulong i=0UL; i<vs->cnt; i++ ) {
    if( vs->cnt>i+vs->v[ i ].conf ) vs->v[ i ].conf++;
  }
  return root;
}

static int
an_is_recent( fd_tower_t const * tower,
              ulong              slot ) {
  if( !fd_tower_vote_empty( tower->votes ) ) return slot>fd_tower_vote_peek_tail_const( tower->votes )->slot;
  if( tower->root!=ULONG_MAX ) return slot>tower->root;
  return 1;
}


static int
an_locked_out( fd_an_vote_t const * vote,
               fd_tower_t *         tower,
               an_vs_t const *      inc,
               ulong                slot ) {
  ulong f = vote->flags;

  if( an_bit( f, 0 ) ^ (ulong)an_is_recent( tower, slot ) ) {
    return (int)an_bit( f, 1 );
  }

  an_vs_t vs[1] = { *inc };
  if( an_bit( f, 2 ) ) an_vs_push( vs, slot, 1 );

  for( ulong i=0UL; i<vs->cnt; i++ ) {
    ulong s = vs->v[ i ].slot;
    if( ( ( (ulong)( slot==s ) ^ an_bit( f, 3 ) ) & ( an_bit( f, 4 ) ^ (ulong)fd_tower_blocks_is_slot_ancestor( tower, slot, s ) ) ) | an_bit( f, 5 ) ) {
      return (int)an_bit( f, 6 );
    }
  }
  return 0;
}


static ulong
an_pop_locked_out_at( fd_an_vote_t const * vote,
                      fd_tower_t const *   tower,
                      ulong const *        new_votes,
                      ulong                cnt,
                      ulong                slot ) {
  an_vs_t vs[1];
  an_vs_load( vs, tower->votes );
  for( ulong i=0UL; i<cnt; i++ ) {
    an_vs_push( vs, new_votes[ i ], 1 );
    if( FD_LIKELY( vs->cnt ) ) {
      if( (ulong)an_locked_out_at( &vs->v[ vs->cnt-1UL ], slot ) ^ an_bit( vote->flags, 7 ) ) return i;
    }
  }
  return cnt;
}


static ulong
an_chain( fd_an_vote_t *   vote,
          fd_tower_t const * tower,
          fd_ghost_t *     ghost,
          fd_ghost_blk_t * blk ) {
  ulong n = 0UL;
  while( blk && n<FD_AN_VOTE_CHAIN_MAX ) {
    if( FD_UNLIKELY( tower->root!=ULONG_MAX && blk->slot<tower->root ) ) break;
    vote->chain[ n++ ] = blk;
    blk = fd_ghost_parent( ghost, blk );
  }
  return n;
}


static inline ulong
an_between( fd_an_vote_t const * vote,
            ulong                n,
            ulong                top,
            ulong                first ) {
  ulong i = top;
  while( i<n && vote->chain[ i ]->slot>=first ) i++;
  return i-top;
}


static int
an_chain_find( fd_an_vote_t const * vote,
               ulong                n,
               ulong                slot,
               ulong *              idx ) {
  ulong lo = 0UL;
  ulong hi = n;
  while( lo<hi ) {
    ulong mid = lo + ( hi-lo )/2UL;
    ulong s   = vote->chain[ mid ]->slot;
    if( s==slot ) { *idx = mid; return 1; }
    if( s>slot ) lo = mid+1UL;
    else         hi = mid;
  }
  return 0;
}

static double
an_duplicate_ratio( void ) {
  static double const ratios[ FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT ] = FD_TOWER_SLOT_CONFIRMED_RATIOS;
  static int    const levels[ FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT ] = FD_TOWER_SLOT_CONFIRMED_LEVELS;
  for( ulong i=0UL; i<FD_TOWER_SLOT_CONFIRMED_LEVEL_CNT; i++ ) {
    if( levels[ i ]==FD_TOWER_SLOT_CONFIRMED_DUPLICATE ) return ratios[ i ];
  }
  FD_LOG_CRIT(( "no duplicate confirmation level" ));
}

void
fd_an_vote_mark( fd_an_vote_t *   vote,
                 fd_tower_t *     tower,
                 fd_ghost_t *     ghost,
                 fd_ghost_blk_t * blk,
                 ulong            total_stake ) {
  if( FD_LIKELY( !vote->enable ) ) return;
  ulong f    = vote->flags;
  ulong slot = blk->slot;
  ulong n    = an_chain( vote, tower, ghost, blk );
  fd_memset( vote->stake, 0, n*sizeof(ulong) );

  int voters = 0;
  for( fd_tower_vtr_iter_t iter = fd_tower_vtr_iter_init( tower->vtrs );
                                 !fd_tower_vtr_iter_done( tower->vtrs, iter );
                           iter = fd_tower_vtr_iter_next( tower->vtrs, iter ) ) {
    fd_tower_vtr_t const * vtr = fd_tower_vtr_iter_ele_const( tower->vtrs, iter );
    if( FD_UNLIKELY( !vtr->stake ) ) continue;
    voters = 1;
    an_vs_t vs[1];
    an_vs_load( vs, vtr->votes );
    if( FD_UNLIKELY( vs->cnt && vs->v[ vs->cnt-1UL ].slot>=slot ) ) continue;
    an_vs_expire( vs, slot );
    if( FD_UNLIKELY( !vs->cnt ) ) continue;
    ulong idx;
    if( FD_LIKELY( an_chain_find( vote, n, vs->v[ vs->cnt-1UL ].slot, &idx ) ) ) vote->stake[ idx ] += vtr->stake;
  }

  double dup   = an_duplicate_ratio();
  ulong  voted = 0UL;
  for( ulong i=0UL; i<n; i++ ) {
    voted += vote->stake[ i ];
    fd_tower_blk_t * tblk = fd_tower_blocks_query( tower, vote->chain[ i ]->slot );
    if( FD_UNLIKELY( !tblk || tblk->replay_confirmed ) ) continue;
    double ratio = (double)voted / (double)total_stake;
    if( ( (ulong)tblk->replayed ^ an_bit( f, 60 ) ) & ( voters ? ( (ulong)( ratio>vote->cfg.mostly_confirmed_threshold ) ^ an_bit( f, 63 ) ) : 0UL ) ) {
      tblk->mostly_confirmed = 1;
    }
    if( ratio>dup ) tblk->replay_confirmed = 1;
  }
}



static ulong
an_last_confirmed_slot( fd_an_vote_t const * vote,
                        fd_tower_t *         tower,
                        ulong                n ) {
  for( ulong i=0UL; i<n; i++ ) {
    fd_tower_blk_t const * tblk = fd_tower_blocks_query( tower, vote->chain[ i ]->slot );
    if( tblk && tblk->confirmed ) return tblk->slot;
  }
  return 0UL;
}


static ulong
an_window( fd_an_vote_t * vote,
           fd_tower_t *   tower,
           ulong          n,
           int *          pop_expired ) {
  ulong f = vote->flags;

  ulong m = 0UL;
  for( ; m<n; m++ ) {
    fd_tower_blk_t const * tblk = fd_tower_blocks_query( tower, vote->chain[ m ]->slot );
    if( tblk && tblk->mostly_confirmed ) break;
  }
  if( m==n ) {
    *pop_expired = (int)an_bit( f, 55 );
    return 0UL;
  }

  int   has_r = !fd_tower_vote_empty( tower->votes );
  ulong r     = has_r ? fd_tower_vote_peek_tail_const( tower->votes )->slot : 0UL;

  ulong cand_cnt = 0UL;
  if( has_r && m+1UL<n ) {
    ulong cnt = an_between( vote, n, m+1UL, r + an_bit( f, 8 ) );
    for( ulong i=0UL; i<cnt; i++ ) vote->cand[ cand_cnt++ ] = m+cnt-i;
  }

  {
    ulong cnt  = an_between( vote, n, 0UL, vote->chain[ m ]->slot + an_bit( f, 9 ) );
    ulong take = fd_ulong_min( cnt, vote->cfg.threshold_ahead_count + an_bit( f, 27 ) );
    for( ulong i=0UL; i<take; i++ ) vote->cand[ cand_cnt++ ] = cnt-1UL-i;
  }

  an_vs_t inc[1];
  an_vs_load( inc, tower->votes );
  ulong win_cnt  = 0UL;
  ulong slot_cnt = 0UL;
  for( ulong c=0UL; c<cand_cnt; c++ ) {
    fd_ghost_blk_t const * blk  = vote->chain[ vote->cand[ c ] ];
    ulong                  slot = blk->slot;
    if( slot<=( has_r ? r : an_bit( f, 10 ) ) + an_bit( f, 11 ) ) continue;
    if( an_locked_out( vote, tower, inc, slot ) ) {
      FD_LOG_INFO(( "vote-optimizer cannot vote on %lu because it's locked out", slot ));
      continue;
    }
    fd_tower_blk_t const * tblk = fd_tower_blocks_query( tower, slot );
    if( vote->cfg.after_skip_threshold && tblk && slot>tblk->parent_slot+1UL ) {
      int confirmed_enough = vote->cfg.after_skip_threshold==1UL ? tblk->mostly_confirmed : tblk->confirmed;
      if( !confirmed_enough ) {
        FD_LOG_DEBUG(( "vote-optimizer not voting on %lu or later slots: first slot after a skip has not reached the after-skip threshold", slot ));
        break;
      }
    }
    vote->win[ win_cnt++ ] = vote->cand[ c ];
    if( win_cnt==an_value( f, 12UL, 6UL ) ) break;
    vote->slots[ slot_cnt++ ] = slot;
    an_vs_push( inc, slot, 1 );
  }

  if( win_cnt ) {
    ulong first_slot_to_not_lock_out = an_last_confirmed_slot( vote, tower, n ) + an_value( f, 20UL, 7UL );
    slot_cnt = an_pop_locked_out_at( vote, tower, vote->slots, slot_cnt, first_slot_to_not_lock_out );
    if( win_cnt>slot_cnt+an_bit( f, 29 ) ) {
      FD_LOG_INFO(( "vote-optimizer cannot vote on %lu or subsequent slots because lockout would exceed slot %lu",
                    vote->chain[ vote->win[ slot_cnt ] ]->slot, first_slot_to_not_lock_out-1UL ));
      win_cnt = slot_cnt;
    }
  }

  if( !win_cnt ) {
    if( has_r ) {
      ulong cnt = an_between( vote, n, 0UL, r + an_bit( f, 30 ) );
      an_vs_load( inc, tower->votes );
      ulong unvoted_cnt = 0UL;
      for( ulong i=0UL; i<cnt; i++ ) {
        ulong idx = cnt-1UL-i;
        ulong s   = vote->chain[ idx ]->slot;
        if( !an_locked_out( vote, tower, inc, s ) ) {
          if( !unvoted_cnt ) vote->win[ 0 ] = idx;
          unvoted_cnt++;
          an_vs_push( inc, s, 1 );
        }
      }
      if( unvoted_cnt && unvoted_cnt+an_bit( f, 35 )>vote->cfg.threshold_escape_count ) {
        FD_LOG_INFO(( "vote-optimizer voting on escape slot %lu", vote->chain[ vote->win[ 0 ] ]->slot ));
        win_cnt = 1UL;
      }
    } else {
      FD_LOG_INFO(( "vote-optimizer never voted, so voting on %lu", vote->chain[ 0 ]->slot ));
      vote->win[ 0 ] = 0UL;
      win_cnt = 1UL;
    }
  }

  if( win_cnt ) {
    ulong last = vote->chain[ vote->win[ win_cnt-1UL ] ]->slot;
    while( !fd_tower_vote_empty( tower->votes ) ) {
      ulong s = fd_tower_vote_peek_tail_const( tower->votes )->slot;
      if( fd_tower_blocks_is_slot_ancestor( tower, last, s ) ) break;
      FD_LOG_INFO(( "vote-optimizer purged %lu", s ));
      fd_tower_vote_pop_tail( tower->votes );
    }
  }

  *pop_expired = (int)an_bit( f, 38 );
  return win_cnt;
}

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
                      fd_hash_t *    root_block_id ) {
  if( FD_LIKELY( !vote->enable ) ) {
    return fd_tower_vote_and_reset( tower, ghost, votes, reset_slot, reset_block_id, reset_bank_seq,
                                    vote_slot, vote_block_id, vote_bank_hash, root_slot, root_block_id );
  }

  fd_ghost_blk_t * best      = fd_ghost_best( ghost, fd_ghost_root( ghost ) );
  fd_tower_blk_t * best_tblk = fd_tower_blocks_query( tower, best->slot );
  FD_TEST( best_tblk );
  int       best_voted    = best_tblk->voted;
  fd_hash_t best_voted_id = best_tblk->voted_block_id;
  an_vs_t   saved[1];
  an_vs_load( saved, tower->votes );

  uchar flags = fd_tower_vote_and_reset( tower, ghost, votes, reset_slot, reset_block_id, reset_bank_seq,
                                         vote_slot, vote_block_id, vote_bank_hash, root_slot, root_block_id );
  if( FD_LIKELY( *vote_slot==ULONG_MAX ) ) return flags;
  FD_TEST( *vote_slot==best->slot );

  an_vs_store( saved, tower );
  best_tblk->voted          = best_voted;
  best_tblk->voted_block_id = best_voted_id;
  *vote_slot      = ULONG_MAX;
  *vote_block_id  = (fd_hash_t){0};
  *vote_bank_hash = (fd_hash_t){0};
  *root_slot      = ULONG_MAX;
  *root_block_id  = (fd_hash_t){0};

  ulong n = an_chain( vote, tower, ghost, best );
  int   pop_expired;
  ulong win_cnt = an_window( vote, tower, n, &pop_expired );
  if( FD_UNLIKELY( !win_cnt ) ) return flags;

  an_vs_t vs[1];
  an_vs_load( vs, tower->votes );
  char   list[ AN_LIST_MAX*AN_LIST_SLOT+8UL ];
  char * p = fd_cstr_init( list );
  p = fd_cstr_append_char( p, '[' );
  for( ulong i=0UL; i<win_cnt; i++ ) {
    fd_ghost_blk_t const * blk = vote->chain[ vote->win[ i ] ];
    if( FD_UNLIKELY( vs->cnt && blk->slot<=vs->v[ vs->cnt-1UL ].slot ) ) {
      FD_LOG_CRIT(( "vote %lu is not newer than the tower's last vote %lu", blk->slot, vs->v[ vs->cnt-1UL ].slot ));
    }
    ulong root = an_vs_push( vs, blk->slot, pop_expired );
    if( FD_UNLIKELY( root!=ULONG_MAX ) ) *root_slot = root;
    fd_tower_blk_t * tblk = fd_tower_blocks_query( tower, blk->slot );
    FD_TEST( tblk );
    tblk->voted          = 1;
    tblk->voted_block_id = blk->id;
    if( FD_LIKELY( i<AN_LIST_MAX ) ) p = fd_cstr_append_printf( p, "%s%lu", i ? ", " : "", blk->slot );
  }
  p = fd_cstr_append_char( p, ']' );
  fd_cstr_fini( p );
  an_vs_store( vs, tower );

  FD_LOG_INFO(( "voting for window: %s", list ));

  fd_ghost_blk_t const * last      = vote->chain[ vote->win[ win_cnt-1UL ] ];
  fd_tower_blk_t const * last_tblk = fd_tower_blocks_query( tower, last->slot );
  *vote_slot      = last->slot;
  *vote_block_id  = last->id;
  *vote_bank_hash = last_tblk->bank_hash;
  if( FD_UNLIKELY( *root_slot!=ULONG_MAX ) ) {
    fd_tower_blk_t const * root_tblk = fd_tower_blocks_query( tower, *root_slot );
    FD_TEST( root_tblk );
    *root_block_id = *fd_ptr_if( root_tblk->confirmed, &root_tblk->confirmed_block_id, &root_tblk->voted_block_id );
  }
  return flags;
}
