#include "fd_an_consts.h"

#include <string.h>


static fd_an_const_decl_t * fd_an_const_reg[ FD_AN_CONST_MAX ];
static ulong                fd_an_const_reg_cnt;


static fd_an_consts_t const * fd_an_consts_shared;

void
fd_an_const_register( fd_an_const_decl_t * decl ) {
  if( FD_UNLIKELY( !decl || decl->idx!=ULONG_MAX ) ) return;
  if( FD_UNLIKELY( fd_an_const_reg_cnt>=FD_AN_CONST_MAX ) ) return;
  decl->idx = fd_an_const_reg_cnt;
  fd_an_const_reg[ fd_an_const_reg_cnt++ ] = decl;
}

void
fd_an_consts_attach( fd_an_consts_t const * consts ) {
  fd_an_consts_shared = consts;
}

ulong
fd_an_consts_cnt( void ) {
  return fd_an_const_reg_cnt;
}

static fd_an_const_t const *
fd_an_const_slot( fd_an_const_decl_t const * decl ) {
  if( FD_UNLIKELY( !decl || decl->idx>=FD_AN_CONST_MAX || !fd_an_consts_shared ) ) return NULL;
  fd_an_const_t const * slot = fd_an_consts_shared->v + decl->idx;
  return slot->set ? slot : NULL;
}

char const *
fd_an_const_s( fd_an_const_decl_t const * decl ) {
  fd_an_const_t const * slot = fd_an_const_slot( decl );
  if( FD_LIKELY( !slot ) ) return decl ? decl->dflt_s : "";
  return slot->s;
}

ulong
fd_an_const_u( fd_an_const_decl_t const * decl ) {
  fd_an_const_t const * slot = fd_an_const_slot( decl );
  if( FD_LIKELY( !slot ) ) return decl ? decl->dflt_u : 0UL;
  return slot->u;
}

int
fd_an_consts_set( fd_an_consts_t * consts,
                  char const *     name,
                  ulong            name_len,
                  char const *     value,
                  ulong            value_len ) {
  if( FD_UNLIKELY( !consts || !name || !value ) ) return 0;
  if( FD_UNLIKELY( !name_len || value_len>=FD_AN_CONST_VALUE_MAX ) ) return 0;

  for( ulong i=0UL; i<fd_an_const_reg_cnt; i++ ) {
    fd_an_const_decl_t const * decl = fd_an_const_reg[ i ];
    if( strlen( decl->name )!=name_len ) continue;
    if( memcmp( decl->name, name, name_len ) ) continue;

    fd_an_const_t * slot = consts->v + decl->idx;
    if( FD_LIKELY( decl->kind==FD_AN_CONST_KIND_ULONG ) ) {
      if( FD_UNLIKELY( !value_len ) ) return 0;
      ulong u = 0UL;
      for( ulong j=0UL; j<value_len; j++ ) {
        if( FD_UNLIKELY( value[ j ]<'0' || value[ j ]>'9' ) ) return 0;
        if( FD_UNLIKELY( u>(ULONG_MAX-(ulong)( value[ j ]-'0' ))/10UL ) ) return 0;
        u = u*10UL + (ulong)( value[ j ]-'0' );
      }
      slot->u = u;
    } else {
      fd_memcpy( slot->s, value, value_len );
      slot->s[ value_len ] = '\0';
    }
    slot->set = 1;
    return 1;
  }
  return 0;
}
