#include "fd_an_env.h"

#include <string.h>

extern char ** environ;

#define FD_AN_ENV_MAGIC (0xa11d0de5e14b0001UL)

struct fd_an_env {
  ulong magic;
  ulong used;
  ulong dropped;
  char  buf[ FD_AN_ENV_MAX ];
};

ulong
fd_an_env_align( void ) {
  return alignof(fd_an_env_t);
}

ulong
fd_an_env_footprint( void ) {
  return sizeof(fd_an_env_t);
}

fd_an_env_t *
fd_an_env_snapshot( void * mem ) {
  fd_an_env_t * env = mem;
  env->magic   = FD_AN_ENV_MAGIC;
  env->used    = 0UL;
  env->dropped = 0UL;

  if( FD_UNLIKELY( !environ ) ) return env;

  for( char * const * e=environ; *e; e++ ) {
    ulong len = strlen( *e )+1UL;
    if( FD_UNLIKELY( len>FD_AN_ENV_MAX-env->used ) ) { env->dropped++; continue; }
    fd_memcpy( env->buf+env->used, *e, len );
    env->used += len;
  }
  return env;
}

char const *
fd_an_env_get( fd_an_env_t const * env,
               char const *        name ) {
  if( FD_UNLIKELY( !env || env->magic!=FD_AN_ENV_MAGIC || !name || !name[ 0 ] ) ) return NULL;

  ulong name_len = strlen( name );
  for( ulong off=0UL; off<env->used; ) {
    char const * entry = env->buf+off;
    ulong        len   = strlen( entry );
    if( len>name_len && entry[ name_len ]=='=' && !memcmp( entry, name, name_len ) ) {
      char const * value = entry+name_len+1UL;
      return value[ 0 ] ? value : NULL;
    }
    off += len+1UL;
  }
  return NULL;
}

ulong
fd_an_env_dropped( fd_an_env_t const * env ) {
  return env && env->magic==FD_AN_ENV_MAGIC ? env->dropped : 0UL;
}
