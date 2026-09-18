#ifndef HEADER_fd_src_discof_allnodes_fd_an_env_h
#define HEADER_fd_src_discof_allnodes_fd_an_env_h


#include "../../util/fd_util_base.h"


#define FD_AN_ENV_MAX (64UL<<10)

struct fd_an_env;
typedef struct fd_an_env fd_an_env_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_an_env_align( void );

FD_FN_CONST ulong
fd_an_env_footprint( void );


fd_an_env_t *
fd_an_env_snapshot( void * mem );


FD_FN_PURE char const *
fd_an_env_get( fd_an_env_t const * env,
               char const *        name );


FD_FN_PURE ulong
fd_an_env_dropped( fd_an_env_t const * env );

FD_PROTOTYPES_END

#endif
