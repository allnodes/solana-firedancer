#ifndef HEADER_fd_src_discof_allnodes_fd_an_topo_h
#define HEADER_fd_src_discof_allnodes_fd_an_topo_h


#include "../../disco/topo/fd_topo.h"
#include "../../app/shared/fd_config.h"

FD_PROTOTYPES_BEGIN


void
fd_an_topo_build( fd_topo_t *      topo,
                  config_t const * config );

FD_PROTOTYPES_END

#endif
