#ifndef HEADER_fd_src_discof_allnodes_fd_an_endpoints_h
#define HEADER_fd_src_discof_allnodes_fd_an_endpoints_h


#include "../../util/fd_util_base.h"


#define FD_AN_LOCATION_CNT (3UL)
#define FD_AN_PORT_CNT     (3UL)
#define FD_AN_MIRROR_CNT   (3UL)


#define FD_AN_ENDPOINT_MAX (27UL)


#define FD_AN_GROUP_MAX (9UL)


#define FD_AN_URI_MAX  (128UL)
#define FD_AN_HOST_MAX (64UL)


#define FD_AN_OVERRIDE_MAX (4096UL)


#define FD_AN_CAP_MAINNET                 ( 0UL)
#define FD_AN_CAP_GET_BOOTSTRAP_INFO      ( 1UL)
#define FD_AN_CAP_PROCESS_POH_CORE_CONFIG ( 2UL)
#define FD_AN_CAP_RESOLVE_POH_CPU_CORE    ( 3UL)
#define FD_AN_CAP_HEARTBEAT               ( 4UL)
#define FD_AN_CAP_NONE                    (ULONG_MAX)

struct fd_an_endpoint {
  char   uri [ FD_AN_URI_MAX  ];
  char   host[ FD_AN_HOST_MAX ];
  ushort port;
  int    tls;
  ulong  group;
  int    probed;
  int    valid;
  ulong  latency_micros;
  ulong  capabilities;
};

typedef struct fd_an_endpoint fd_an_endpoint_t;


struct fd_an_endpoints {
  fd_an_endpoint_t ep[ FD_AN_ENDPOINT_MAX ];
  ulong            cnt;
  ulong            group_cnt;
  long             selected_group;
  ulong            drop_cnt;
};

typedef struct fd_an_endpoints fd_an_endpoints_t;

FD_PROTOTYPES_BEGIN


extern char const * const fd_an_locations[ FD_AN_LOCATION_CNT ];
extern ushort       const fd_an_ports    [ FD_AN_PORT_CNT     ];


FD_FN_CONST static inline int
fd_an_cap_supported( ulong capabilities,
                     ulong cap_bit ) {
  if( FD_UNLIKELY( cap_bit>=64UL ) ) return 1;
  return (int)( ( capabilities>>cap_bit ) & 1UL );
}


ulong
fd_an_endpoints_init( fd_an_endpoints_t * eps,
                      char const *        override_cstr );


void
fd_an_endpoints_probe_result( fd_an_endpoints_t * eps,
                              ulong               idx,
                              int                 valid,
                              ulong               latency_micros,
                              ulong               capabilities );


int
fd_an_endpoints_select( fd_an_endpoints_t * eps,
                        ulong               elapsed_micros );


FD_FN_PURE long
fd_an_endpoints_next( fd_an_endpoints_t const * eps,
                      long                      prev,
                      ulong                     cap_bit );


FD_FN_PURE ulong
fd_an_endpoints_pending( fd_an_endpoints_t const * eps );


FD_FN_PURE ulong
fd_an_endpoints_group_latency( fd_an_endpoints_t const * eps,
                               ulong                     group );

FD_PROTOTYPES_END

#endif
