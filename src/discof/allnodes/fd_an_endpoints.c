#include "fd_an_endpoints.h"

#include "../../util/cstr/fd_cstr.h"
#include "../../util/log/fd_log.h"
#include "../../waltz/http/fd_url.h"


FD_STATIC_ASSERT( FD_AN_ENDPOINT_MAX==FD_AN_LOCATION_CNT*FD_AN_PORT_CNT*FD_AN_MIRROR_CNT, endpoint_max );
FD_STATIC_ASSERT( FD_AN_GROUP_MAX==FD_AN_LOCATION_CNT*FD_AN_PORT_CNT, group_max );

char const * const fd_an_locations[ FD_AN_LOCATION_CNT ] = { "ash", "fra", "tyo" };
ushort       const fd_an_ports    [ FD_AN_PORT_CNT     ] = { (ushort)10280, (ushort)20280, (ushort)21280 };


static inline int
an_isspace( char c ) {
  return c==' ' || c=='\t' || c=='\n' || c=='\v' || c=='\f' || c=='\r';
}


static int
an_endpoint_set( fd_an_endpoint_t * ep,
                 char const *       uri,
                 ulong              uri_len,
                 char const *       host,
                 ulong              host_len,
                 ushort             port,
                 int                tls,
                 ulong              group ) {
  if( FD_UNLIKELY( !uri_len  || uri_len >=FD_AN_URI_MAX  ) ) return 0;
  if( FD_UNLIKELY( !host_len || host_len>=FD_AN_HOST_MAX ) ) return 0;

  fd_memcpy( ep->uri, uri, uri_len );
  ep->uri[ uri_len ] = '\0';
  fd_memcpy( ep->host, host, host_len );
  ep->host[ host_len ] = '\0';

  ep->port           = port;
  ep->tls            = !!tls;
  ep->group          = group;
  ep->probed         = 0;
  ep->valid          = 0;
  ep->latency_micros = 0UL;
  ep->capabilities   = 0UL;
  return 1;
}


static ulong
an_endpoints_builtin( fd_an_endpoints_t * eps ) {
  ulong cnt = 0UL;

  for( ulong l=0UL; l<FD_AN_LOCATION_CNT; l++ ) {
    for( ulong p=0UL; p<FD_AN_PORT_CNT; p++ ) {
      for( ulong m=0UL; m<FD_AN_MIRROR_CNT; m++ ) {
        char  host[ FD_AN_HOST_MAX ];
        char  uri [ FD_AN_URI_MAX  ];
        ulong host_len;
        ulong uri_len;

        if( FD_UNLIKELY( !fd_cstr_printf_check( host, FD_AN_HOST_MAX, &host_len,
                                                "solana-server-%s-%lu.allnodes.me",
                                                fd_an_locations[ l ], m+1UL ) ) ) continue;
        if( FD_UNLIKELY( !fd_cstr_printf_check( uri, FD_AN_URI_MAX, &uri_len,
                                                "https://%s:%u",
                                                host, (uint)fd_an_ports[ p ] ) ) ) continue;

        cnt += (ulong)an_endpoint_set( eps->ep+cnt, uri, uri_len, host, host_len,
                                       fd_an_ports[ p ], 1, FD_AN_PORT_CNT*l+p );
      }
    }
  }

  eps->group_cnt = FD_AN_GROUP_MAX;
  return cnt;
}


static ulong
an_endpoints_override( fd_an_endpoints_t * eps,
                       char const *        s,
                       ulong               s_len ) {
  ulong cnt = 0UL;
  ulong i   = 0UL;

  while( i<s_len ) {
    ulong j = i;
    while( j<s_len && s[ j ]!=',' && s[ j ]!=';' ) j++;

    ulong b = i;
    ulong e = j;
    while( b<e && an_isspace( s[ b     ] ) ) b++;
    while( e>b && an_isspace( s[ e-1UL ] ) ) e--;
    i = j+1UL;

    if( b==e ) continue;

    char const * tok     = s+b;
    ulong        tok_len = e-b;

    if( FD_UNLIKELY( cnt>=FD_AN_ENDPOINT_MAX ) ) {
      eps->drop_cnt++;
      continue;
    }

    if( FD_UNLIKELY( tok_len>=FD_AN_URI_MAX ) ) {
      eps->drop_cnt++;
      continue;
    }

    fd_url_t url[1];
    ushort   port[1];
    _Bool    tls [1];
    if( FD_UNLIKELY( fd_url_parse_endpoint( url, tok, tok_len, port, tls, "Allnodes endpoint" ) ) ) {
      eps->drop_cnt++;
      continue;
    }
    if( FD_UNLIKELY( !url->host_len || url->host_len>=FD_AN_HOST_MAX ) ) {
      eps->drop_cnt++;
      continue;
    }

    if( FD_UNLIKELY( !an_endpoint_set( eps->ep+cnt, tok, tok_len,
                                       url->host, url->host_len,
                                       *port, (int)*tls, 0UL ) ) ) {
      eps->drop_cnt++;
      continue;
    }

    if( FD_UNLIKELY( !*tls ) ) {
    }

    cnt++;
  }

  if( FD_UNLIKELY( !cnt && eps->drop_cnt ) ) {
    FD_LOG_WARNING(( "Invalid Allnodes server endpoint overrides: %lu rejected, using the built-in endpoints", eps->drop_cnt ));
  }

  eps->group_cnt = cnt ? 1UL : 0UL;
  return cnt;
}

ulong
fd_an_endpoints_init( fd_an_endpoints_t * eps,
                      char const *        override_cstr ) {
  if( FD_UNLIKELY( !eps ) ) return 0UL;

  fd_memset( eps, 0, sizeof(fd_an_endpoints_t) );
  eps->selected_group = -1L;

  ulong cnt = 0UL;

  if( override_cstr ) {
    ulong len = fd_cstr_nlen( override_cstr, FD_AN_OVERRIDE_MAX+1UL );
    if( FD_UNLIKELY( len>FD_AN_OVERRIDE_MAX ) ) {
      eps->drop_cnt++;
    } else {
      cnt = an_endpoints_override( eps, override_cstr, len );
    }
  }

  if( FD_UNLIKELY( !cnt ) ) cnt = an_endpoints_builtin( eps );

  eps->cnt = cnt;
  return cnt;
}

void
fd_an_endpoints_probe_result( fd_an_endpoints_t * eps,
                              ulong               idx,
                              int                 valid,
                              ulong               latency_micros,
                              ulong               capabilities ) {
  if( FD_UNLIKELY( !eps || idx>=eps->cnt || idx>=FD_AN_ENDPOINT_MAX ) ) return;

  fd_an_endpoint_t * ep = eps->ep + idx;

  if( FD_UNLIKELY( ep->probed ) ) return;

  ep->probed         = 1;
  ep->valid          = !!valid;
  ep->latency_micros = latency_micros;
  ep->capabilities   = capabilities;
}

ulong
fd_an_endpoints_pending( fd_an_endpoints_t const * eps ) {
  if( FD_UNLIKELY( !eps ) ) return 0UL;

  ulong cnt     = fd_ulong_min( eps->cnt, FD_AN_ENDPOINT_MAX );
  ulong pending = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) pending += (ulong)!eps->ep[ i ].probed;
  return pending;
}

ulong
fd_an_endpoints_group_latency( fd_an_endpoints_t const * eps,
                               ulong                     group ) {
  if( FD_UNLIKELY( !eps || group>=eps->group_cnt ) ) return ULONG_MAX;

  ulong cnt  = fd_ulong_min( eps->cnt, FD_AN_ENDPOINT_MAX );
  ulong best = ULONG_MAX;
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_an_endpoint_t const * ep = eps->ep + i;
    if( ep->group!=group || !ep->probed || !ep->valid ) continue;
    best = fd_ulong_min( best, ep->latency_micros );
  }
  return best;
}

int
fd_an_endpoints_select( fd_an_endpoints_t * eps,
                        ulong               elapsed_micros ) {
  if( FD_UNLIKELY( !eps ) ) return 0;

  if( eps->selected_group>=0L ) return 1;

  ulong best_group = ULONG_MAX;
  ulong best_score = ULONG_MAX;
  for( ulong g=0UL; g<eps->group_cnt; g++ ) {
    ulong score = fd_an_endpoints_group_latency( eps, g );
    if( score==ULONG_MAX ) continue;

    if( best_group==ULONG_MAX || score<best_score ) {
      best_group = g;
      best_score = score;
    }
  }

  if( best_group==ULONG_MAX ) return 0;

  if( fd_an_endpoints_pending( eps ) && best_score>elapsed_micros ) return 0;

  eps->selected_group = (long)best_group;
  return 1;
}


static int
an_phase( fd_an_endpoint_t const * ep,
          ulong                    group,
          ulong                    cap_bit ) {
  if( ep->group!=group ) return 2;
  if( !ep->probed      ) return 1;
  if( !ep->valid       ) return 2;

  if( !fd_an_cap_supported( ep->capabilities, cap_bit ) ) return 2;

  return 0;
}

long
fd_an_endpoints_next( fd_an_endpoints_t const * eps,
                      long                      prev,
                      ulong                     cap_bit ) {
  if( FD_UNLIKELY( !eps || eps->selected_group<0L ) ) return -1L;

  ulong cnt   = fd_ulong_min( eps->cnt, FD_AN_ENDPOINT_MAX );
  ulong group = (ulong)eps->selected_group;

  ulong start = 0UL;
  int   phase = 0;

  if( prev>=0L ) {
    if( FD_UNLIKELY( (ulong)prev>=cnt ) ) return -1L;
    start = (ulong)prev + 1UL;
    phase = an_phase( eps->ep+(ulong)prev, group, cap_bit );

    if( phase>1 ) phase = 0;
  }

  for( ; phase<2; phase++ ) {
    for( ulong i=start; i<cnt; i++ ) {
      if( an_phase( eps->ep+i, group, cap_bit )==phase ) return (long)i;
    }
    start = 0UL;
  }

  return -1L;
}
