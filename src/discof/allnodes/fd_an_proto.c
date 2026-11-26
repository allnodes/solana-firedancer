#include "fd_an_proto.h"

#include "../../ballet/pb/fd_pb_encode.h"
#include "../../ballet/pb/fd_pb_tokenize.h"
#include "../../util/net/fd_ip4.h"

#include <string.h>


#define AN_REQ_SHRED_VERSION  (1U)

#define AN_HB_IDENTITY        (1U)
#define AN_HB_SLOT            (2U)
#define AN_HB_SIGNATURE       (3U)

#define AN_RESP_NODE          (1U)
#define AN_RESP_FLAGS         (2U)
#define AN_RESP_CONSTANTS     (4U)

#define AN_CONST_NAME         (1U)
#define AN_CONST_VALUE        (2U)
#define AN_CONST_PERSISTENT   (3U)

#define AN_NODE_RPC           (1U)
#define AN_NODE_PUBKEY        (2U)
#define AN_NODE_SNAPSHOT_HASH (3U)
#define AN_NODE_LATENCY       (4U)

#define AN_SVC_SHRED_VERSION  (1U)
#define AN_SVC_CAPABILITIES   (2U)
#define AN_SVC_VERSION        (3U)

#define AN_HB_RESP_ROUTES     (1U)

#define AN_ROUTE_RANGE        (1U)
#define AN_ROUTE_FLAGS        (2U)
#define AN_ROUTE_TARGETS      (3U)


#define AN_RANGE_SZ                  (6UL)
#define AN_TARGET_RELATIVE_MAX       (0x03)
#define AN_TARGET_RELATIVE_SZ        (2UL)
#define AN_TARGET_ABSOLUTE           (0x80)
#define AN_TARGET_ABSOLUTE_SECONDARY (0x81)
#define AN_TARGET_ABSOLUTE_SZ        (7UL)


#define AN_HASH_FULL_SLOT_OFF (0UL)
#define AN_HASH_FULL_HASH_OFF (8UL)
#define AN_HASH_INCR_SLOT_OFF (40UL)
#define AN_HASH_INCR_HASH_OFF (48UL)


static int
an_field_bytes( fd_pb_inbuf_t *     buf,
                fd_pb_tlv_t const * tlv,
                uchar const **      out,
                ulong *             out_sz ) {
  if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_LEN ) ) return 0;
  if( FD_UNLIKELY( tlv->len>fd_pb_inbuf_sz( buf )      ) ) return 0;
  *out    = buf->cur;
  *out_sz = tlv->len;
  fd_pb_inbuf_skip( buf, tlv->len );
  return 1;
}


static int
an_field_skip( fd_pb_inbuf_t *     buf,
               fd_pb_tlv_t const * tlv ) {
  if( tlv->wire_type!=FD_PB_WIRE_TYPE_LEN ) return 1;
  if( FD_UNLIKELY( tlv->len>fd_pb_inbuf_sz( buf ) ) ) return 0;
  fd_pb_inbuf_skip( buf, tlv->len );
  return 1;
}

ulong
fd_an_proto_encode_bootstrap_req( uchar * buf,
                                  ulong   buf_sz,
                                  uint    shred_version ) {
  if( FD_UNLIKELY( buf_sz<64UL ) ) return 0UL;

  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, buf, buf_sz );
  if( FD_UNLIKELY( !fd_pb_push_uint32( enc, AN_REQ_SHRED_VERSION, shred_version ) ) ) {
    fd_pb_encoder_fini( enc );
    return 0UL;
  }
  ulong sz = fd_pb_encoder_out_sz( enc );
  fd_pb_encoder_fini( enc );
  return sz;
}

ulong
fd_an_proto_encode_heartbeat_req( uchar *       buf,
                                  ulong         buf_sz,
                                  uchar const * identity,
                                  ulong         slot,
                                  uchar const * signature ) {
  if( FD_UNLIKELY( buf_sz<FD_AN_PROTO_HEARTBEAT_REQ_BUF_SZ ) ) return 0UL;

  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, buf, buf_sz );
  int ok = !!fd_pb_push_bytes ( enc, AN_HB_IDENTITY,  identity,  32UL ) &&
           !!fd_pb_push_uint64( enc, AN_HB_SLOT,      slot            ) &&
           !!fd_pb_push_bytes ( enc, AN_HB_SIGNATURE, signature, 64UL );
  ulong sz = ok ? fd_pb_encoder_out_sz( enc ) : 0UL;
  fd_pb_encoder_fini( enc );
  return sz;
}

int
fd_an_proto_decode_service_info( fd_an_service_info_t * out,
                                 uchar const *          msg,
                                 ulong                  msg_sz ) {
  fd_an_service_info_t info = {0};

  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, msg, msg_sz );

  fd_pb_tlv_t tlv[1];
  while( fd_pb_inbuf_sz( buf ) ) {
    if( FD_UNLIKELY( !fd_pb_read_tlv( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;

    switch( tlv->field_id ) {

    case AN_SVC_SHRED_VERSION:
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return FD_AN_PROTO_ERR_DECODE;
      if( FD_UNLIKELY( tlv->varint>UINT_MAX                   ) ) return FD_AN_PROTO_ERR_DECODE;
      info.shred_version = (uint)tlv->varint;
      break;

    case AN_SVC_CAPABILITIES:
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return FD_AN_PROTO_ERR_DECODE;
      info.capabilities = tlv->varint;
      break;

    case AN_SVC_VERSION: {
      uchar const * ver;
      ulong         ver_sz;
      if( FD_UNLIKELY( !an_field_bytes( buf, tlv, &ver, &ver_sz ) ) ) return FD_AN_PROTO_ERR_DECODE;
      ulong n = fd_ulong_min( ver_sz, FD_AN_PROTO_VERSION_MAX-1UL );
      for( ulong i=0UL; i<n; i++ ) {
        uchar c = ver[ i ];
        info.version[ i ] = (char)fd_uchar_if( c>=0x20 && c<0x7f, c, (uchar)'.' );
      }
      info.version[ n ] = '\0';
      break;
    }

    default:
      if( FD_UNLIKELY( !an_field_skip( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;
      break;
    }
  }

  *out = info;
  return FD_AN_PROTO_OK;
}


static int
an_decode_node( fd_an_snapshot_node_t * out,
                uchar const *           msg,
                ulong                   msg_sz ) {
  fd_an_snapshot_node_t node = {0};
  int have_rpc = 0, have_pubkey = 0, have_hash = 0;

  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, msg, msg_sz );

  fd_pb_tlv_t tlv[1];
  while( fd_pb_inbuf_sz( buf ) ) {
    if( FD_UNLIKELY( !fd_pb_read_tlv( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;

    switch( tlv->field_id ) {

    case AN_NODE_RPC: {
      uchar const * addr;
      ulong         addr_sz;
      if( FD_UNLIKELY( !an_field_bytes( buf, tlv, &addr, &addr_sz ) ) ) return FD_AN_PROTO_ERR_DECODE;
      if( addr_sz==FD_AN_PROTO_SOCKADDR_V6_SZ && addr[ 0 ]==1 ) return FD_AN_PROTO_ERR_IPV6;
      if( FD_UNLIKELY( addr_sz!=FD_AN_PROTO_SOCKADDR_V4_SZ || addr[ 0 ]!=0 ) ) return FD_AN_PROTO_ERR_DECODE;
      node.ip4  = FD_IP4_ADDR( addr[ 1 ], addr[ 2 ], addr[ 3 ], addr[ 4 ] );
      node.port = fd_ushort_load_2( addr+5 );
      have_rpc  = 1;
      break;
    }

    case AN_NODE_PUBKEY: {
      uchar const * pk;
      ulong         pk_sz;
      if( FD_UNLIKELY( !an_field_bytes( buf, tlv, &pk, &pk_sz ) ) ) return FD_AN_PROTO_ERR_DECODE;
      if( FD_UNLIKELY( pk_sz!=sizeof(node.pubkey)              ) ) return FD_AN_PROTO_ERR_DECODE;
      memcpy( node.pubkey, pk, sizeof(node.pubkey) );
      have_pubkey = 1;
      break;
    }

    case AN_NODE_SNAPSHOT_HASH: {
      uchar const * h;
      ulong         h_sz;
      if( FD_UNLIKELY( !an_field_bytes( buf, tlv, &h, &h_sz )   ) ) return FD_AN_PROTO_ERR_DECODE;
      if( FD_UNLIKELY( h_sz!=FD_AN_PROTO_SNAPSHOT_HASH_SZ       ) ) return FD_AN_PROTO_ERR_DECODE;
      node.full_slot = fd_ulong_load_8( h+AN_HASH_FULL_SLOT_OFF );
      memcpy( node.full_hash, h+AN_HASH_FULL_HASH_OFF, sizeof(node.full_hash) );
      node.incr_slot = fd_ulong_load_8( h+AN_HASH_INCR_SLOT_OFF );
      memcpy( node.incr_hash, h+AN_HASH_INCR_HASH_OFF, sizeof(node.incr_hash) );
      have_hash = 1;
      break;
    }

    case AN_NODE_LATENCY:
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return FD_AN_PROTO_ERR_DECODE;
      node.latency_micros = tlv->varint;
      break;

    default:
      if( FD_UNLIKELY( !an_field_skip( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;
      break;
    }
  }

  if( FD_UNLIKELY( !have_rpc || !have_pubkey || !have_hash ) ) return FD_AN_PROTO_ERR_DECODE;

  int incr_hash_set = 0;
  for( ulong i=0UL; i<sizeof(node.incr_hash); i++ ) incr_hash_set |= !!node.incr_hash[ i ];
  node.has_incremental = incr_hash_set && node.incr_slot>node.full_slot;

  *out = node;
  return FD_AN_PROTO_OK;
}


static int
an_decode_const( fd_an_proto_const_t * out,
                 uchar const *         msg,
                 ulong                 msg_sz ) {
  fd_an_proto_const_t c = {0};

  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, msg, msg_sz );

  fd_pb_tlv_t tlv[1];
  while( fd_pb_inbuf_sz( buf ) ) {
    if( FD_UNLIKELY( !fd_pb_read_tlv( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;

    switch( tlv->field_id ) {

    case AN_CONST_NAME:
      if( FD_UNLIKELY( !an_field_bytes( buf, tlv, &c.name, &c.name_sz ) ) ) return FD_AN_PROTO_ERR_DECODE;
      break;

    case AN_CONST_VALUE:
      if( FD_UNLIKELY( !an_field_bytes( buf, tlv, &c.value, &c.value_sz ) ) ) return FD_AN_PROTO_ERR_DECODE;
      break;

    case AN_CONST_PERSISTENT:
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return FD_AN_PROTO_ERR_DECODE;
      break;

    default:
      if( FD_UNLIKELY( !an_field_skip( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;
      break;
    }
  }

  *out = c;
  return FD_AN_PROTO_OK;
}


static int
an_field_const( fd_pb_inbuf_t *       buf,
                fd_pb_tlv_t const *   tlv,
                fd_an_proto_const_t * out ) {
  uchar const * sub;
  ulong         sub_sz;
  return an_field_bytes( buf, tlv, &sub, &sub_sz ) && an_decode_const( out, sub, sub_sz )==FD_AN_PROTO_OK;
}

int
fd_an_proto_decode_bootstrap( fd_an_snapshot_node_t * out,
                              uchar const *           msg,
                              ulong                   msg_sz ) {
  fd_an_snapshot_node_t node = {0};
  int have_node = 0;

  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, msg, msg_sz );

  fd_pb_tlv_t tlv[1];
  while( fd_pb_inbuf_sz( buf ) ) {
    if( FD_UNLIKELY( !fd_pb_read_tlv( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;

    if( tlv->field_id==AN_RESP_NODE ) {
      uchar const * sub;
      ulong         sub_sz;
      if( FD_UNLIKELY( !an_field_bytes( buf, tlv, &sub, &sub_sz ) ) ) return FD_AN_PROTO_ERR_DECODE;
      int err = an_decode_node( &node, sub, sub_sz );
      if( FD_UNLIKELY( err!=FD_AN_PROTO_OK ) ) return err;
      have_node = 1;
    } else if( tlv->field_id==AN_RESP_CONSTANTS ) {
      fd_an_proto_const_t c;
      if( FD_UNLIKELY( !an_field_const( buf, tlv, &c ) ) ) return FD_AN_PROTO_ERR_DECODE;
    } else if( tlv->field_id==AN_RESP_FLAGS ) {
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return FD_AN_PROTO_ERR_DECODE;
    } else {
      if( FD_UNLIKELY( !an_field_skip( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;
    }
  }

  if( FD_UNLIKELY( !have_node ) ) return FD_AN_PROTO_ERR_NO_NODE;

  *out = node;
  return FD_AN_PROTO_OK;
}

int
fd_an_proto_decode_flags( ulong *       out,
                          uchar const * msg,
                          ulong         msg_sz ) {
  ulong flags = 0UL;

  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, msg, msg_sz );

  fd_pb_tlv_t tlv[1];
  while( fd_pb_inbuf_sz( buf ) ) {
    if( FD_UNLIKELY( !fd_pb_read_tlv( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;
    if( tlv->field_id==AN_RESP_FLAGS ) {
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return FD_AN_PROTO_ERR_DECODE;
      flags = tlv->varint;
    } else {
      if( FD_UNLIKELY( !an_field_skip( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;
    }
  }

  *out = flags;
  return FD_AN_PROTO_OK;
}


static int
an_decode_constants( fd_an_proto_const_t * out,
                     ulong *               out_cnt,
                     uchar const *         msg,
                     ulong                 msg_sz ) {
  ulong cnt = 0UL;
  if( FD_UNLIKELY( !msg_sz ) ) { *out_cnt = 0UL; return FD_AN_PROTO_OK; }

  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, msg, msg_sz );

  fd_pb_tlv_t tlv[1];
  while( fd_pb_inbuf_sz( buf ) ) {
    if( FD_UNLIKELY( !fd_pb_read_tlv( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;

    if( tlv->field_id!=AN_RESP_CONSTANTS ) {
      if( FD_UNLIKELY( !an_field_skip( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;
      continue;
    }

    fd_an_proto_const_t c;
    if( FD_UNLIKELY( !an_field_const( buf, tlv, &c ) ) ) return FD_AN_PROTO_ERR_DECODE;
    if( out && cnt<FD_AN_PROTO_CONSTS_MAX ) out[ cnt ] = c;
    cnt++;
  }

  *out_cnt = fd_ulong_min( cnt, FD_AN_PROTO_CONSTS_MAX );
  return FD_AN_PROTO_OK;
}

int
fd_an_proto_decode_constants( fd_an_proto_const_t * out,
                              ulong *               out_cnt,
                              uchar const *         msg,
                              ulong                 msg_sz ) {
  ulong cnt;
  int   err = an_decode_constants( NULL, &cnt, msg, msg_sz );
  if( FD_UNLIKELY( err!=FD_AN_PROTO_OK ) ) return err;
  return an_decode_constants( out, out_cnt, msg, msg_sz );
}


static ulong
an_decode_targets( uchar const *    blob,
                   ulong            blob_sz,
                   fd_an_target_t * out ) {
  ulong cnt = 0UL;
  ulong off = 0UL;
  while( off<blob_sz ) {
    uchar          tag  = blob[ off ];
    ulong          left = blob_sz-off;
    fd_an_target_t t    = {0};
    if( tag<=AN_TARGET_RELATIVE_MAX ) {
      if( FD_UNLIKELY( left<AN_TARGET_RELATIVE_SZ ) ) break;
      t.relative  = 1;
      t.port_type = tag;
      t.secondary = (uchar)!!blob[ off+1UL ];
      off += AN_TARGET_RELATIVE_SZ;
    } else if( tag==AN_TARGET_ABSOLUTE || tag==AN_TARGET_ABSOLUTE_SECONDARY ) {
      if( FD_UNLIKELY( left<AN_TARGET_ABSOLUTE_SZ ) ) break;
      uchar const * e = blob+off+1UL;
      t.secondary = (uchar)( tag==AN_TARGET_ABSOLUTE_SECONDARY );
      t.ip4       = FD_IP4_ADDR( e[ 0 ], e[ 1 ], e[ 2 ], e[ 3 ] );
      t.port      = (ushort)( ( (uint)e[ 4 ]<<8 ) | (uint)e[ 5 ] );
      off += AN_TARGET_ABSOLUTE_SZ;
    } else {
      break;
    }
    if( out ) out[ cnt ] = t;
    cnt++;
  }
  return cnt;
}


struct an_route_wire {
  uchar const * range;
  ulong         range_sz;
  ulong         flags;
  uchar const * targets;
  ulong         targets_sz;
};

typedef struct an_route_wire an_route_wire_t;

static int
an_decode_route( an_route_wire_t * out,
                 uchar const *     msg,
                 ulong             msg_sz ) {
  an_route_wire_t route = {0};

  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, msg, msg_sz );

  fd_pb_tlv_t tlv[1];
  while( fd_pb_inbuf_sz( buf ) ) {
    if( FD_UNLIKELY( !fd_pb_read_tlv( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;

    switch( tlv->field_id ) {

    case AN_ROUTE_RANGE:
      if( FD_UNLIKELY( !an_field_bytes( buf, tlv, &route.range, &route.range_sz ) ) ) return FD_AN_PROTO_ERR_DECODE;
      break;

    case AN_ROUTE_FLAGS:
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return FD_AN_PROTO_ERR_DECODE;
      route.flags = tlv->varint;
      break;

    case AN_ROUTE_TARGETS:
      if( FD_UNLIKELY( !an_field_bytes( buf, tlv, &route.targets, &route.targets_sz ) ) ) return FD_AN_PROTO_ERR_DECODE;
      break;

    default:
      if( FD_UNLIKELY( !an_field_skip( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;
      break;
    }
  }

  *out = route;
  return FD_AN_PROTO_OK;
}


static void
an_route_add( fd_an_routes_t *        out,
              an_route_wire_t const * wire,
              int *                   full ) {
  if( FD_UNLIKELY( *full || wire->range_sz!=AN_RANGE_SZ ) ) {
    out->dropped++;
    return;
  }

  ulong from = (ulong)fd_uint_bswap  ( FD_LOAD( uint,   wire->range      ) );
  ulong to   = from + (ulong)fd_ushort_bswap( FD_LOAD( ushort, wire->range+4UL ) );
  if( FD_UNLIKELY( out->route_cnt && from<=out->route[ out->route_cnt-1UL ].slot_to ) ) {
    out->dropped++;
    return;
  }

  ulong cnt = an_decode_targets( wire->targets, wire->targets_sz, NULL );
  if( FD_UNLIKELY( out->route_cnt==FD_AN_ROUTES_MAX || cnt>FD_AN_TARGETS_MAX-out->target_cnt ) ) {
    *full = 1;
    out->dropped++;
    return;
  }

  an_decode_targets( wire->targets, wire->targets_sz, out->target+out->target_cnt );
  out->route[ out->route_cnt++ ] = (fd_an_route_t){
    .slot_from  = from,
    .slot_to    = to,
    .flags      = wire->flags,
    .target_off = (uint)out->target_cnt,
    .target_cnt = (uint)cnt
  };
  out->target_cnt += cnt;
}


static int
an_decode_routes( fd_an_routes_t * out,
                  uchar const *    msg,
                  ulong            msg_sz ) {
  if( out ) {
    out->route_cnt  = 0UL;
    out->target_cnt = 0UL;
    out->dropped    = 0UL;
  }
  if( FD_UNLIKELY( !msg_sz ) ) return FD_AN_PROTO_OK;

  int full = 0;

  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, msg, msg_sz );

  fd_pb_tlv_t tlv[1];
  while( fd_pb_inbuf_sz( buf ) ) {
    if( FD_UNLIKELY( !fd_pb_read_tlv( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;

    if( FD_UNLIKELY( tlv->field_id!=AN_HB_RESP_ROUTES ) ) {
      if( FD_UNLIKELY( !an_field_skip( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;
      continue;
    }

    uchar const * sub;
    ulong         sub_sz;
    if( FD_UNLIKELY( !an_field_bytes( buf, tlv, &sub, &sub_sz ) ) ) return FD_AN_PROTO_ERR_DECODE;
    an_route_wire_t wire;
    int err = an_decode_route( &wire, sub, sub_sz );
    if( FD_UNLIKELY( err!=FD_AN_PROTO_OK ) ) return err;
    if( out ) an_route_add( out, &wire, &full );
  }

  return FD_AN_PROTO_OK;
}

int
fd_an_proto_decode_routes( fd_an_routes_t * out,
                           uchar const *    msg,
                           ulong            msg_sz ) {
  int err = an_decode_routes( NULL, msg, msg_sz );
  if( FD_UNLIKELY( err!=FD_AN_PROTO_OK ) ) return err;
  return an_decode_routes( out, msg, msg_sz );
}

char const *
fd_an_proto_strerror( int err ) {
  switch( err ) {
  case FD_AN_PROTO_OK:          return "ok";
  case FD_AN_PROTO_ERR_DECODE:  return "decode";
  case FD_AN_PROTO_ERR_NO_NODE: return "no node";
  case FD_AN_PROTO_ERR_IPV6:    return "ipv6 node";
  default:                      return "unknown";
  }
}
