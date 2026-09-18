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

#define AN_NODE_RPC           (1U)
#define AN_NODE_PUBKEY        (2U)
#define AN_NODE_SNAPSHOT_HASH (3U)
#define AN_NODE_LATENCY       (4U)

#define AN_SVC_SHRED_VERSION  (1U)
#define AN_SVC_CAPABILITIES   (2U)
#define AN_SVC_VERSION        (3U)


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
    } else {
      if( FD_UNLIKELY( !an_field_skip( buf, tlv ) ) ) return FD_AN_PROTO_ERR_DECODE;
    }
  }

  if( FD_UNLIKELY( !have_node ) ) return FD_AN_PROTO_ERR_NO_NODE;

  *out = node;
  return FD_AN_PROTO_OK;
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
