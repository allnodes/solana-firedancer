#include "fd_an_ports_log.h"

#include "../../util/net/fd_ip4.h"


static char const *
an_or( char const * s,
       char const * dflt ) {
  return s && s[ 0 ] ? s : dflt;
}

void
fd_an_ports_log( config_t const * config ) {
  if( FD_UNLIKELY( !config ) ) return;

  int alpenglow = config->firedancer.development.alpenglow;

  char votor[ 64 ] = "off";
  if( FD_LIKELY( alpenglow ) ) {
    fd_cstr_printf( votor, sizeof(votor), NULL, "server %hu, client %hu",
                    config->firedancer.development.votor.quic_server_listen_port,
                    config->firedancer.development.votor.quic_client_listen_port );
  }

  char snapsv[ 96 ] = "off";
  if( FD_LIKELY( config->firedancer.snapshots.server.enabled ) ) {
    fd_cstr_printf( snapsv, sizeof(snapsv), NULL, "%s:%u",
                    an_or( config->firedancer.snapshots.server.http_listen_address, "0.0.0.0" ),
                    config->firedancer.snapshots.server.http_listen_port );
  }

  char gui[ 96 ] = "off";
  if( FD_LIKELY( config->tiles.gui.enabled ) ) {
    fd_cstr_printf( gui, sizeof(gui), NULL, "%s:%hu",
                    an_or( config->tiles.gui.gui_listen_address, "0.0.0.0" ),
                    config->tiles.gui.gui_listen_port );
  }

  char rpc[ 96 ] = "off";
  if( FD_LIKELY( config->tiles.rpc.enabled ) ) {
    fd_cstr_printf( rpc, sizeof(rpc), NULL, "%s:%hu",
                    an_or( config->tiles.rpc.rpc_listen_address, "0.0.0.0" ),
                    config->tiles.rpc.rpc_listen_port );
  }

  FD_LOG_INFO(( "Bound all network sockets as follows:\n"
                "  network:        provider %s, interface %s, bind %s, address " FD_IP4_ADDR_FMT "\n"
                "  Gossip UDP:     %hu (advertised host %s)\n"
                "  TPU QUIC:       %hu\n"
                "  TPU regular:    %hu\n"
                "  Shreds UDP:     %hu\n"
                "  Repair client:  %hu\n"
                "  Repair serve:   %hu\n"
                "  Send TXN src:   %hu\n"
                "  Alpenglow QUIC: %s\n"
                "  Metrics HTTP:   %s:%hu\n"
                "  GUI HTTP:       %s\n"
                "  RPC HTTP:       %s\n"
                "  Snapshot HTTP:  %s",
                an_or( config->net.provider, "auto" ),
                an_or( config->net.interface, "(auto)" ),
                an_or( config->net.bind_address, "(auto)" ),
                FD_IP4_ADDR_FMT_ARGS( config->net.ip_addr ),
                config->gossip.port, an_or( config->firedancer.gossip.host, "(from the interface)" ),
                config->tiles.quic.quic_transaction_listen_port,
                config->tiles.quic.regular_transaction_listen_port,
                config->tiles.shred.shred_listen_port,
                config->tiles.repair.repair_client_listen_port,
                config->tiles.rserve.repair_serve_listen_port,
                config->tiles.txsend.txsend_src_port,
                votor,
                an_or( config->tiles.metric.prometheus_listen_address, "0.0.0.0" ), config->tiles.metric.prometheus_listen_port,
                gui,
                rpc,
                snapsv ));
}
