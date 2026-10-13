ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_an_proto.h fd_an_shared.h fd_an_endpoints.h fd_an_conn.h fd_an_client.h fd_an_heartbeat.h fd_an_topo.h fd_an_ports_log.h fd_an_env.h fd_an_consts.h fd_an_routes.h fd_an_peers.h fd_an_vote.h)
$(call add-objs,fd_an_proto fd_an_endpoints fd_an_conn fd_an_client fd_an_heartbeat fd_an_tile fd_an_topo fd_an_ports_log fd_an_env fd_an_consts fd_an_routes fd_an_peers fd_an_vote,fd_discof)


include src/app/firedancer/version.mk
FD_AN_VERSION_MINOR:=$(shell [ $(FD_VERSION_MAJOR) -ge 26 ] && printf %02d $(FD_VERSION_MINOR) || printf %d $(FD_VERSION_MINOR))
FD_AN_CLIENT_VERSION:=$(or $(ALLNODES_CLIENT_VERSION),$(addprefix firedancer/,$(shell git describe --tags 2>/dev/null)),firedancer/v$(FD_VERSION_MAJOR).$(FD_AN_VERSION_MINOR).$(FD_VERSION_PATCH)-allnodes)
ifneq ($(words $(FD_AN_CLIENT_VERSION)),1)
$(error ALLNODES_CLIENT_VERSION `$(FD_AN_CLIENT_VERSION)` must be one word)
endif
ifneq ($(findstring ",$(FD_AN_CLIENT_VERSION))$(findstring \,$(FD_AN_CLIENT_VERSION)),)
$(error ALLNODES_CLIENT_VERSION `$(FD_AN_CLIENT_VERSION)` must not contain quotes or backslashes)
endif
FD_AN_VERSION_DIR:=$(OBJDIR)/gen/discof/allnodes
define FD_AN_VERSION_GENERATED_H
#define FD_AN_CLIENT_VERSION "$(FD_AN_CLIENT_VERSION)"
endef
$(shell mkdir -p $(FD_AN_VERSION_DIR))
ifneq ($(if $(wildcard $(FD_AN_VERSION_DIR)/fd_an_version_generated.h),$(file <$(FD_AN_VERSION_DIR)/fd_an_version_generated.h)),$(FD_AN_VERSION_GENERATED_H))
$(file >$(FD_AN_VERSION_DIR)/fd_an_version_generated.h,$(FD_AN_VERSION_GENERATED_H))
endif
$(OBJDIR)/obj/discof/allnodes/fd_an_tile.%: CPPFLAGS+=-I$(FD_AN_VERSION_DIR)
$(OBJDIR)/obj/discof/allnodes/fd_an_tile.o $(OBJDIR)/obj/discof/allnodes/fd_an_tile.d $(OBJDIR)/obj/discof/allnodes/fd_an_tile.check: $(FD_AN_VERSION_DIR)/fd_an_version_generated.h

endif
