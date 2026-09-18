#ifndef HEADER_fd_src_discof_allnodes_fd_an_consts_h
#define HEADER_fd_src_discof_allnodes_fd_an_consts_h


#include "../../util/fd_util_base.h"

#define FD_AN_CONST_KIND_CSTR  (0)
#define FD_AN_CONST_KIND_ULONG (1)


#define FD_AN_CONST_MAX       ( 16UL)
#define FD_AN_CONST_VALUE_MAX (512UL)

struct fd_an_const_decl {
  char const * name;
  int          kind;
  ulong        dflt_u;
  char const * dflt_s;
  ulong        idx;
};

typedef struct fd_an_const_decl fd_an_const_decl_t;

struct fd_an_const {
  int   set;
  ulong u;
  char  s[ FD_AN_CONST_VALUE_MAX ];
};

typedef struct fd_an_const fd_an_const_t;

struct fd_an_consts {
  fd_an_const_t v[ FD_AN_CONST_MAX ];
};

typedef struct fd_an_consts fd_an_consts_t;

FD_PROTOTYPES_BEGIN

void
fd_an_const_register( fd_an_const_decl_t * decl );


void
fd_an_consts_attach( fd_an_consts_t const * consts );

FD_FN_PURE char const *
fd_an_const_s( fd_an_const_decl_t const * decl );

FD_FN_PURE ulong
fd_an_const_u( fd_an_const_decl_t const * decl );


int
fd_an_consts_set( fd_an_consts_t * consts,
                  char const *     name,
                  ulong            name_len,
                  char const *     value,
                  ulong            value_len );


FD_FN_PURE ulong
fd_an_consts_cnt( void );

FD_PROTOTYPES_END


#define FD_AN_CONST_ULONG( name, dflt )                                                       \
  static fd_an_const_decl_t name##_decl = { #name, FD_AN_CONST_KIND_ULONG, (dflt), "", ULONG_MAX }; \
  __attribute__((constructor)) static void name##_register( void ) { fd_an_const_register( &name##_decl ); } \
  FD_FN_UNUSED static ulong name( void ) { return fd_an_const_u( &name##_decl ); }            \
  struct fd_an_const_semicolon_##name

#define FD_AN_CONST_CSTR( name, dflt )                                                        \
  static fd_an_const_decl_t name##_decl = { #name, FD_AN_CONST_KIND_CSTR, 0UL, (dflt), ULONG_MAX }; \
  __attribute__((constructor)) static void name##_register( void ) { fd_an_const_register( &name##_decl ); } \
  FD_FN_UNUSED static char const * name( void ) { return fd_an_const_s( &name##_decl ); }      \
  struct fd_an_const_semicolon_##name

#endif
