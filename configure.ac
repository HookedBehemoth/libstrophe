AC_INIT([libstrophe], [0.9.3], [jack@metajack.im])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
LT_INIT([dlopen])

AC_PROG_CC
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG

WARNING_FLAGS="-Wall"

AS_CASE([$PLATFORM],
    [haiku],   [],
               [WARNING_FLAGS="$WARNING_FLAGS -Wextra"])

AC_ARG_WITH([libxml2],
    [AS_HELP_STRING([--with-libxml2], [use libxml2 for XML parsing, expat is the default])])
AC_ARG_ENABLE([tls],
    [AS_HELP_STRING([--disable-tls], [disable TLS support])])
AC_ARG_ENABLE([cares],
    [AS_HELP_STRING([--enable-cares], [use c-ares for DNS resolution])])

AC_SEARCH_LIBS([socket], [network socket])
AC_CHECK_FUNCS([snprintf vsnprintf])

with_parser=""
if test "x$with_libxml2" != xyes; then
    PKG_CHECK_MODULES([expat], [expat >= 2.0.0],
        [
            with_parser="expat"
            PC_REQUIRES="expat ${PC_REQUIRES}"
        ],
        [AC_CHECK_HEADER([expat.h],
            [
                with_parser="expat"
                expat_LIBS="-lexpat"
                PC_LIBS="${expat_LIBS} ${PC_LIBS}"
            ])
        ])
fi
if test "x$with_libxml2" != xno -a "x$with_parser" = x; then
    PKG_CHECK_MODULES([libxml2], [libxml-2.0 >= 2.7],
        [
            with_parser="libxml2"
            PC_REQUIRES="libxml-2.0 ${PC_REQUIRES}"
        ],
        [
            old_CFLAGS=$CFLAGS
            CFLAGS="-I${includedir}/libxml2"
            AC_CHECK_HEADER([libxml/parser.h],
                [
                    with_parser="libxml2"
                    libxml2_CFLAGS="-I${includedir}/libxml2"
                    libxml2_LIBS="-lxml2 -lm"
                    PC_LIBS="${libxml2_LIBS} ${PC_LIBS}"
                    PC_CFLAGS="${libxml2_CFLAGS} ${PC_CFLAGS}"
                ])
            CFLAGS=$old_CFLAGS
        ])
fi

if test "x$with_parser" = xlibxml2; then
    PARSER_CFLAGS=$libxml2_CFLAGS
    PARSER_LIBS=$libxml2_LIBS
elif test "x$with_parser" = xexpat; then
    PARSER_CFLAGS=$expat_CFLAGS
    PARSER_LIBS=$expat_LIBS
else
    AC_MSG_ERROR([no XML parser was found, libstrophe requires expat or libxml2])
fi

AC_MSG_NOTICE([libstrophe will use the $with_parser XML parser])

m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR],
    [AC_ARG_WITH([pkgconfigdir],
        [AS_HELP_STRING([--with-pkgconfigdir],
            [install directory for libstrophe.pc pkg-config file])],
        [], [with_pkgconfigdir='$(libdir)/pkgconfig'])
    AC_SUBST([pkgconfigdir], [${with_pkgconfigdir}])])

AM_CONDITIONAL([PARSER_EXPAT], [test x$with_parser != xlibxml2])
AM_CONDITIONAL([DISABLE_TLS], [test x$enable_tls = xno])

AC_SUBST([PC_REQUIRES], [${PC_REQUIRES}])
AC_SUBST([PC_CFLAGS], [${PC_CFLAGS}])
AC_SUBST([PC_LIBS], [${PC_LIBS}])

AC_SUBST(PARSER_CFLAGS)
AC_SUBST(PARSER_LIBS)
AC_SUBST(WARNING_FLAGS)
AC_CONFIG_FILES([Makefile libstrophe.pc])
AC_OUTPUT
