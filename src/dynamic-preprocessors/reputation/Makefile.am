## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include -I${srcdir}/../libs -I$(srcdir)/includes

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libsf_reputation_preproc.la

libsf_reputation_preproc_la_LDFLAGS = -shared -export-dynamic -module @XCCFLAGS@
if SO_WITH_STATIC_LIB
libsf_reputation_preproc_la_LIBADD = ../libsf_dynamic_preproc.la
else
nodist_libsf_reputation_preproc_la_SOURCES = \
../include/sf_dynamic_preproc_lib.c \
../include/sf_ip.c \
../include/sfrt.c \
../include/sfrt_dir.c \
../include/sfPolicyUserData.c
endif

libsf_reputation_preproc_la_SOURCES = \
spp_reputation.c \
spp_reputation.h \
reputation_config.c \
reputation_config.h \
reputation_utils.c \
reputation_utils.h \
reputation_debug.h 

EXTRA_DIST = \
sf_reputation.dsp


all-local: $(LTLIBRARIES)
	$(MAKE) DESTDIR=`pwd`/../build install-libLTLIBRARIES
