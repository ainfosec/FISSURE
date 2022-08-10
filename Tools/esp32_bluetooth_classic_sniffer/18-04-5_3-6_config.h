/* cmakeconfig.h.in */

#ifndef __CONFIG_H__
#define __CONFIG_H__

/* Note: You cannot use earlier #defines in later #cmakedefines (cmake 2.6.2). */

/* Name of package */
#define PACKAGE "wireshark"

#define VERSION_EXTRA ""

/* Version number of package */
#define VERSION "3.6.5"
#define VERSION_MAJOR 3
#define VERSION_MINOR 6
#define VERSION_MICRO 5

#define PLUGIN_PATH_ID "3.6"
#define VERSION_FLAVOR "Development Build"

/* Build wsutil with SIMD optimization */
#define HAVE_SSE4_2 1

/* Define to 1 if we want to enable plugins */
#define HAVE_PLUGINS 1

/*  Define to 1 if we check hf conflict */
/* #undef ENABLE_CHECK_FILTER */

/* Link Wireshark libraries statically */
/* #undef ENABLE_STATIC */

/* Enable AirPcap */
/* #undef HAVE_AIRPCAP */

/* Define to 1 if you have the <alloca.h> header file. */
/* #undef HAVE_ALLOCA_H */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to use the MaxMind DB library */
/* #undef HAVE_MAXMINDDB */

/* Define to 1 if you have the <ifaddrs.h> header file. */
#define HAVE_IFADDRS_H 1

/* Define to 1 if yu have the `fseeko` function. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the `getexecname' function. */
/* #undef HAVE_GETEXECNAME */

/* Define to 1 if you have the `getifaddrs' function. */
#define HAVE_GETIFADDRS 1

/* Define if LIBSSH support is enabled */
/* #undef HAVE_LIBSSH */

/* Define if you have the 'dlget' function. */
/* #undef HAVE_DLGET */

/* Define if you have the 'getexecname' function. */
/* #undef HAVE_GETEXECNAME */

/* Define if you have the 'floorl' function. */
#define HAVE_FLOORL 1

/* Define to 1 if you have the getopt_long function. */
#define HAVE_GETOPT_LONG 1

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define to use heimdal kerberos */
/* #undef HAVE_HEIMDAL_KERBEROS */

/* Define to 1 if you have the `krb5_pac_verify' function. */
#define HAVE_KRB5_PAC_VERIFY 1

/* Define to 1 if you have the `krb5_c_fx_cf2_simple' function. */
#define HAVE_KRB5_C_FX_CF2_SIMPLE 1

/* Define to 1 if you have the `inflatePrime' function. */
#define HAVE_INFLATEPRIME 1

/* Define to 1 if you have the `issetugid' function. */
/* #undef HAVE_ISSETUGID */

/* Define to use kerberos */
#define HAVE_KERBEROS 1

/* Define to use nghttp2 */
#define HAVE_NGHTTP2 1

/* Define to use the libcap library */
#define HAVE_LIBCAP 1

/* Define to use GnuTLS library */
#define HAVE_LIBGNUTLS 1

/* Define to 1 if GnuTLS was built with pkcs11 support. */
#define HAVE_GNUTLS_PKCS11 1

/* Enable libnl support */
#define HAVE_LIBNL 1

/* libnl version 1 */
/* #undef HAVE_LIBNL1 */

/* libnl version 2 */
/* #undef HAVE_LIBNL2 */

/* libnl version 3 */
#define HAVE_LIBNL3 1

/* Define to use libpcap library */
#define HAVE_LIBPCAP 1

/* Define to 1 if you have the `smi' library (-lsmi). */
#define HAVE_LIBSMI 1

/* Define to use zlib library */
#define HAVE_ZLIB 1

/* Define to use the minizip library */
/* #undef HAVE_MINIZIP */

/* Define to use brotli library */
#define HAVE_BROTLI 1

/* Define to use lz4 library */
#define HAVE_LZ4 1

/* Check for lz4frame */
#define HAVE_LZ4FRAME_H 1

/* Define to use snappy library */
#define HAVE_SNAPPY 1

/* Define to use zstd library */
#define HAVE_ZSTD 1

/* Define to 1 if you have the <linux/sockios.h> header file. */
#define HAVE_LINUX_SOCKIOS_H 1

/* Define to 1 if you have the <linux/if_bonding.h> header file. */
#define HAVE_LINUX_IF_BONDING_H 1

/* Define to use Lua */
/* #undef HAVE_LUA */

/* Define to use MIT kerberos */
#define HAVE_MIT_KERBEROS 1

/* Define to 1 if you have the `mkstemps' function. */
#define HAVE_MKSTEMPS 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* nl80211.h is new enough */
#define HAVE_NL80211 1

/* SET_CHANNEL is supported */
#define HAVE_NL80211_CMD_SET_CHANNEL 1

/* SPLIT_WIPHY_DUMP is supported */
#define HAVE_NL80211_SPLIT_WIPHY_DUMP 1

/* VHT_CAPABILITY is supported */
#define HAVE_NL80211_VHT_CAPABILITY 1

/* Define to 1 if you have macOS frameworks */
/* #undef HAVE_MACOS_FRAMEWORKS */

/* Define to 1 if you have the macOS CFPropertyListCreateWithStream function */
/* #undef HAVE_CFPROPERTYLISTCREATEWITHSTREAM */

/* Define to 1 if you have the `pcap_create' function. */
/* #undef HAVE_PCAP_CREATE */

/* Define to 1 if the capture buffer size can be set. */
#define CAN_SET_CAPTURE_BUFFER_SIZE 1

/* Define to 1 if you have the `pcap_freecode' function. */
/* #undef HAVE_PCAP_FREECODE */

/* Define to 1 if you have the `pcap_free_datalinks' function. */
/* #undef HAVE_PCAP_FREE_DATALINKS */

/* Define to 1 if you have the `pcap_open' function. */
/* #undef HAVE_PCAP_OPEN */

/* Define to 1 if you have libpcap/WinPcap/Npcap remote capturing support. */
/* #undef HAVE_PCAP_REMOTE */

/* Define to 1 if you have the `pcap_setsampling' function. */
/* #undef HAVE_PCAP_SETSAMPLING */

/* Define to 1 if you have the `pcap_set_tstamp_precision' function. */
/* #undef HAVE_PCAP_SET_TSTAMP_PRECISION */

/* Define to 1 if you have the `pcap_set_tstamp_type' function. */
/* #undef HAVE_PCAP_SET_TSTAMP_TYPE */

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you have the optreset variable */
/* #undef HAVE_OPTRESET */

/* Define if sa_len field exists in struct sockaddr */
/* #undef HAVE_STRUCT_SOCKADDR_SA_LEN */

/* Define to 1 if you want to playing SBC by standalone BlueZ SBC library */
#define HAVE_SBC 1

/* Define to 1 if you have the SpanDSP library. */
#define HAVE_SPANDSP 1

/* Define to 1 if you have the bcg729 library. */
/* #undef HAVE_BCG729 */

/* Define to 1 if you have the ilbc library. */
/* #undef HAVE_ILBC */

/* Define to 1 if you have the speexdsp library. */
/* #undef HAVE_SPEEXDSP */

/* Define to 1 if you have the lixbml2 library. */
#define HAVE_LIBXML2 1

/* Define to 1 if you have the `setresgid' function. */
#define HAVE_SETRESGID 1

/* Define to 1 if you have the `setresuid' function. */
#define HAVE_SETRESUID 1

/* Define to 1 if you have the Sparkle or WinSparkle library */
/* #undef HAVE_SOFTWARE_UPDATE */

/* Define if you have the 'strptime' function. */
#define HAVE_STRPTIME 1

/* Define to 1 if `st_birthtime' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_BIRTHTIME */

/* Define if st_flags field exists in struct stat */
/* #undef HAVE_STRUCT_STAT_ST_FLAGS */

/* Define if st_blksize field exists in struct stat */
#define HAVE_STRUCT_STAT_ST_BLKSIZE 1

/* Define to 1 if `__st_birthtime' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT___ST_BIRTHTIME */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/utsname.h> header file. */
#define HAVE_SYS_UTSNAME_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define if tm_zone field exists in struct tm */
#define HAVE_STRUCT_TM_TM_ZONE 1

/* Define if tzname array exists */
#define HAVE_TZNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Name of package */
/* #undef PACKAGE */

/* Define to the address where bug reports for this package should be sent. */
/* #undef PACKAGE_BUGREPORT */

/* Define to the full name of this package. */
/* #undef PACKAGE_NAME */

/* Define to the full name and version of this package. */
/* #undef PACKAGE_STRING */

/* Define to the one symbol short name of this package. */
/* #undef PACKAGE_TARNAME */

/* Define to the version of this package. */
/* #undef PACKAGE_VERSION */

/* Define if we have QtMultimedia */
#define QT_MULTIMEDIA_LIB 1

/* Define if we have QtMacExtras */
/* #undef QT_MACEXTRAS_LIB */

/* Build androiddump with libpcap instead of wireshark stuff */
/* #undef ANDROIDDUMP_USE_LIBPCAP */

/* Large file support */
/* #undef _LARGEFILE_SOURCE */
/* #undef _LARGEFILE64_SOURCE */
/* #undef _LARGE_FILES */
/* #undef _FILE_OFFSET_BITS */

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
/* Note: not use in the code */
/* #undef YYTEXT_POINTER */

#if defined(_WIN32)
   /*
    * Make sure everyone is using the same API and that it's sufficient
    * for our needs.
    * This should match the following:
    * - The <compatibility><application> section in image\wireshark.exe.manifest.in
    * - The GetWindowsVersion parts of packaging\nsis\wireshark.nsi
    * - The VersionNT parts of packaging\wix\Prerequisites.wxi
    */
#  if defined(NTDDI_VERSION)
#    error NTDDI_VERSION already defined.
#  endif
#  define NTDDI_VERSION NTDDI_WIN7
#  if defined(_WIN32_WINNT)
#    error _WIN32_WINNT already defined.
#  endif
#  define _WIN32_WINNT _WIN32_WINNT_WIN7

   /* WpdPack/INclude/pcap/pcap.h checks for "#if defined(WIN32)" */
#  ifndef WIN32
#    define WIN32	1
#  endif

#  if !defined(QT_VERSION) || !defined(_SSIZE_T_DEFINED)
   typedef int ssize_t;
#  endif

   /*
    * Flex (v 2.5.35) uses this symbol to "exclude" unistd.h
    */
#  define YY_NO_UNISTD_H

#  define strncasecmp strnicmp
#  define popen       _popen
#  define pclose      _pclose

#  ifndef __STDC__
#    define __STDC__ 0
#  endif
   /* Use Unicode in Windows runtime functions. */
#  define UNICODE 1
#  define _UNICODE 1

#  define NEED_STRPTIME_H 1
#endif

#include <ws_diag_control.h>

#endif /* __CONFIG_H__ */
