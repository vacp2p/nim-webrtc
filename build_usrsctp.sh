#!/bin/bash
root=$(dirname "$0")
outputFile="${root}/webrtc/usrsctp.nim"

# install nimterop, if not already installed
if ! [ -x "$(command -v toast)" ]; then
  nimble install -y nimterop@0.6.11
fi

# run make on usrsctp sources
cd "${root}/usrsctp" && ./bootstrap && ./configure && make && cd -

# add prelude
cat "${root}/prelude_usrsctp.nim" > "${outputFile}"

# assemble list of C files to be compiled
for file in `find ${root}/usrsctp/usrsctplib -name '*.c'`; do
  compile="${compile} --compile=${file}"
done

# TODO: Make something more reliable, aka remove this LIBCFLAGS
# and put the different flags on prelude.nim depending on the
# OS we're currently on
LIBCFLAGS="$(grep "^LIBCFLAGS = " "${root}/usrsctp/Makefile" | cut -d' ' -f3- | sed 's/-D/--defines=/g')"
LIBCFLAGS="${LIBCFLAGS}"
for flag in 'STDC_HEADERS=1' 'HAVE_SYS_TYPES_H=1' 'HAVE_SYS_STAT_H=1' 'HAVE_STDLIB_H=1' 'HAVE_STRING_H=1' 'HAVE_MEMORY_H=1' 'HAVE_STRINGS_H=1' 'HAVE_INTTYPES_H=1' 'HAVE_STDINT_H=1' 'HAVE_UNISTD_H=1' 'HAVE_DLFCN_H=1' 'LT_OBJDIR=".libs/"' 'SCTP_DEBUG=1' 'INET=1' 'INET6=1' 'HAVE_SOCKET=1' 'HAVE_INET_ADDR=1' 'HAVE_STDATOMIC_H=1' 'HAVE_SYS_QUEUE_H=1' 'HAVE_LINUX_IF_ADDR_H=1' 'HAVE_LINUX_RTNETLINK_H=1' 'HAVE_NETINET_IP_ICMP_H=1' 'HAVE_NET_ROUTE_H=1' '_GNU_SOURCE'; do
	LIBCFLAGS="${LIBCFLAGS} --defines=${flag}"
done

# generate nim wrapper with nimterop
toast \
  $compile \
  --pnim \
  --preprocess \
  --noHeader \
  $LIBCFLAGS \
  --replace=sockaddr=SockAddr \
  --replace=SockAddr_storage=Sockaddr_storage \
  --replace=SockAddr_in=Sockaddr_in \
  --replace=SockAddr_conn=Sockaddr_conn \
  --replace=socklen_t=SockLen \
  --includeDirs="${root}/usrsctp/usrsctplib" \
  "${root}/usrsctp/usrsctplib/usrsctp.h" >> "${outputFile}"

sed -i 's/\bpassC\b/passc/g' "${outputFile}"
