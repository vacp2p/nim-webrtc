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
cat "${root}/prelude.nim" > "${outputFile}"

# assemble list of C files to be compiled
for file in `find ${root}/usrsctp/usrsctplib -name '*.c'`; do
  compile="${compile} --compile=${file}"
done

LIBCFLAGS="$(grep "^LIBCFLAGS = " "${root}/usrsctp/Makefile" | cut -d' ' -f3- | sed 's/-D/--defines=/g')"

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
