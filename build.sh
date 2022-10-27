#!/bin/bash
root=$(dirname "$0")

# install nimterop, if not already installed
if ! [ -x "$(command -v toast)" ]; then
  nimble install -y nimterop@0.6.11
fi

# run make on usrsctp sources
cd "${root}/usrsctp" && ./bootstrap && ./configure && make && cd "${root}"

# add prelude
cat "${root}/prelude.nim" > "${root}/usrsctp.nim"

# dividing line
echo >> "${root}/usrsctp.nim"

# assemble list of C files to be compiled
for file in `find ${root}/usrsctp/usrsctplib -name '*.c'`; do
  compile="${compile} --compile=${file}"
done

# generate nim wrapper with nimterop
toast \
  $compile \
  --pnim \
  --preprocess \
  --noHeader \
  --defines=NGTCP2_STATICLIB \
  --replace=sockaddr=SockAddr \
  --replace=SockAddr_storage=Sockaddr_storage \
  --replace=socklen_t=SockLen \
  --includeDirs="${root}/usrsctp/usrsctplib" \
  "${root}/usrsctp/usrsctplib/usrsctp.h" >> "${root}/usrsctp.nim"
