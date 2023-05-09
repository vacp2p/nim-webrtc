#!/bin/bash
root=$(dirname "$0")
outputDirectory="${root}/webrtc/mbedtls"
genDirectory="${root}/gen"

mkdir -p "${outputDirectory}" "${genDirectory}"

# install nimterop, if not already installed
if ! [ -x "$(command -v toast)" ]; then
  nimble install -y nimterop@0.6.11
fi

# run make on usrsctp sources
cd "${root}/mbedtls" && make && cd -

# assemble list of C files to be compiled
for file in `find ${root}/mbedtls/library -name '*.c'`; do
  compile="${compile} --compile=${file}"
done

# rm -r generatedmbedtls.h
# for inc in $(for file in ${root}/mbedtls/include/mbedtls/*.h; do gcc -H "${file}" -I mbedtls/include/ 2>&1 | grep '^\.* mbedtls/include/mbedtls'; echo "- ${file}"; done | LC_COLLATE=C sort -r | awk '{$0=$2}!seen[$0]++'); do
#   cat "$inc" | sed '/^#include ".*"/d' >> generatedmbedtls.h
#   echo "" >> generatedmbedtls.h
# done
# cat "${root}/prelude_mbedtls.nim" > generatedmbedtls.nim
# echo 'type tm {.importc: "struct tm", header: "<time.h>".} = object' >> generatedmbedtls.nim
# toast \
#   $compile \
#   --pnim \
#   --preprocess \
#   --nocomment \
#   --replace=_pms_rsa=u_pms_rsa \
#   --replace=_pms_dhm=u_pms_dhm \
#   --replace=_pms_ecdh=u_pms_ecdh \
#   --replace=_pms_psk=u_pms_psk \
#   --replace=_pms_dhe_psk=u_pms_dhe_psk \
#   --replace=_pms_rsa_psk=u_pms_rsa_psk \
#   --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk \
#   --replace=_pms_ecjpake=u_pms_ecjpake \
#   --includeDirs="${root}/mbedtls/include" \
#   --includeDirs="${root}/mbedtls/library" \
#   generatedmbedtls.h >> generatedmbedtls.nim

# generate nim wrapper with nimterop
errorProc=()
for inc in ${root}/mbedtls/include/mbedtls/*.h; do
  bname="$(basename "${inc}" | tr -- -. __)"
  outputFile="${outputDirectory}/${bname%_h}.nim"
  genFile="${genDirectory}/${bname%_h}.nim"

  echo "=======> ${outputFile}"
  # add prelude
  cat "${root}/prelude_mbedtls.nim" > "${outputFile}"

  if [ "${bname}" = "platform_util_h" ]; then
    echo 'type tm {.importc: "struct tm", header: "<time.h>".} = object' >> "${outputFile}"
  fi
  # add include
  gcc -H "${inc}" -I"${root}/mbedtls/include" 2>&1 |
    grep "^\.* ${root}/mbedtls/include/mbedtls" |
    sed 's/^.*\/\(.*\)\.h/import "\1"/' >> "${outputFile}"
#  grep "^#include \"mbedtls/.*\.h\".*$" "${inc}" |
#    sed "s/.*\"mbedtls\/\(.*\).h\".*$/import \1/" >> "${outputFile}"

  toast \
    --pnim \
    --preprocess \
    --nocomment \
    --noHeader \
    --replace=_pms_rsa=u_pms_rsa \
    --replace=_pms_dhm=u_pms_dhm \
    --replace=_pms_ecdh=u_pms_ecdh \
    --replace=_pms_psk=u_pms_psk \
    --replace=_pms_dhe_psk=u_pms_dhe_psk \
    --replace=_pms_rsa_psk=u_pms_rsa_psk \
    --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk \
    --replace=_pms_ecjpake=u_pms_ecjpake \
    --replace=private_xm1=private_xm1_1 \
    --replace=private_xm2=private_xm2_1 \
    --includeDirs="${root}/mbedtls/include" \
    --includeDirs="${root}/mbedtls/library" \
    "${inc}" > "${genFile}"
  sed -i \
    -e 's/\bpassC\b/passc/g' \
    -e 's/cuchar/byte/g' \
    "${genFile}"
  while read -r procLine; do
    proc="$(sed 's/^proc \(.*\)\*(.*/\1/' <<< "${procLine}")"
    matches="$(grep "\\<${proc}\\>" "${root}/mbedtls/tags" | sed '/library/!d')"
    if [ $? -ne 0 ]; then
      errorProc+=("${proc} in ${outputFile}")
      continue
    fi
    if ! [ -z "${matches}" ]; then
      echo "${matches}" | awk '{$0="{.compile: \"'"${root}"'/mbedtls/"$2"\".}"}1'
    fi
  done <<<  "$(grep '^proc .*\*(' "${genFile}")" | sort | uniq >> "${outputFile}"
  cat "${genFile}" >> "${outputFile}"
done
