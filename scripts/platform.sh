#!/bin/bash

GO=${GO-go}

target_os=${TARGETOS:-${GOOS:-}}
target_arch=${TARGETARCH:-${GOARCH:-}}
target_variant=${TARGETVARIANT:-}

OS=${OS:-${target_os:-$("${GO}" env GOOS)}}
ARCH=${ARCH:-${target_arch:-$("${GO}" env GOARCH)}}

case "${ARCH}/${target_variant}" in
  arm/v7|arm/7|armv7l/*)
    ARCH=arm
    export GOARM=7
    ;;
esac

case "${ARCH}" in
  armv7l)
    ARCH=arm
    export GOARM=7
    ;;
esac

export OS ARCH
export GOOS=${GOOS:-${OS}}
export GOARCH=${GOARCH:-${ARCH}}

if [ "${ARCH}" = arm ]; then
  export GOARM=${GOARM:-7}
fi

SUFFIX="-${ARCH}"
BIN_SUFFIX="-${ARCH}"
case "${ARCH}" in
  amd64)
    BIN_SUFFIX=""
    ;;
  arm)
    BIN_SUFFIX="-armhf"
    ;;
esac

BINARY_POSTFIX=
if [ "${OS}" = windows ]; then
  BINARY_POSTFIX=.exe
fi

export SUFFIX BIN_SUFFIX BINARY_POSTFIX
