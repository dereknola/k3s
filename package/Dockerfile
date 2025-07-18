FROM alpine:3.22 AS base
RUN apk add -U ca-certificates zstd tzdata
ARG TARGETARCH
COPY build/out/data-linux*.tar.zst /
RUN SOURCE_TAR_ZST="/data-linux-${TARGETARCH}.tar.zst" && \
    # If the arch-specific file doesn't exist, try the default one (used with Dapper or single-arch)
    if [ ! -f "${SOURCE_TAR_ZST}" ]; then \
       SOURCE_TAR_ZST="/data-linux.tar.zst" ; \
    fi && \
    \
    mkdir -p /image/etc/ssl/certs /image/run /image/var/run /image/tmp /image/lib/modules /image/lib/firmware /image/var/lib/rancher/k3s/data/cni && \
    zstdcat -d "${SOURCE_TAR_ZST}" | tar -xa -C /image && \
    for FILE in cni $(/image/bin/find /image/bin -lname cni -printf "%f\n"); do ln -s /bin/cni /image/var/lib/rancher/k3s/data/cni/$FILE; done && \
    echo "root:x:0:0:root:/:/bin/sh" > /image/etc/passwd && \
    echo "root:x:0:" > /image/etc/group && \
    cp /etc/ssl/certs/ca-certificates.crt /image/etc/ssl/certs/ca-certificates.crt

FROM scratch AS collect
ARG DRONE_TAG="dev"
COPY --from=base /image /
COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo
RUN mkdir -p /etc && \
    echo 'hosts: files dns' > /etc/nsswitch.conf && \
    echo "PRETTY_NAME=\"K3s ${DRONE_TAG}\"" > /etc/os-release && \
    chmod 1777 /tmp

FROM scratch
VOLUME /var/lib/kubelet
VOLUME /var/lib/rancher/k3s
VOLUME /var/lib/cni
VOLUME /var/log
COPY --from=collect / /
ENV PATH="/var/lib/rancher/k3s/data/cni:$PATH:/bin/aux"
ENV CRI_CONFIG_FILE="/var/lib/rancher/k3s/agent/etc/crictl.yaml"
ENTRYPOINT ["/bin/k3s"]
CMD ["agent"]
