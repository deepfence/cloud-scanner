ARG DF_IMG_TAG=latest
ARG IMAGE_REPOSITORY=deepfenceio
FROM $IMAGE_REPOSITORY/steampipe:$DF_IMG_TAG AS steampipe

FROM golang:1.22-bookworm AS build
ARG VERSION=latest

WORKDIR /home/deepfence/src/cloud_scanner
COPY . .
WORKDIR /home/deepfence/src/cloud_scanner
RUN go build -ldflags="-s -w -X main.Version=${VERSION}" -o cloud_scanner .

FROM debian:bookworm-slim
ARG VERSION

MAINTAINER Deepfence Inc
LABEL deepfence.role=system

ENV HOME_DIR="/home/deepfence" \
    COMPLIANCE_MOD_PATH="/opt/steampipe"

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash git ca-certificates nano logrotate sudo \
    #&& apt-get install -y --no-install-recommends postgresql-client-15 \
    && useradd -rm -d /home/deepfence -s /bin/bash -g root -G sudo -u 1001 deepfence \
    && mkdir /opt/steampipe \
    && chown deepfence /opt/steampipe

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY logrotate.conf /etc/logrotate.d/logrotate.conf
RUN chmod 600 /etc/logrotate.d/logrotate.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /opt/steampipe

USER deepfence

COPY --from=steampipe /usr/local/bin/steampipe /usr/local/bin/steampipe

RUN steampipe service start \
    && steampipe plugin install steampipe \
    # plugin version should be in sync with Deepfence fork https://github.com/deepfence/steampipe-plugin-aws
    && steampipe plugin install aws@0.118.1 gcp@0.43.0 azure@0.49.0 azuread@0.12.0 \
    && git clone https://github.com/turbot/steampipe-mod-aws-compliance.git --branch v0.79 --depth 1 \
    && git clone https://github.com/turbot/steampipe-mod-gcp-compliance.git --branch v0.21 --depth 1 \
    && git clone https://github.com/turbot/steampipe-mod-azure-compliance.git --branch v0.35 --depth 1 \
    && steampipe service stop


ENV PUBLISH_CLOUD_RESOURCES_INTERVAL_MINUTES=5 \
    FETCH_CLOUD_RESOURCES_INTERVAL_HOURS=12

EXPOSE 8080

COPY --from=steampipe /usr/local/bin/steampipe-plugin-aws.plugin /home/deepfence/.steampipe/plugins/hub.steampipe.io/plugins/turbot/aws@latest/steampipe-plugin-aws.plugin
COPY --from=steampipe /usr/local/bin/steampipe-plugin-gcp.plugin /home/deepfence/.steampipe/plugins/hub.steampipe.io/plugins/turbot/gcp@latest/steampipe-plugin-gcp.plugin
COPY --from=steampipe /usr/local/bin/steampipe-plugin-azure.plugin /home/deepfence/.steampipe/plugins/hub.steampipe.io/plugins/turbot/azure@latest/steampipe-plugin-azure.plugin
COPY --from=steampipe /usr/local/bin/steampipe-plugin-azuread.plugin /home/deepfence/.steampipe/plugins/hub.steampipe.io/plugins/turbot/azuread@latest/steampipe-plugin-azuread.plugin

COPY --from=build /home/deepfence/src/cloud_scanner/cloud_scanner /usr/local/bin/cloud_scanner

USER root

RUN ln -s /usr/local/bin/cloud_scanner /usr/local/bin/cloud_compliance_scan \
    && apt-get -y remove git ca-certificates

USER deepfence

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/cloud_scanner"]
