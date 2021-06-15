FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/zeek/bin:${PATH}"

RUN apt update && apt install -y dpdk-dev libdpdk-dev curl gpg cmake make gcc g++

RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null && \
    apt update && \
    apt install -y zeek

COPY . /app

RUN cd /app && ./configure && make && make install

ENTRYPOINT zeek