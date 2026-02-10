FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    build-essential \
    wget \
    unzip \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

ENV NDK_VERSION=r26b
ENV ANDROID_NDK_HOME=/opt/android-ndk-${NDK_VERSION}
RUN wget -q https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip && \
    unzip -q android-ndk-${NDK_VERSION}-linux.zip -d /opt && \
    rm android-ndk-${NDK_VERSION}-linux.zip

ENV PATH=${ANDROID_NDK_HOME}:${PATH}

# Create a non-root user
# RUN useradd -m -s /bin/bash user
# just run as root for now

COPY template /exp
WORKDIR /exp

USER user
