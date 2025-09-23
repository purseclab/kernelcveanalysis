FROM ubuntu:22.04

# Environment setup
ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_NDK_HOME=/workspace/android_sdk/ndk/25.2.9519653/
ENV PATH="$ANDROID_NDK_HOME:$PATH"
ENV GHIDRA_INSTALL_DIR=/workspace/ghidra_11.4_PUBLIC

# Create user with UID and GID 1000
RUN groupadd -g 1000 kuser && \
    useradd -m -u 1000 -g kuser -s /bin/bash kuser

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    unzip \
    wget \
    python3 \
    python3-pip \
    build-essential \
    clang \
    lld \
    gcc \
    g++ \
    make \
    cmake \
    pkg-config \
    zlib1g-dev \
    libssl-dev \
    liblzo2-dev \
    libprotobuf-dev \
    protobuf-compiler \
    xz-utils \
    clang-format \
    qemu-system-x86 \
    sudo

# Install jdk 21
RUN cd /opt && \
    wget "https://release-assets.githubusercontent.com/github-production-release-asset/602574963/3aef38ae-ccf5-4599-9459-d2d6cdc3cce7?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-07-23T07:51:56Z&rscd=attachment; filename=OpenJDK21U-jdk_x64_linux_hotspot_21.0.8_9.tar.gz&rsct=application/octet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-07-23T06:51:11Z&ske=2025-07-23T07:51:56Z&sks=b&skv=2018-11-09&sig=lqqxf6fpaT70stZ32Oj7i0Tm/d/VYCn0wLCZqAcEw+w=&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc1MzI1NDYxOSwibmJmIjoxNzUzMjU0MzE5LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.rxOBnCWOWiCkWhhUsWV7bSLqWYxAeY0IITk5hdBfcMI&response-content-disposition=attachment; filename=OpenJDK21U-jdk_x64_linux_hotspot_21.0.8_9.tar.gz&response-content-type=application/octet-stream" -O openjdk21.tar.gz && \
    tar -xvaf openjdk21.tar.gz && \
    mv jdk-21* openjdk-21 && \
    rm openjdk21.tar.gz
ENV PATH="/opt/openjdk-21/bin:$PATH"

# Install GHIDRA
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4_build/ghidra_11.4_PUBLIC_20250620.zip && \
    unzip ghidra_11.4_PUBLIC_20250620.zip -d /workspace && \
    rm ghidra_11.4_PUBLIC_20250620.zip 

# Install uv
RUN pip install uv rich pyyaml

# Clone and build vmlinux-to-elf
RUN git clone https://github.com/marin-m/vmlinux-to-elf.git /workspace/vmlinux-to-elf && \
    pip3 install --upgrade lz4 zstandard git+https://github.com/clubby789/python-lzo@b4e39df && \
    pip3 install --upgrade git+https://github.com/marin-m/vmlinux-to-elf 

# Create workspace
RUN mkdir -p /workspace && chown -R kuser:kuser /workspace
WORKDIR /workspace

# Install Android SDK & NDK
RUN mkdir -p /workspace/android_sdk && \
    wget https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip -O /workspace/commandlinetools-linux-13114758_latest.zip && \
    unzip /workspace/commandlinetools-linux-13114758_latest.zip -d /workspace/android_sdk && \
    cd /workspace/android_sdk/cmdline-tools && \
    mkdir latest && \
    mv /workspace/android_sdk/cmdline-tools/bin /workspace/android_sdk/cmdline-tools/latest && \
    mv /workspace/android_sdk/cmdline-tools/lib /workspace/android_sdk/cmdline-tools/latest && \
    mv /workspace/android_sdk/cmdline-tools/NOTICE.txt /workspace/android_sdk/cmdline-tools/latest && \
    mv /workspace/android_sdk/cmdline-tools/source.properties /workspace/android_sdk/cmdline-tools/latest && \
    cd /workspace/android_sdk/cmdline-tools/latest/ && \
    yes | ./bin/sdkmanager --install "ndk;25.2.9519653"

# Clone and build syzkaller for syz-prog2c
RUN wget https://dl.google.com/go/go1.23.6.linux-amd64.tar.gz && \
    tar -xf go1.23.6.linux-amd64.tar.gz && \
    export GOROOT=`pwd`/go && \
    export PATH=$GOROOT/bin:$PATH && \
    git clone https://github.com/google/syzkaller && \
    cd syzkaller && \
    make

# Copy project (before switching user)
COPY --chown=kuser:kuser ./ /workspace/syzbot-repro

ENV PATH="/workspace/syzkaller/bin:$PATH"
ENV SYZBOT_REPRO_DATA_DIR="/workspace/syzbot-repro/syzbot-repro_data/"

# Switch to non-root user
USER kuser

# pull all python packages in the uv project
RUN cd syzbot-repro && uv sync
