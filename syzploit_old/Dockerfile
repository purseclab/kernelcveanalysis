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
    gdb \
    gdb-multiarch \
    sudo \
    ca-certificates \
    python3-dev \
    autotools-dev \
    libboost-all-dev=1.74.0.3ubuntu7 \
    libboost-program-options1.74-dev

# Install JDK 21
RUN cd /opt && \
    wget -O openjdk21.tar.gz \
      https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.8+9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.8_9.tar.gz && \
    tar -xvaf openjdk21.tar.gz && \
    mv jdk-21* openjdk-21 && \
    rm openjdk21.tar.gz
ENV PATH="/opt/openjdk-21/bin:$PATH"

# Install GHIDRA
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4_build/ghidra_11.4_PUBLIC_20250620.zip && \
    unzip ghidra_11.4_PUBLIC_20250620.zip -d /workspace && \
    rm ghidra_11.4_PUBLIC_20250620.zip

# Install uv (both the CLI and as pip-accessible build backend)
RUN pip install --no-cache-dir uv uv-build rich pyyaml && \
    pip3 install --no-cache-dir uv uv-build

# Clone and build vmlinux-to-elf
RUN git clone https://github.com/marin-m/vmlinux-to-elf.git /workspace/vmlinux-to-elf && \
    pip3 install --upgrade lz4 zstandard git+https://github.com/clubby789/python-lzo@b4e39df && \
    cd /workspace/vmlinux-to-elf && pip3 install --upgrade .

# Create workspace
RUN mkdir -p /workspace && chown -R kuser:kuser /workspace
WORKDIR /workspace

# Install Android SDK & NDK
RUN mkdir -p /workspace/android_sdk && \
    wget https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip \
        -O /workspace/commandlinetools-linux-13114758_latest.zip && \
    unzip /workspace/commandlinetools-linux-13114758_latest.zip -d /workspace/android_sdk && \
    cd /workspace/android_sdk/cmdline-tools && \
    mkdir latest && \
    mv bin lib NOTICE.txt source.properties latest/ && \
    cd latest && \
    yes | ./bin/sdkmanager --install "ndk;25.2.9519653"


# Build syzkaller
RUN wget https://dl.google.com/go/go1.23.6.linux-amd64.tar.gz && \
    tar -xf go1.23.6.linux-amd64.tar.gz && \
    export GOROOT=/workspace/go && \
    export PATH=$GOROOT/bin:$PATH && \
    git clone https://github.com/google/syzkaller && \
    cd syzkaller && \
    make

# Copy syzploit project WITHOUT .git (expected)
COPY --chown=kuser:kuser ./ /workspace/syzploit

# Mount point for ingots_tools (kexploit integration)
# Mount at runtime: docker run -v /path/to/ingots_tools:/workspace/ingots_tools
RUN mkdir -p /workspace/ingots_tools && chown kuser:kuser /workspace/ingots_tools

ENV CPDDL_BIN=/workspace/syzploit/src/cpddl/bin

ENV POWERLIFTED=/workspace/syzploit/src/powerlifted

ENV PATH="/workspace/syzkaller/bin:$POWERLIFTED:$PATH"

ENV SYZBOT_REPRO_DATA_DIR="/workspace/syzploit/syzploit_data/"

# Switch to non-root user
USER kuser

# Pull base python deps (kexploit extras installed at runtime if ingots_tools is mounted)
RUN cd /workspace/syzploit && uv sync

WORKDIR /workspace/syzploit

RUN /workspace/syzploit/build_submodules

# Entrypoint: install kexploit extras if ingots_tools is mounted, then exec shell
COPY --chown=kuser:kuser --chmod=755 ./docker-entrypoint.sh /workspace/syzploit/docker-entrypoint.sh
ENTRYPOINT ["/workspace/syzploit/docker-entrypoint.sh"]
CMD ["/bin/bash"]