FROM archlinux:latest

RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
        base-devel \
        dav1d \
        clang \
        cmake \
        curl \
        git \
        libx11 \
        libxcursor \
        libxinerama \
        libxkbcommon \
        libxrandr \
        libxi \
        llvm \
        mesa \
        nasm \
        ninja \
        pkgconf \
        python \
        rustup \
        vulkan-headers \
        vulkan-icd-loader \
        wayland \
        wayland-protocols \
        rav1e \
        shaderc \
        spirv-tools \
        spirv-llvm-translator && \
    pacman -Scc --noconfirm

ENV CARGO_HOME=/.cargo
ENV RUSTUP_HOME=/.rustup
ENV PATH=/.cargo/bin:${PATH}

WORKDIR /work

CMD ["/bin/bash"]
