FROM skw/base-archlinux

RUN mkdir /root/tools

RUN pacman --noconfirm -Syu --needed jdk-openjdk jdk8-openjdk maven ant && \
    rm -rf /var/cache/pacman/pkg/*

# Marshalsec
RUN git clone --depth 1 https://github.com/mbechler/marshalsec/ /root/tools/marshalsec && \
    cd /root/tools/marshalsec && \
    archlinux-java set java-8-openjdk && \
    mvn clean package -DskipTests && \
    rm -rf ~/.m2/repository && \
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'exec java -cp /root/tools/marshalsec/target/marshalsec-*-all.jar "$@"' \
        > /usr/local/bin/marshalsec && \
    chmod +x /usr/local/bin/marshalsec

# Ysoserial
RUN git clone --depth 1 https://github.com/frohoff/ysoserial /root/tools/ysoserial && \
    cd /root/tools/ysoserial && \
    mvn clean package -DskipTests && \
    rm -rf ~/.m2/repository && \
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'exec java -jar /root/tools/ysoserial/target/ysoserial-*-all.jar "$@"' \
        > /usr/local/bin/ysoserial && \
    chmod +x /usr/local/bin/ysoserial

# JDeserialize
RUN git clone --depth 1 https://github.com/unsynchronized/jdeserialize /root/tools/jdeserialize && \
    cd /root/tools/jdeserialize/jdeserialize && \
    ant compile && ant build-jar && \
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'exec java -jar /root/tools/jdeserialize/jdeserialize/jdeserialize.jar "$@"' \
        > /usr/local/bin/jdeserialize && \
    chmod +x /usr/local/bin/jdeserialize

# Newest installed JDK
RUN archlinux-java set \
    "$(archlinux-java status | grep -oE 'java-[0-9]+-openjdk' | sort -uV | tail -1)"

WORKDIR /work
CMD ["/bin/bash"]
