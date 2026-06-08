FROM skw/base-archlinux

RUN mkdir /root/tools

# Several JDKs and build tools
RUN pacman --noconfirm -S jdk-openjdk jdk8-openjdk maven ant

# Marshalsec
RUN git clone https://github.com/mbechler/marshalsec/ /root/tools/marshalsec && \
    cd /root/tools/marshalsec && \
    archlinux-java set java-8-openjdk && \
    mvn clean package -DskipTests && \
    rm -rf ~/.m2/repository && \
    echo '#!/usr/bin/env bash' > /usr/local/bin/marshalsec && \
    echo 'java -cp /root/tools/marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar $@' >> /usr/local/bin/marshalsec && \
    chmod +x /usr/local/bin/marshalsec

# Ysoserial
RUN git clone https://github.com/frohoff/ysoserial /root/tools/ysoserial && \
    cd /root/tools/ysoserial && \
    mvn clean package -DskipTests && \
    rm -rf ~/.m2/repository && \
    echo '#!/usr/bin/env bash' > /usr/local/bin/ysoserial && \
    echo 'java -jar /root/tools/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar $@' >> /usr/local/bin/ysoserial && \
    chmod +x /usr/local/bin/ysoserial

# JDeserialize
RUN git clone https://github.com/unsynchronized/jdeserialize /root/tools/jdeserialize && \
    cd /root/tools/jdeserialize/jdeserialize && \
    ant compile && ant build-jar && \
    echo '#!/usr/bin/env bash ' > /usr/local/bin/jdeserialize && \
    echo 'java -jar /root/tools/jdeserialize/jdeserialize/jdeserialize.jar $@' >> /usr/local/bin/jdeserialize && \
    chmod +x /usr/local/bin/jdeserialize

# Set default Java version
RUN archlinux-java set java-26-openjdk

WORKDIR /work
CMD ["/bin/bash"]
