FROM skw/java-env

ARG JAZZER_VERSION=0.30.0

ENV JAVA_HOME=/usr/lib/jvm/default

RUN mkdir -p /root/tools/jazzer && \
    curl -fsSL \
      "https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v${JAZZER_VERSION}/jazzer-linux-x86-64.tar.gz" \
      | tar xz -C /root/tools/jazzer && \
    ln -s /root/tools/jazzer/jazzer /usr/local/bin/jazzer

ENV JAVA_OPTS="-XX:+EnableDynamicAgentLoading -XX:-OmitStackTraceInFastThrow -XX:+UseParallelGC"

WORKDIR /work
CMD ["/bin/bash"]
