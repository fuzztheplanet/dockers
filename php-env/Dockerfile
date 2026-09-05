FROM skw/base-ubuntu

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    php-dev php-pear php-xml php-zip php-sqlite3 \
    libsodium-dev && \
    apt-get -y autoremove && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pecl install -f libsodium

WORKDIR /work
CMD ["/bin/bash"]
