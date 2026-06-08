FROM skw/base-ubuntu

RUN DEBIAN_FRONTEND=noninteractive apt -y install \
    php-dev php-pear php-xml php-zip php-sqlite3 \
    libsodium-dev && \
    apt -y autoremove && apt -y autoclean && apt -y autopurge

RUN pecl install -f libsodium

WORKDIR /work
CMD ["/bin/bash"]
