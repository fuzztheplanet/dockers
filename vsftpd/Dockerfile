FROM skw/base-alpine

RUN apk add --no-cache vsftpd

RUN mkdir -p /home/ftpuser && \
    chmod 755 /home/ftpuser

COPY vsftpd/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21 30000-30009

ENTRYPOINT ["/entrypoint.sh"]
