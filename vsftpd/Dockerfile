FROM skw/base-alpine

# Install vsftpd
RUN apk add --no-cache vsftpd

# Create FTP directory
RUN mkdir -p /home/ftpuser && \
    chmod 755 /home/ftpuser

# Copy entrypoint script
COPY vsftpd/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose FTP ports
EXPOSE 21 30000-30009

# Run entrypoint
ENTRYPOINT ["/entrypoint.sh"]
