FROM python:3.12-slim

RUN pip install --no-cache-dir uploadserver

RUN openssl req -x509 \
    -out /etc/ssl/private/server.pem -keyout /etc/ssl/private/server.pem \
    -newkey rsa:2048 -nodes -sha256 -subj '/CN=Cool Server'


WORKDIR /work
EXPOSE 8000

ENTRYPOINT ["python", "-m", "uploadserver"]
