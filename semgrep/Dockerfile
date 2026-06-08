FROM python:3.12-slim

RUN pip install --no-cache-dir semgrep

RUN semgrep login --override-tty
RUN semgrep install-semgrep-pro

WORKDIR /work
ENTRYPOINT ["semgrep"]
