FROM python:3.13

RUN addgroup --gid 1024 raven
RUN adduser --home /app --disabled-password --gecos "" --force-badname --gid 1024 raven

WORKDIR /app/raven

COPY . /app/

RUN chown -R raven:raven /app

RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

RUN pip install /app

USER raven

EXPOSE 8088

CMD ["/app/venv/bin/eud_handler", "--no-ssl"]

# Flask will stop gracefully on SIGINT (Ctrl-C).
# Docker compose tries to stop processes using SIGTERM by default, then sends SIGKILL after a delay if the process doesn't stop.
STOPSIGNAL SIGINT