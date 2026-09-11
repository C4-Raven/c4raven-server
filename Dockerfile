FROM python:3.13

RUN addgroup --gid 1024 raven
RUN adduser --home /app --disabled-password --gecos "" --force-badname --gid 1024 raven
RUN apt update && apt install ffmpeg -y

USER raven

WORKDIR /app/raven

RUN chown -R raven:raven /app

RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# TODO: Install from PyPI
RUN pip install git+https://github.com/C4Raven/c4raven-server.git

RUN /app/venv/bin/flask --app /app/venv/lib/python3.13/site-packages/raven/app.py raven create-ca
#RUN /app/venv/bin/flask --app /app/venv/lib/python3.13/site-packages/raven/app.py db upgrade

EXPOSE 8081

ENTRYPOINT ["raven"]

# Flask will stop gracefully on SIGINT (Ctrl-C).
# Docker compose tries to stop processes using SIGTERM by default, then sends SIGKILL after a delay if the process doesn't stop.
STOPSIGNAL SIGINT

HEALTHCHECK --interval=1m CMD curl --fail http://localhost:8081/api/health || exit 1