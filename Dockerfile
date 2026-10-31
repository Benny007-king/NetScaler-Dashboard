# The newest Python; the Debian packages under it are brought up to date at every
# build, so a release carries the security fixes published until that day.
FROM python:3.15-slim

# Version is stamped into the image at build time (see docker-compose.yml).
ARG APP_VERSION=dev
LABEL org.opencontainers.image.title="NetScaler Dashboard" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.source="https://github.com/Benny007-king/NetScaler-Dashboard"
ENV APP_VERSION=$APP_VERSION

ENV TZ=Asia/Jerusalem
RUN apt-get update && apt-get -y --no-install-recommends upgrade && rm -rf /var/lib/apt/lists/*  && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
WORKDIR /app
COPY requirements.txt .
# pip only installs; it is removed afterwards so the image carries nothing that is
# not used at run time (pip bundles its own copies of urllib3, msgpack, ...).
RUN pip install --no-cache-dir -r requirements.txt && pip uninstall -y -q pip
COPY . .
EXPOSE 443
# HTTPS on 443 with a CA-signed cert (generated on first boot via gunicorn.conf.py)
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
