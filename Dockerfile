FROM python:3.9-slim

# Version is stamped into the image at build time (see docker-compose.yml).
ARG APP_VERSION=dev
LABEL org.opencontainers.image.title="NetScaler Dashboard" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.source="https://github.com/Benny007-king/NetScaler-Dashboard"
ENV APP_VERSION=$APP_VERSION

ENV TZ=Asia/Jerusalem
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 443
# HTTPS on 443 with a CA-signed cert (generated on first boot via gunicorn.conf.py)
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
