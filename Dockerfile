FROM python:3.9-slim
ENV TZ=Asia/Jerusalem
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 443
# HTTPS on 443 with a self-signed cert (generated on first boot via gunicorn.conf.py)
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
