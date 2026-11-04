FROM accetto/debian-vnc-xfce-g3:latest
LABEL org.opencontainers.image.source="https://github.com/roplizeramr-blip/debian-root-mcp"

USER root
ENV DEBIAN_FRONTEND=noninteractive \
    NOVNC_PORT=6902 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      nginx python3 python3-venv python3-pip ca-certificates \
      freeradius freeradius-rest freeradius-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/debian-root-mcp
COPY requirements.txt .
RUN python3 -m venv /opt/debian-root-mcp/.venv \
    && /opt/debian-root-mcp/.venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/debian-root-mcp/.venv/bin/pip install --no-cache-dir -r requirements.txt

COPY server.py /opt/debian-root-mcp/server.py
COPY radius_panel.py /opt/debian-root-mcp/radius_panel.py
COPY configure_radius.py /opt/debian-root-mcp/configure_radius.py
COPY nginx.conf /etc/nginx/nginx.conf
COPY start-with-radius.sh /usr/local/bin/start-with-radius.sh
RUN chmod 0755 /usr/local/bin/start-with-radius.sh /opt/debian-root-mcp/configure_radius.py \
    && /opt/debian-root-mcp/.venv/bin/python -m py_compile /opt/debian-root-mcp/server.py /opt/debian-root-mcp/radius_panel.py /opt/debian-root-mcp/configure_radius.py \
    && nginx -t -c /etc/nginx/nginx.conf

EXPOSE 6901 5901 1812/udp 1813/udp
CMD ["/usr/local/bin/start-with-radius.sh"]
