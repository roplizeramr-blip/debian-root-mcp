FROM accetto/debian-vnc-xfce-g3:latest
LABEL org.opencontainers.image.source="https://github.com/roplizeramr-blip/debian-root-mcp"

USER root
ENV DEBIAN_FRONTEND=noninteractive \
    NOVNC_PORT=6902 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      nginx python3 python3-venv python3-pip ca-certificates curl tar \
      freeradius freeradius-rest freeradius-utils \
    && mkdir -p /opt/debian-root-mcp/static/tabler/fonts /tmp/tabler-core /tmp/tabler-icons \
    && curl -fsSL --retry 3 https://registry.npmjs.org/@tabler/core/-/core-1.7.3.tgz -o /tmp/tabler-core.tgz \
    && tar -xzf /tmp/tabler-core.tgz -C /tmp/tabler-core \
    && install -m 0644 /tmp/tabler-core/package/dist/css/tabler.rtl.min.css /opt/debian-root-mcp/static/tabler/tabler.rtl.min.css \
    && install -m 0644 /tmp/tabler-core/package/dist/js/tabler.min.js /opt/debian-root-mcp/static/tabler/tabler.min.js \
    && curl -fsSL --retry 3 https://registry.npmjs.org/@tabler/icons-webfont/-/icons-webfont-3.50.0.tgz -o /tmp/tabler-icons.tgz \
    && tar -xzf /tmp/tabler-icons.tgz -C /tmp/tabler-icons \
    && install -m 0644 /tmp/tabler-icons/package/dist/tabler-icons.min.css /opt/debian-root-mcp/static/tabler/tabler-icons.min.css \
    && cp -a /tmp/tabler-icons/package/dist/fonts/. /opt/debian-root-mcp/static/tabler/fonts/ \
    && curl -fsSL https://portwarp.com/download/install.sh | bash \
    && pwrp version \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/debian-root-mcp
COPY THIRD_PARTY_NOTICES.md /opt/debian-root-mcp/static/tabler/THIRD_PARTY_NOTICES.md
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
