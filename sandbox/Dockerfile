FROM debian:bookworm-slim

LABEL maintainer="CyberSentinel AI - SolventCyber.com"
LABEL description="Security tools sandbox for CyberSentinel AI"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    dnsutils \
    curl \
    wget \
    netcat-openbsd \
    traceroute \
    iputils-ping \
    tcpdump \
    openssl \
    python3 \
    python3-pip \
    python3-venv \
    jq \
    git \
    ca-certificates \
    unzip \
    perl \
    libnet-ssleay-perl \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

# Install nikto from source
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    || echo "nikto install skipped"

# Install nuclei
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -sSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name' | tr -d 'v')_linux_amd64.zip -o /tmp/nuclei.zip \
    && apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && rm -rf /var/lib/apt/lists/* \
    || echo "nuclei install skipped - will work without it"

# Install subfinder
RUN curl -sSL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_$(curl -sSL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | jq -r '.tag_name' | tr -d 'v')_linux_amd64.zip -o /tmp/subfinder.zip \
    && unzip /tmp/subfinder.zip -d /usr/local/bin/ \
    && rm /tmp/subfinder.zip \
    || echo "subfinder install skipped"

# Install httpx
RUN curl -sSL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_$(curl -sSL https://api.github.com/repos/projectdiscovery/httpx/releases/latest | jq -r '.tag_name' | tr -d 'v')_linux_amd64.zip -o /tmp/httpx.zip \
    && unzip /tmp/httpx.zip -d /usr/local/bin/ \
    && rm /tmp/httpx.zip \
    || echo "httpx install skipped"

# Install Zeek (open source network analysis)
# Zeek installs to /opt/zeek/bin - must add to PATH
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' > /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/security_zeek.gpg \
    && apt-get update && apt-get install -y --no-install-recommends zeek-lts \
    && rm -rf /var/lib/apt/lists/* \
    || echo "zeek install skipped - will use tcpdump fallback"

# Add Zeek to PATH (installs to /opt/zeek/bin)
ENV PATH="/opt/zeek/bin:${PATH}"

# Install OWASP ZAP CLI (headless mode)
RUN pip3 install --break-system-packages zaproxy 2>/dev/null \
    || echo "zaproxy pip install skipped"
# Download ZAP CLI wrapper as fallback
RUN curl -sSL https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz -o /tmp/zap.tar.gz \
    && tar -xzf /tmp/zap.tar.gz -C /opt/ \
    && ln -sf /opt/ZAP_2.15.0/zap.sh /usr/local/bin/zap-cli \
    && rm /tmp/zap.tar.gz \
    || echo "ZAP install skipped - will work without it"

# Ensure /etc/services exists (fixes whois and other tools)
RUN if [ ! -f /etc/services ]; then \
    echo "whois 43/tcp" > /etc/services && \
    echo "domain 53/tcp" >> /etc/services && \
    echo "domain 53/udp" >> /etc/services && \
    echo "http 80/tcp" >> /etc/services && \
    echo "https 443/tcp" >> /etc/services; \
    fi

# Stay as root for nmap and other tools that need privileges
WORKDIR /tmp

# Keep container alive - backend sends commands via docker exec
CMD ["tail", "-f", "/dev/null"]
