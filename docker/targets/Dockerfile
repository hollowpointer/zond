# Mock target and service container for Zond integration testing
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    python3 \
    nginx \
    && rm -rf /var/lib/apt/lists/*

RUN echo '#!/bin/bash\n\
# Start Nginx (Port 80)\n\
nginx\n\
# Start a simple HTTP server on 8080\n\
python3 -m http.server 8080 &\n\
# Keep container running\n\
tail -f /dev/null' > /usr/local/bin/start-services.sh && \
chmod +x /usr/local/bin/start-services.sh

EXPOSE 80 8080 22

CMD ["/usr/local/bin/start-services.sh"]
