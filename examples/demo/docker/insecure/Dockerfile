FROM ubuntu:latest

ARG API_KEY=demo-placeholder-not-a-real-secret
ENV AUTH_TOKEN=demo-placeholder-not-a-real-secret

ADD https://example.com/tool.sh /tmp/tool.sh

RUN curl -fsSL https://example.com/install.sh | sh
RUN chmod 777 /opt/app

USER root
CMD ["sh", "-c", "sleep infinity"]
