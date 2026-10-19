FROM codercom/code-server:4.141.0@sha256:72ab24b5680ee597dd647b30d82625752f40109b5f61bef90ffbf1ea1f02dbb8

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm python3 python3-venv build-essential default-jdk-headless \
    && rm -rf /var/lib/apt/lists/*
USER 1000:1000
ENV HOME=/home/coder
WORKDIR /home/coder
