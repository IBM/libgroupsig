FROM node:lts-buster-slim

# Copy the server files
RUN mkdir /opt/server
WORKDIR /opt/server
COPY ./ /opt/server/

# Install and configure postgresql, and build the server (all in one line to save docker layers)
RUN apt update && apt install postgresql cmake build-essential git libssl-dev -y
RUN sed -i -e "s/local\s\{1,\}all\s\{1,\}postgres\s\{1,\}peer/local\tall\t\tall\t\t\t\t\ttrust/" /etc/postgresql/11/main/pg_hba.conf
RUN service postgresql start && \
    psql -U postgres -c "CREATE USER groupsig WITH PASSWORD 'groupsig';" && \
    psql -U postgres -c "CREATE DATABASE groupsig;" && \
    psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE groupsig to groupsig;" && \
    npm install && \
    apt purge cmake build-essential git -y

RUN echo '#!/bin/bash\nport=$1\n\nif [ -z "$port" ]; then\n\tport=3000\nfi\n\nservice postgresql start\nPORT=$port npm start' > start.sh

ENTRYPOINT ["bash", "start.sh"]
