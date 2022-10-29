from python:3.8-slim-bullseye

RUN apt-get update && apt-get install wget gnupg2 zip -y
RUN sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt bullseye-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
RUN sh -c 'wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -'
RUN apt-get update
RUN apt-get install -y postgresql-12 postgresql-12-postgis

# # dynamodb # #
RUN cd /tmp && wget https://s3.eu-central-1.amazonaws.com/dynamodb-local-frankfurt/dynamodb_local_latest.zip >> /dev/null
RUN mkdir /opt/dynamodb && cd /opt/dynamodb && unzip /tmp/dynamodb_local_latest.zip

RUN apt install -yq --no-install-recommends pkg-config git build-essential \
    gcc libcurl4-gnutls-dev libgdal28 libgnutls28-dev default-jdk \
    libxml2-dev libxmlsec1-dev libxmlsec1-openssl python3-lxml && apt autoclean

COPY testing_image/init_db_script.sh /opt/db_script.sh
RUN chmod 777 /opt/db_script.sh

ENV PGDATA /var/lib/postgresql/12/main
RUN cp -v /etc/postgresql/12/main/pg_hba.conf "$PGDATA/pg_hba.conf"
RUN chown -R postgres:postgres "$PGDATA" && chmod 700 "$PGDATA"

# db optimization for tests
RUN echo "\
listen_addresses = '*'\n\
max_connections = 32\n\
max_wal_senders=1\n\
autovacuum=off\n\
shared_buffers = 86MB\n\
dynamic_shared_memory_type = posix\n\
log_timezone = 'Etc/UTC'\n\
datestyle = 'iso, mdy'\n\
timezone = 'Etc/UTC'\n\
default_text_search_config = 'pg_catalog.english'\n\
effective_io_concurrency = 4\n\
max_worker_processes = 4\n\
max_parallel_workers_per_gather = 4\n\
max_parallel_workers = 4\n\
wal_level = 'replica'\n\
fsync = off\n\
synchronous_commit = off\n\
max_wal_size = 1GB\n\
min_wal_size = 800MB\n\
" > "$PGDATA/postgresql.conf"

RUN java --version && python3.8 --version && rm -r /tmp/dynamodb_local_latest.zip
