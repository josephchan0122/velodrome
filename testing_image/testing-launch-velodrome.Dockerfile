FROM base-velodrome-testing-img
ARG test_n=4
RUN mkdir -p /opt/velodrome/requirements /opt/velodrome/envdir
WORKDIR /opt/velodrome

COPY requirements requirements
COPY vendored vendored
COPY bin bin
COPY build build
COPY .git .git

RUN git submodule update --init

RUN /bin/bash -c "python3.8 -m pip install --no-cache-dir --no-dependencies -r requirements/travis.txt && \
    python3.8 -m pip install envdir==1.0.1 && python3.8 -m pip install -e vendored/pinax-stripe"

COPY velodrome velodrome
COPY envdir.travis envdir
COPY setup.cfg setup.cfg

RUN echo 'postgis://testuser:testuser@localhost/trackings' > envdir/DATABASE_TRACKINGS_URL
RUN echo 'postgis://testuser:testuser@localhost/velodrome' > envdir/DATABASE_URL

ENV PYTEST_ADDOPTS="-vv -n ${test_n} --maxfail=10 --run-slow-tests --dynamodb-test-url=http://localhost:9001/"

RUN echo '#!/bin/bash' > /opt/run.sh && chmod 777 /opt/run.sh
RUN echo 'java -Djava.library.path=/opt/dynamodb/DynamoDBLocal_lib -jar /opt/dynamodb/DynamoDBLocal.jar -sharedDb -port 9001 &' >> /opt/run.sh
RUN echo 'su -c "/opt/db_script.sh & /usr/lib/postgresql/12/bin/postgres" postgres' >> /opt/run.sh

RUN echo '#!/bin/bash' > /opt/run_tests.sh && chmod 777 /opt/run_tests.sh
RUN echo 'envdir envdir python3.8 -m pytest' >> /opt/run_tests.sh
RUN cat /opt/run_tests.sh

CMD ["/opt/run.sh"]
