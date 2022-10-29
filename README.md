# velodrome

API service powered by django-rest-framework

[![Build Status](https://travis-ci.com/lock8/velodrome.svg?token=1cZ3Jy2DStcoTAvezSS8&branch=master)](https://travis-ci.com/lock8/velodrome)
[![Docker Repository on Quay.io](https://quay.io/repository/lock8/velodrome/status?token=b205b8ce-c520-440e-9fda-5358412ad70c&branch=latest "Docker Repository on Quay.io")](https://quay.io/repository/lock8/velodrome)
[![codecov.io](https://codecov.io/github/lock8/velodrome/coverage.svg?branch=master&token=glvZ1yPlhF)](https://codecov.io/github/lock8/velodrome?branch=master)

## Installation for developer environment

1. Install system dependencies.

    This includes PostgreSQL, Python 3.6 and build tools (Git, Make).
    You might want to use [pyenv](https://github.com/pyenv/pyenv) for managing
    multiple Python versions.

1. Activate your virtual environment.

    ```bash
    python3.8 -m venv .venv
    . .venv/bin/activate
    ```

1. Install requirements.
    in system (tested on Linux, will be different on macOS/Windows):

    ```bash
    apt-get install python3-dev python3-pip libpython3-dev python3-cffi python3-pycurl python3-lxml python3-psycopg2 libgdal-dev python3-gdal libcurl4-gnutls-dev libgnutls28-dev
    ```

    and in environment:

    ```bash
    git submodule update --init
    pip install -U pip
    pip install -r requirements/dev.txt
    pip install -e vendored/pinax-stripe
    ```

1. Create an `envdir` directory to hold your environment variables.
  You can use `envdir.travis` as a base, but should remove DJANGO_MEDIA_URL (and better set `Dev` instead of `Travis` in DJANGO_CONFIGURATION)
  then:

      ```bash
      cp -a envdir.travis envdir
      rm envdir/DJANGO_MEDIA_URL
      echo 'Dev' > envdir/DJANGO_CONFIGURATION
      mkdir -p build/static_root
      ```

      See also the [documentation of
      django-configurations](https://django-configurations.readthedocs.org/en/latest/)
      for the naming convention of environment variables.

1. Migrate/setup the database

    ```bash
    envdir envdir python manage.py migrate
    ```

1. Create superuser to get access to Django Admin

    ```bash
    envdir envdir python manage.py createsuperuser
    ```

## Run the server locally

```bash
envdir envdir python manage.py runserver
```

## Run the tests locally

### All the suite

```bash
envdir envdir pytest
```

or with empty base and to pass tests with full urls:

```bash
cp envdir.travis/DJANGO_MEDIA_URL envdir/DJANGO_MEDIA_URL
envdir envdir python -m pytest --create-db
```

### With more awesomeness

```bash
envdir envdir ptw velodrome -- --testmon
```

## Deploy a new release

### Make the release
Go to github and prepare a new release on the UI. the release must be a dot separated list of digits:

Good examples:

```bash
1.2
1.2.3
```

Bad examples:

```bash
v1.2
1.2.3a
```

### Bump salt-states
Go to salt-states repo and bump the docker image to the new release

```yaml
# /pillar/prod/velodrome/init.sls
velodrome:
  image: quay.io/lock8/velodrome:<release tag is HERE!>
```

make a pull request with this change and merge once you are ready to deploy

### run deployment

ssh into `saltmaster.lock8.me` and run:

```bash
sudo salt-run state.orchestrate orchestration.velodrome_stack saltenv=prod
```

### Be aware of side-effects

There are some another services explicitly and implicitly depends on Velodrome databases and endpoint responses.

1. BigQuery tables (perodically filled by the [kraken](https://github.com/lock8/kraken)). If you add/remove columns in the Velodrome DB schema, make sure that the same changes are made to the corresponding BigQuery tables. Tables to be copied into BigQuery: `affiliations`, `alerts`, `bicycles`, `locks`, `organizations`, `rental_sessions`, `support_tickets`, `users`, `zones`.

## Rollback ?

Same process as making a new release, set the docker image tag to desired value and rollout the update from saltmaster.

## Outdated and deprecated

### Accessing the API

TODO: Find a new way to access the API. Maybe by creation of Postman collections. When you will invent this method, describe it here and put this section back somewhere after test paragraph.

#### Using coreapi-cli

1. Install coreapi-cli, e.g. using `pip install --user coreapi-cli`, or from
   your distribution.

1. Setup authentication:

    ```bash
    coreapi credentials add api-test.lock8.me 'JWT …'
    ```

1. Fetch the schema:

    ```bash
    coreapi get https://api-test.lock8.me/swagger/?format=openapi
    ```

1. Setup required API version header:

    ```bash
    coreapi headers add Accept 'application/json; version=1.0'
    ```

1. Do some actions:

    ```bash
    coreapi action bicycles list
    ```

##### Debugging

You can use `--debug` to see the request headers/response:

```bash
coreapi action bicycles list --debug
```

coreapi-cli stores its information in `~/.coreapi`, so you can change e.g.
`~/.coreapi/headers.json` there directly.
