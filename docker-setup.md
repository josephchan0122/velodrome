# Docker Setup 
This is a file with instructions on how to get Docker containers for this project running based on the Docker setup in this Branch

## Get Started
- Follow the Instructions in 4, of the README to set up your environment variables
- Run the services

```docker-compose build```
```docker-compose up```
- Make migrations

```docker exec velodrome_web_1 envdir envdir python manage.py makemigrations```

- Migrate

```docker exec velodrome_web_1 envdir envdir python manage.py migrate```

## Tests
- To run your tests

`docker exec velodrome_web_1 envdir envdir python -m pytest`

#Note

If you're having migration errors when running your test you should run the tests with:

```docker exec velodrome_web_1 envdir envdir python -m pytest —reuse-db —create-db```