# Launching tests in a container

- 1) create a base image:

```bash
make build_baseimg
```

- 2) build a container for tests and launch:

```bash
make launch_tests
```

To minimize a testing time it would be great to place the base testing image `base-velodrome-testing-img` to some docker registry.
