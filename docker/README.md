# Dockerfile examples

Sample Dockerfiles for the SFTPGo daemon and the REST API CLI.

The SFTPGo Dockerfiles for `Debian` and `Alpine` are multi-stage builds, you can customize your build configuration using the pre-defined build arguments. For example the following build argument is defined for both `Debian` and `Alpine`:

```console
ARG TAG
```

you can build a specific tag/commit passing, for example, `--build-arg TAG=v1.0.0` to the `docker build` command, please take a look at the specific `Dockerfile` to see all the available build args.

The runtime configuration can be customized via environment variables that you can set directly inside the `Dockerfile` (not recommended) or passing the `-e` option to the `docker run` command or inside the `environment` section if you are using [docker stack deploy](https://docs.docker.com/engine/reference/commandline/stack_deploy/) or [docker-compose](https://github.com/docker/compose).

Please take a look [here](../docs/full-configuration.md#environment-variables) to learn how to configure SFTPGo via environment variables.

I'm not a `Docker` expert, you can use the provided Dockerfiles as starting point, if you think they can improved to be more general or you want to improve the documentation please send pull requests, thank you!
