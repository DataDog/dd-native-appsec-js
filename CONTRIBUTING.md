# Contributing to dd-native-metrics-js

Please reach out before starting work on any major code changes.
This will ensure we avoid duplicating work, or that your code can't be merged due to a rapidly changing
base. If you would like support for a module that is not listed, [contact support][1] to share a request.

[1]: https://docs.datadoghq.com/help

## Local setup

To set up the project locally, you can install it with:
```
$ npm install --ignore-scripts
$ node scripts/setup.js
```

If libddwaf is in a private repository, you will need to set up an environment variable named GH_TOKEN with a Github
token that has read access to libddwaf.

### Download another release of libddwaf

The `scripts/setup.js` accepts the following environment variables:
* `PLATFORM`: to override the value of `os.platform()`
* `ARCH`: to override the value of `os.arch()`
* `LIBC`: to select a specific libc implementaition (Linux only)

### Build

Build the project with
```
$ npm run dev
```

and then it will be possible to run the tests with
```
$ npm t
```
