# oci-runtime-tool [![Build Status](https://travis-ci.org/opencontainers/runtime-tools.svg?branch=master)](https://travis-ci.org/opencontainers/runtime-tools) [![Go Report Card](https://goreportcard.com/badge/github.com/opencontainers/runtime-tools)](https://goreportcard.com/report/github.com/opencontainers/runtime-tools)

oci-runtime-tool is a collection of tools for working with the [OCI runtime specification][runtime-spec].

## Generating an OCI runtime spec configuration files

[`oci-runtime-tool generate`][generate.1] generates [configuration JSON][config.json] for an [OCI bundle][bundle].
[OCI-compatible runtimes][runtime-spec] like [runC][] expect to read the configuration from `config.json`.

```sh
$ oci-runtime-tool generate --output config.json
$ cat config.json
{
        "ociVersion": "0.5.0",
        …
}
```

## Validating an OCI bundle

[`oci-runtime-tool validate`][validate.1] validates an OCI bundle.
The error message will be printed if the OCI bundle failed the validation procedure.

```sh
$ oci-runtime-tool generate
$ oci-runtime-tool validate
INFO[0000] Bundle validation succeeded.
```

## Testing OCI runtimes

You can run [`test_runtime.sh`][test_runtime.sh] with any [TAP consumer][tap-consumer].
For example, with [prove][]:

```
$ make
$ sudo make install
$ sudo prove ./test_runtime.sh -r /usr/bin/runc
./test_runtime.sh .. ok
All tests successful.
Files=1, Tests=90,  0 wallclock secs ( 0.02 usr  0.00 sys +  0.04 cusr  0.00 csys =  0.06 CPU)
Result: PASS
```

[bundle]: https://github.com/opencontainers/runtime-spec/blob/master/bundle.md
[config.json]: https://github.com/opencontainers/runtime-spec/blob/master/config.md
[prove]: http://perldoc.perl.org/prove.html
[runC]: https://github.com/opencontainers/runc
[runtime-spec]: https://github.com/opencontainers/runtime-spec
[tap-consumer]: https://testanything.org/consumers.html

[generate.1]: man/oci-runtime-tool-generate.1.md
[validate.1]: man/oci-runtime-tool-validate.1.md
