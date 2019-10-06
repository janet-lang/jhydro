# jhydro

Lightweight cryptographic and random number generation utils for Janet. Based on [libhydrogen](https://github.com/jedisct1/libhydrogen/).

Bindings for most of the libhydrogen API are available so far, with the exception of the key sharing API.

```clojure
(use jhydro)

(print (random/u32))

(pp (random/buf 1024))

(def buf @"")
(for i 0 10
    (random/buf buf 64))
```

## Documentation

Documentation can be built with [Mendoza](https://github.com/bakpakin/mendoza).
First, install the latest verion of mendoza, and then run `mdz && mdz serve`
from the jhydro repository directory. You can then navigate to
`http://localhost:8000` to see the documentation.

## Building

```
jpm build
```

To build the library.

## Testing

```
jpm test
```

## License

This module is licensed under the MIT/X11 License.
