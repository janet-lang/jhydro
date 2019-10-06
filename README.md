# jhydro

Lightweight cryptographic and random number generation utils for Janet. Based on [libhydrogen](https://github.com/jedisct1/libhydrogen/).

Bindings for most of the libhydrogen API are available so far, with the exception of key sharing APIs.

```clojure
(use jhydro)

(print (random/u32))

(pp (random/buf 1024))

(def buf @"")
(for i 0 10
    (random/buf buf 64))
```

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
