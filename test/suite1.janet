(use ../build/jhydro)
(use spork/test)

(start-suite 1)

(assert
  # ok, so this isn't strictly correct, but it is very unlikely.
  (all identity (seq [i :range [0 500]]
                  (not= (random/u32) (random/u32))))
  "u32")
(assert (= 1024 (length (random/buf 1024))) "buffer 1")
(assert (= 0 (length (random/buf 0))) "buffer 2")

(assert-error "buffer 3" (random/buf -1))

(assert-error "buffer 4" (random/buf @"abc" -10))

(end-suite)
