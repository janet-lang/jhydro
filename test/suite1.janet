(use ../build/jhydro)
(use ./support/tester)

(deftest
  (test "u32"
        # ok, so this isn't strictly correct, but it is very unlikely.
        (all identity (seq [i :range [0 500]]
                           (not= (random/u32) (random/u32)))))

  (test "buffer 1"
        (= 1024 (length (random/buf 1024))))

  (test "buffer 2"
        (= 0 (length (random/buf 0))))

  (assert-error "buffer 3" (random/buf -1))

  (assert-error "buffer 4" (random/buf @"abc" -10)))
