(use ../build/jhydro)
(use ../support/tester)

(deftest
  (test "util/hex2bin" (deep= (util/hex2bin "a3") @"\xA3"))
  (test "util/bin2hex" (deep= (util/bin2hex "\xA3") @"a3")))
