(use ../build/jhydro)
(use spork/test)

(start-suite 2)

(assert (deep= (util/hex2bin "a3") @"\xA3") "util/hex2bin")
(assert (deep= (util/bin2hex "\xA3") @"a3") "util/bin2hex")

(end-suite)
