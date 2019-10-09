(use ../build/jhydro)
(use ./support/tester)

(deftest
  (def {:public-key pk :secret-key sk} (kx/keygen))
  (def packet @"")
  (def psk (string/repeat "abcdefgh" 4))
  (def {:tx client-tx :rx client-rx} (kx/n1 packet psk pk))
  (def {:tx server-tx :rx server-rx} (kx/n2 packet psk pk sk))
  (test "client tx = server rx" (util/= client-tx server-rx))
  (test "client rx = server tx" (util/= client-rx server-tx)))
