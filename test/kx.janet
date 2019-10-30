(use ../build/jhydro)
(use ../support/tester)

(deftest

  # n variant
  (do
    (def {:public-key pk :secret-key sk} (kx/keygen))
    (def packet @"")
    (def psk (random/buf kx/psk-bytes))
    (def {:tx client-tx :rx client-rx} (kx/n1 packet psk pk))
    (def {:tx server-tx :rx server-rx} (kx/n2 packet psk pk sk))
    (test "client tx = server rx" (util/= client-tx server-rx))
    (test "client rx = server tx" (util/= client-rx server-tx)))

  # kk variant
  (do
    (def {:public-key pk1 :secret-key sk1} (kx/keygen))
    (def {:public-key pk2 :secret-key sk2} (kx/keygen))
    (def packet1 @"")
    (def packet2 @"")
    (def a-state (kx/kk1 packet1 pk2 pk1 sk1))
    (def {:tx b-tx :rx b-rx} (kx/kk2 packet2 packet1 pk1 pk2 sk2))
    (def {:tx a-tx :rx a-rx} (kx/kk3 a-state packet2 pk1 sk1))
    (test "a tx = b rx" (util/= a-tx b-rx))
    (test "a rx = b tx" (util/= a-rx b-tx)))

  # xx variant
  (do
    (def {:public-key pk1 :secret-key sk1} (kx/keygen))
    (def {:public-key pk2 :secret-key sk2} (kx/keygen))
    (def packet1 @"")
    (def packet2 @"")
    (def packet3 @"")
    (def psk (random/buf kx/psk-bytes))
    (def a-state (kx/xx1 packet1 psk))
    (def b-state (kx/xx2 packet2 packet1 psk pk2 sk2))
    (def {:tx b-tx :rx b-rx} (kx/xx3 a-state packet3 packet2 psk pk1 sk1))
    (def {:tx a-tx :rx a-rx} (kx/xx4 b-state packet3 psk))
    (test "a tx = b rx" (util/= a-tx b-rx))
    (test "a rx = b tx" (util/= a-rx b-tx))))
