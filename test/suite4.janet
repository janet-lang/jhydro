(use ../_build/develop/jhydro)
(use spork/test)

(start-suite 4)

(def ctx "context1")
(def key (hash/keygen))
(def other-key (hash/keygen))

(assert (= (hash/hash 32 "msg" ctx) (hash/hash 32 "msg" ctx nil))
        "nil key same as no key")
(assert (= (hash/hash 32 "msg" ctx key) (hash/hash 32 "msg" ctx key))
        "keyed hash deterministic")
(assert (not= (hash/hash 32 "msg" ctx) (hash/hash 32 "msg" ctx key))
        "key changes hash")
(assert (not= (hash/hash 32 "msg" ctx key) (hash/hash 32 "msg" ctx other-key))
        "different keys give different hashes")
(assert-error "short key" (hash/hash 32 "msg" ctx "short"))

(end-suite)
