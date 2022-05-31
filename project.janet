(declare-project
  :name "jhydro"
  :description "Lightweight cryptographic and random number generation utils for Janet. Based on libhydrogen."
  :author "Calvin Rose"
  :license "MIT"
  :url "https://github.com/janet-lang/jhydro"
  :repo "git+https://github.com/janet-lang/jhydro.git"
  :dependencies ["spork"])

(declare-native
  :name "jhydro"
  :cflags [;default-cflags "-I."]
  :source @["jhydro.c"
            "hydrogen.c"])
