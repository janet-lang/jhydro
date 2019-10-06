(import "./gendoc" :as gen)

(declare-project
  :name "jhydro"
  :author "Calvin Rose"
  :license "MIT"
  :url "https://github.com/janet-lang/jhydro"
  :repo "git+https://github.com/janet-lang/jhydro.git")

(declare-native
  :name "jhydro"
  :cflags [;default-lflags "-Ilibhydrogen"]
  :source @["jhydro.c"
            "libhydrogen/hydrogen.c"])
