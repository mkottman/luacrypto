local crypto = require "crypto"
base64 = crypto.base64
unbase64 = crypto.unbase64

assert(unbase64(base64("abc")) == "abc")
