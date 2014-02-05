local HAS_RUNNER = not not lunit

local lunit = require "lunit"
assert(lunit.TEST_CASE, "lunitx >= 0.7 require")

local crypto = require "crypto"

print("------------------------------------")
print("Lua       version: " .. (_G.jit and _G.jit.version or _G._VERSION))
print("LuaCrypto version: " .. crypto._VERSION)
if crypto.openssl_version then
  print("OpenSSL   version: " .. crypto.openssl_version())
end
print("------------------------------------")
print("")

_TEST = true

require "x509_ca"
require "encrypt"
require "open_seal"
require "update"
require "pkeytest"
require "resetiv"
require "digest"
require "encrypt_large"

if not HAS_RUNNER then lunit.run() end