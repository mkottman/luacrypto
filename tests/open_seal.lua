require 'crypto'

assert(crypto.pkey, "crypto.pkey is unavaliable")

k = crypto.pkey.generate('rsa', 1024)
assert(k, "no key generated")

k:write('pub.pem', 'priv.pem')

kpub = assert(crypto.pkey.read('pub.pem'))
kpriv = assert(crypto.pkey.read('priv.pem', true))

assert(crypto.open, "crypto.open is unavaliable")
assert(crypto.seal, "crypto.seal is unavaliable")

message = string.rep('This message will be signed', 1222)

data = assert(crypto.seal("aes128", message, kpub))
assert(crypto.open("aes128", data, kpriv) == message)

local ctx = crypto.seal.new("aes128", kpub)
local p1 = ctx:update(message)
local p2 = ctx:final()
assert(crypto.open("aes128", p1..p2, kpriv) == message)

local ctx = crypto.open.new("aes128", kpriv)
p1 = ctx:update(data)
p2 = ctx:final()
assert(message == (p1 .. p2))

print("OK")
