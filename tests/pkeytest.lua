require 'crypto'

assert(crypto.pkey, "crypto.pkey is unavaliable")

local k = crypto.pkey.generate('rsa', 1024)
assert(k, "no key generated")
print(k)

k:write('pub.pem', 'priv.pem')

kpub = assert(crypto.pkey.read('pub.pem'))
print(kpub)

kpriv = assert(crypto.pkey.read('priv.pem', true))
print(kpriv)
