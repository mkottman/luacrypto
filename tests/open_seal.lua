local function ichunks(len, chunk_size)
  return function(_, b)
    b = b + chunk_size
    if b > len then return nil end
    local e = b + chunk_size - 1
    if e > len then e = len end
    return b, e
  end, nil, -chunk_size + 1
end

crypto = require 'crypto'

assert(crypto.pkey, "crypto.pkey is unavaliable")

k = crypto.pkey.generate('rsa', 1024)
assert(k, "no key generated")

k:write('pub.pem', 'priv.pem')

kpub = assert(crypto.pkey.read('pub.pem'))
kpriv = assert(crypto.pkey.read('priv.pem', true))

assert(crypto.open, "crypto.open is unavaliable")
assert(crypto.seal, "crypto.seal is unavaliable")

message = string.rep('This message will be signed', 122)

data, ek, iv = assert(crypto.seal("aes128", message, kpub))

assert(crypto.open("aes128", data, kpriv, ek, iv) == message)
do
local ctx = crypto.seal.new("aes128", kpub)
local p1 = ctx:update(message)
local p2, ek_2, iv_2 = ctx:final()
assert(crypto.open("aes128", p1..p2, kpriv, ek_2, iv_2) == message)

local ctx = crypto.open.new("aes128", kpriv, ek_2, iv_2)
p3 = ctx:update(p1..p2)
p4 = ctx:final()
assert(message == (p3 .. p4))
end

do
local ctx = crypto.seal.new("aes128", kpub)
local p1 = ''
for b,e in ichunks(#message, 25) do 
  p1 = p1 .. ctx:update(message, b, e)
end
local p2, ek_2, iv_2 = ctx:final()

assert(crypto.open("aes128", p1..p2, kpriv, ek_2, iv_2) == message)

local ctx = crypto.open.new("aes128", kpriv, ek_2, iv_2)

p3 = ctx:update(p1..p2, 1, #p1)
p3 = p3 .. ctx:update(p1..p2, #p1+1, #(p1..p2))
p4 = ctx:final()
assert(message == (p3 .. p4))
end

do
local ctx = crypto.seal.new("aes128", kpub)
local t = {}
ctx:set_writer(table.insert, t)
local a, b = ctx:get_writer()
assert(a == table.insert)
assert(b == t)
assert(ctx == ctx:update(message))
local ek_2, iv_2 = ctx:final()

assert(crypto.open("aes128", table.concat(t), kpriv, ek_2, iv_2) == message)

local ctx = crypto.open.new("aes128", kpriv, ek_2, iv_2)
local t2 = {}
ctx:set_writer(table.insert, t2)
local a, b = ctx:get_writer()
assert(a == table.insert)
assert(b == t2)

assert(ctx == ctx:update(table.concat(t)))
assert(ctx == ctx:final())

assert(message == table.concat(t2))
end

print("OK")
