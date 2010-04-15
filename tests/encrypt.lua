function tohex(s)
	return (s:gsub('.', function (c) return string.format("%02X", string.byte(c)) end))
end
function hexprint(s)
	print(tohex(s))
end

require 'crypto'

-- TESTING ENCRYPT

assert(crypto.encrypt, "missing crypto.encrypt")

local cipher = 'aes128'
local text = 'Hello world!'
local key = 'abcd'
local iv = '1234'

local res = crypto.encrypt(cipher, text, key, iv)
assert(type(res) == "string", "wrong result type, expecting string")
assert(#res % 16 == 0, "unexpected result size") -- aes128 block size is 16bytes
assert(tohex(res) == "9BAC9A71DD600824706096852E7282DF", "unexpected result")

local res2 = crypto.encrypt(cipher, text, key, iv)
assert(res == res2, "the results are different!")

assert(crypto.encrypt.new, "missing crypto.encrypt.new")
local ctx = crypto.encrypt.new(cipher, key, iv)
local p1 = ctx:update(text)
local p2 = ctx:final()
local res3 = p1 .. p2
assert(res == res3, "constructed result is different from direct")

hexprint(res)

-- TESTING DECRYPT

assert(crypto.decrypt, "missing crypto.decrypt")

local dec = crypto.decrypt(cipher, res, key, iv)
assert(dec == text, "different direct result")

print(dec)

assert(crypto.decrypt.new, "missing crypto.decrypt.new")

local ctx = crypto.decrypt.new(cipher, key, iv)
local p1 = ctx:update(res)
local p2 = ctx:final()
local dec2 = p1 .. p2

assert(dec2 == text, "different partial result")
