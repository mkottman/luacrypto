crypto = require 'crypto'

local cipher = 'aes128'
local text = ('0124'):rep(3):rep(1333) .. 'abcd'
local key = 'abcd'
local iv = '1234'

local res = assert(crypto.encrypt(cipher, text, key, iv))
assert(type(res) == "string", "wrong result type, expecting string")
assert(#res % 16 == 0, "unexpected result size") -- aes128 block size is 16 bytes

do -- encrypt large block
local ctx = crypto.encrypt.new(cipher, key, iv)
local p1 = ctx:update(text)
local p2 = ctx:final()
assert(res == p1..p2, "constructed result is different from direct")
end

do -- encrypt large block with writer
local ctx = crypto.encrypt.new(cipher, key, iv)
local t = {}
ctx:set_writer(table.insert, t)
assert(ctx == ctx:update(text))
assert(ctx == ctx:final())
assert(res == table.concat(t), "constructed result is different from direct")
end

do -- decrypt
local text2 = assert(crypto.decrypt(cipher, res, key, iv))
assert(text2 == text)
end

do -- decrypt large block
local ctx = crypto.decrypt.new(cipher, key, iv)
local p1 = ctx:update(res)
local p2 = ctx:final()
assert(text == p1..p2, "constructed result is different from direct")
end

do -- decrypt large block with writer
local ctx = crypto.decrypt.new(cipher, key, iv)
local t = {}
ctx:set_writer(table.insert, t)
assert(ctx == ctx:update(res))
assert(ctx == ctx:final())
assert(text == table.concat(t), "constructed result is different from direct")
end
