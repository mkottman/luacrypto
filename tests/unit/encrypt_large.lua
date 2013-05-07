local lunit = require "lunit"
local TEST_CASE = lunit.TEST_CASE
local crypto = require 'crypto'

local cipher = 'aes128'
local key = 'abcd'
local iv = '1234'

local function make_test(N)

local text = ('0124'):rep(3):rep(N) .. 'abcd'

local _ENV = TEST_CASE("encrypt.large." .. tostring(N))

local res

function setup()
  assert(crypto.encrypt)
  res = assert_string(crypto.encrypt(cipher, text, key, iv))
  assert_equal(0, #res % 16, "unexpected result size") -- aes128 block size is 16 bytes
end

function teardown()
  res = nil
end

function test_decrypt()
  local text2 = assert_string(crypto.decrypt(cipher, res, key, iv))
  assert_equal(text, text2)
end

function test_encrypt_update()
  local ctx = assert_userdata(crypto.encrypt.new(cipher, key, iv))
  local p1 = assert_string(ctx:update(text))
  local p2 = assert_string(ctx:final())
  assert_equal(res,  p1..p2, "constructed result is different from direct")
end

function test_encrypt_writer()
  local ctx = assert_userdata(crypto.encrypt.new(cipher, key, iv))
  local t = {} ctx:set_writer(table.insert, t)
  assert_equal(ctx, ctx:update(text))
  assert_equal(ctx, ctx:final())
  assert_equal(res, table.concat(t), "constructed result is different from direct")
end

function test_decrypt_update()
  local ctx = assert_userdata(crypto.decrypt.new(cipher, key, iv))
  local p1 = assert_string(ctx:update(res))
  local p2 = assert_string(ctx:final())
  assert_equal(text, p1..p2, "constructed result is different from direct")
end

function test_decrypt_writer()
  local ctx = assert_userdata(crypto.decrypt.new(cipher, key, iv))
  local t = {} ctx:set_writer(table.insert, t)
  assert_equal(ctx, ctx:update(res))
  assert_equal(ctx, ctx:final())
  assert_equal(text, table.concat(t), "constructed result is different from direct")
end

end

make_test(1)

make_test(16)

make_test(1333)

if not _TEST then lunit.run() end