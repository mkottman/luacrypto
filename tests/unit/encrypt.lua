function tohex(s)
	return (s:gsub('.', function (c) return string.format("%02x", string.byte(c)) end))
end
function hexprint(s)
	print(crypto.hex(s))
end

local lunit = require "lunit"
local TEST_CASE = lunit.TEST_CASE
local crypto = require 'crypto'

local FAIL = function(str) return function() lunit.fail(str) end end

local _ENV = TEST_CASE "TESTING HEX"

function test()
  assert_function(crypto.hex, "missing crypto.hex")
  local tst = 'abcd'
  local actual = crypto.hex(tst)
  local expected = tohex(tst)
  assert_equal(expected, actual, "different hex results")
end

local _ENV = TEST_CASE "TESTING ENCRYPT/DECRYPT"
if     not crypto.encrypt then test = FAIL"missing crypto.encrypt"
elseif not crypto.decrypt then test = FAIL"missing crypto.decrypt"
else

local cipher = 'aes128'
local text   = 'Hello world!'
local key    = 'abcd'
local iv     = '1234'
local res

function setup()
  res = assert_string(crypto.encrypt(cipher, text, key, iv))
  assert_equal(0, #res % 16, "unexpected result size") -- aes128 block size is 16bytes
  assert_equal("9bac9a71dd600824706096852e7282df", crypto.hex(res), "unexpected result")
end

function test_encrypt()
  local res2 = assert_string(crypto.encrypt(cipher, text, key, iv))
  assert_equal(res, res2, "the results are different!")
end

function test_encrypt_update()
  assert_function(crypto.encrypt.new, "missing crypto.encrypt.new")
  local ctx = assert_userdata(crypto.encrypt.new(cipher, key, iv))
  local p1 = assert_string(ctx:update(text))
  local p2 = assert_string(ctx:final())
  local res3 = p1 .. p2
  assert_equal(res, res3, "constructed result is different from direct")
end

function test_encrypt_writer()
  assert_function(crypto.encrypt.new, "missing crypto.encrypt.new")
  local t = {}
  local ctx = assert_userdata(crypto.encrypt.new(cipher, key, iv))
  ctx:set_writer(table.insert, t)

  local a, b = ctx:get_writer()
  assert_equal(table.insert, a, b)
  assert_equal(t, b)

  assert_equal(ctx, ctx:update(text))
  assert_equal(ctx, ctx:final())
  
  local res3 = table.concat(t)
  assert_equal(res, res3, "constructed result is different from direct")
end

function test_decrypt()
  local dec = assert_string(crypto.decrypt(cipher, res, key, iv))
  assert_equal(text, dec, "different direct result")
end

function test_decrypt_update()
  assert_function(crypto.decrypt.new, "missing crypto.decrypt.new")

  local ctx = assert_userdata(crypto.decrypt.new(cipher, key, iv))
  local p1 = assert_string(ctx:update(res))
  local p2 = assert_string(ctx:final())
  local dec2 = p1 .. p2

  assert_equal(text, dec2, "different partial result")
end

function test_decrypt_writer()
  local t = {}
  local ctx = assert_userdata(crypto.decrypt.new(cipher, key, iv))
  ctx:set_writer(table.insert, t)

  local a,b = ctx:get_writer()
  assert_equal(table.insert, a, b)
  assert_equal(t, b)

  assert_equal(ctx, ctx:update(res))
  assert_equal(ctx, ctx:final())
  local dec2 = table.concat(t)
  assert_equal(text, dec2, "different partial result")
end

function test_decrypt_error_key()
  -- Testing errors when decrypting
  local ctx, err = assert_nil(crypto.decrypt("aes128", res, key.."improper key", iv))
  assert_not_nil(err, "should have failed")
end

function test_decrypt_invalid_iv()
  -- wrong iv, will result in garbage
  local dec, err = assert_string(crypto.decrypt("aes128", res, key, iv .. "foo"))
  assert_not_equal(text, dec, "should have failed")
end

function test_decrypt_invalid_data()
  local dec, err = assert_nil(crypto.decrypt("aes128", res .. "foo", key, iv))
  assert_not_nil(err, "should have failed")
end

function test_decrypt_error_iv()
  -- don't crash on an invalid iv
  local ok, dec, err = pcall(crypto.decrypt, "aes128", res, key, iv .. "123456123456123456")
  assert_false(ok, "should have failed")
  assert_not_nil(dec, "should have failed")
end

function test_decrypt_new_error_iv()
  local ok, ctx = pcall(crypto.decrypt.new, "aes128", key, iv .. "123456123456123456")
  assert_false(ok, "should have failed")
  assert_not_nil(ctx, "should have failed")
end

function test_decrypt_error_large_iv()
  local ok, dec, err = pcall(crypto.decrypt, "aes128", res, string.rep(key, 100), iv)
  assert_false(ok, "should have failed")
  assert_not_nil(dec, "should have failed")
end

function test_decrypt_new_error_large_iv()
  local ok, ctx = pcall(crypto.decrypt.new, "aes128", string.rep(key, 100), iv)
  assert_false(ok, "should have failed")
  assert_not_nil(ctx, "should have failed")
end

function test_encrypt_error_iv()
  -- don't crash on an invalid iv
  local ok, dec, err = pcall(crypto.encrypt, "aes128", res, key, iv .. "123456123456123456")
  assert_false(ok, "should have failed")
  assert_not_nil(dec, "should have failed")
end

function test_encrypt_new_error_iv()
  local ok, ctx = pcall(crypto.encrypt.new, "aes128", key, iv .. "123456123456123456")
  assert_false(ok, "should have failed")
  assert_not_nil(ctx, "should have failed")
end

function test_encrypt_error_large_iv()
  local ok, dec, err = pcall(crypto.encrypt, "aes128", res, string.rep(key, 100), iv)
  assert_false(ok, "should have failed")
  assert_not_nil(dec, "should have failed")
end

function test_encrypt_new_error_large_iv()
  local ok, ctx = pcall(crypto.encrypt.new, "aes128", string.rep(key, 100), iv)
  assert_false(ok, "should have failed")
  assert_not_nil(ctx, "should have failed")
end

function test_empty_cycle()
  local res = crypto.decrypt("aes128", crypto.encrypt("aes128", "", key, iv), key, iv)
  assert_equal("", res)
end

end

if not _TEST then lunit.run() end