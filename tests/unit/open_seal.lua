local function ichunks(len, chunk_size)
  return function(_, b)
    b = b + chunk_size
    if b > len then return nil end
    local e = b + chunk_size - 1
    if e > len then e = len end
    return b, e
  end, nil, -chunk_size + 1
end

local lunit = require "lunit"
local TEST_CASE = lunit.TEST_CASE
local crypto = require 'crypto'

local FAIL = function(str) return function() lunit.fail(str) end end

local _ENV = TEST_CASE"open/seal"

if     not crypto.pkey then test = FAIL"crypto.pkey is unavaliable"
elseif not crypto.open then test = FAIL"crypto.open is unavaliable"
elseif not crypto.seal then test = FAIL"crypto.seal is unavaliable"
else

local message = string.rep('This message will be signed', 122)
local kpub, kpriv

function setup()
  local k = assert_userdata(crypto.pkey.generate('rsa', 1024), "no key generated")
  k:write('pub.pem', 'priv.pem')
  kpub  = assert_userdata(crypto.pkey.read('pub.pem'))
  kpriv = assert_userdata(crypto.pkey.read('priv.pem', true))
end

function teardown()
  os.remove('pub.pem')
  os.remove('priv.pem')
end

function test_cycle()
  local data, ek, iv = assert_string(crypto.seal("aes128", message, kpub))
  assert_equal(message, crypto.open("aes128", data, kpriv, ek, iv))
end

function test_cycle_update()
  local ctx = assert_userdata(crypto.seal.new("aes128", kpub))
  local p1  = assert_string(ctx:update(message))
  local p2, ek_2, iv_2 = assert_string(ctx:final())
  assert_string(ek_2)
  assert_string(iv_2)

  assert_equal(message, crypto.open("aes128", p1..p2, kpriv, ek_2, iv_2))

  local ctx = assert_userdata(crypto.open.new("aes128", kpriv, ek_2, iv_2))
  p3 = assert_string(ctx:update(p1..p2))
  p4 = assert_string(ctx:final())

  assert_equal(message, (p3 .. p4))
end

function test_cycle_update_by_range()
  local ctx = assert_userdata(crypto.seal.new("aes128", kpub))
  local p1 = ''
  for b,e in ichunks(#message, 25) do 
    p1 = p1 .. assert_string(ctx:update(message, b, e))
  end
  local p2, ek_2, iv_2 = assert_string(ctx:final())

  assert_equal(message, crypto.open("aes128", p1..p2, kpriv, ek_2, iv_2))

  local ctx = assert_userdata(crypto.open.new("aes128", kpriv, ek_2, iv_2))

  local p3 = assert_string(ctx:update(p1..p2, 1, #p1))
  p3 = p3 .. assert_string(ctx:update(p1..p2, #p1+1, #(p1..p2)))
  local p4 = assert_string(ctx:final())
  assert_equal(message, (p3 .. p4))
end

function test_cycle_writer()
  local ctx = assert_userdata(crypto.seal.new("aes128", kpub))
  local t = {}
  ctx:set_writer(table.insert, t)
  local a, b = ctx:get_writer()
  assert_equal(table.insert, a, b)
  assert_equal(t, b)
  assert_equal(ctx, ctx:update(message))
  local ek_2, iv_2 = assert_string(ctx:final())

  assert_equal(message, crypto.open("aes128", table.concat(t), kpriv, ek_2, iv_2))

  local ctx = assert_userdata(crypto.open.new("aes128", kpriv, ek_2, iv_2))
  local t2 = {}
  ctx:set_writer(table.insert, t2)
  local a, b = ctx:get_writer()
  assert_equal(table.insert, a, b)
  assert_equal(t2, b)

  assert_equal(ctx, ctx:update(table.concat(t)))
  assert_equal(ctx, ctx:final())

  assert_equal(message, table.concat(t2))
end

end

if not _TEST then lunit.run() end