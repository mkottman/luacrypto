local lunit = require "lunit"
local TEST_CASE = lunit.TEST_CASE
local crypto = require 'crypto'

local _ENV = TEST_CASE "update.range"

function test_digest()
  local str = ("0"):rep(32)
  local h1   = crypto.digest.new("md5")
  local thex = h1:final(str)
  local bhex = h1:final(nil, true)

  assert(thex == crypto.hex(bhex))

  do
    local h2 = crypto.digest.new("md5")
    local h = h2:update(str, 1, 16):final(str, 17, 32)
    assert(h == thex)
  end

  do
    local h2 = crypto.digest.new("md5")
    local h = h2:update(str, 1, 16):final(str, 17, 32, true)
    assert(h == bhex)
  end
end

function test_encrypt()
  local str  = ( "0"):rep(64)
  local key  = ( "0"):rep(32)
  local iv   = ("\0"):rep(16)
  local aes1 = crypto.encrypt.new('aes-256-cbc', key, iv)
  local edata = aes1:update(str)
  edata = edata .. aes1:final()
  assert(#edata == 80)

  do
    local aes2 = crypto.encrypt.new('aes-256-cbc', key, iv)
    local edata2 = aes2:update(str:sub(1, 32))
    edata2 = edata2 .. aes2:update(str:sub(33, 64))
    edata2 = edata2 .. aes2:final()
    assert(edata2 == edata)
  end

  do
    local aes3 = crypto.encrypt.new('aes-256-cbc', key, iv)
    local edata3 = aes3:update(str, 1, 32)
    edata3 = edata3 .. aes3:update(str, 33, 64)
    edata3 = edata3 .. aes3:final()
    assert(edata3 == edata)
  end

  do
    local aes2 = crypto.decrypt.new('aes-256-cbc', key, iv)
    local str2 = aes2:update(edata)
    str2 = str2 .. aes2:final()
    assert(str2 == str)
  end

  do
    local aes2 = crypto.decrypt.new('aes-256-cbc', key, iv)
    local str2 =   aes2:update(edata:sub( 1, 32))
    str2 = str2 .. aes2:update(edata:sub(33, 64))
    str2 = str2 .. aes2:update(edata:sub(65, 80))
    str2 = str2 .. aes2:final()
    assert(str2 == str)
  end

  do
    local aes2 = crypto.decrypt.new('aes-256-cbc', key, iv)
    local str2 =   aes2:update(edata,  1, 32)
    str2 = str2 .. aes2:update(edata, 33, 64)
    str2 = str2 .. aes2:update(edata, 65, 80)
    str2 = str2 .. aes2:final()
    assert(str2 == str)
  end
end

function test_hmac()
  local str = ("0"):rep(32)
  local key  = ( "0"):rep(32)
  local iv   = ("\0"):rep(16)
  local h1   = crypto.hmac.new("md5",key)
  local thex = h1:final(str)
  local bhex = h1:final(nil, true)

  assert(thex == crypto.hex(bhex))

  do
    local h2 = crypto.hmac.new("md5", key)
    local h = h2:update(str, 1, 16):final(str, 17, 32)
    assert(h == thex)
  end

  do
    local h2 = crypto.hmac.new("md5", key)
    local h = h2:update(str, 1, 16):final(str, 17, 32, true)
    assert(h == bhex)
  end

end

function test_clone()
  local key = ("0"):rep(32)
  local h1 = crypto.hmac.new("md5", key)
  h1:update("123456789")
  local h2 = h1:clone()
  assert(h2 ~= h1)
  assert(tostring(h2) ~= tostring(h1))
  h1:update("qwerty")
  h2:update("qwerty")
  assert(h1:final() == h2:final())
end

if not _TEST then lunit.run() end