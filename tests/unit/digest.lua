--[[
-- $Id: test.lua,v 1.3 2006/08/25 03:24:17 nezroy Exp $
-- See Copyright Notice in license.html
--]]

local lunit = require "lunit"
local TEST_CASE = lunit.TEST_CASE
local crypto = require("crypto")

local hmac_key = "luacrypto"

local function make_test(t, st, msg, KNOWN)

  local _ENV = TEST_CASE ("digest." .. t .. "." .. st)

  local etalon = KNOWN[t]

  local d

  local pos

  local function read(n)
    if n == "*all" then return msg end
    if pos > #msg then return nil end
    local i = pos
    pos = pos + n
    return (msg:sub(i, pos - 1))
  end

  function setup()
    pos = 1
    if (t == "hmac") then
      d = assert_userdata(crypto.hmac.new("sha1", hmac_key))
    else
      d = assert_userdata(crypto.digest.new(t))
    end
  end

  function teardown()
    pos = nil
    d = nil
  end

  function test_all()
    local msg = read("*all")
    assert_equal(etalon, d:final(msg), "all")
  end

  function test_loop()
    while true do
      local c = read(1)
      if c == nil then break end
      d:update(c)
    end
    assert_equal(etalon, d:final(), "loop")
    assert_equal(etalon, d:final(), "again")
  end

  function test_digest()
    local msg = read("*all")
    local h
    if (t ~= "hmac") then
      h = assert_string(crypto.digest(t, msg))
    else
      h = assert_string(crypto.hmac.digest("sha1", msg, hmac_key))
    end
    assert_equal(etalon, h, "alone")
  end

  function test_reset()
    d:update("hello")
    d:reset()

    while true do
     local c = read(math.random(1, 16))
     if c == nil then break end
     d:update(c)
    end
    assert_equal(etalon, d:final(), "reset")
  end

  function test_clone()
    local d2
    while true do
      local c = read(1)
      if c == nil then break end
      d:update(c)
      if not d2 then d2 = d:clone() else d2:update(c) end
    end
    assert_equal(etalon, d:final(), "clone")
    assert_equal(etalon, d2:final(), "clone")
  end

end

local msg = "This is a sample message to use for hashing tests.\n"
local KNOWN = {
  md5  = "09920f6f666f8e7b09a8d00bd4d06873";
  sha1 = "d6ed6e26ebeb37ba0792ec75a3d0b4dcec279d25";
  hmac = "70a7ea81a287d094c534cdd67be82e85066e13be";
}

for i, t in ipairs({"sha1", "md5", "hmac"}) do
  make_test(t, "origin", msg, KNOWN)
end

local msg      = ("01"):rep(3):rep(1333) .. 'abcd'
local KNOWN = {
  sha1 = "adc089981eafcc442be904dc6dcbd488ef659c92";
  md5  = "f4432f3bdbcb4c9f590cefd5aee17ef9";
  hmac = "d91d232feecf25724fad0713bd0c5287863cc8bb";
}

for i, t in ipairs({"sha1", "md5", "hmac"}) do
  make_test(t, "large", msg, KNOWN)
end

if not _TEST then lunit.run() end