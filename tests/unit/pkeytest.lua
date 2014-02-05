
local lunit = require "lunit"
local TEST_CASE = lunit.TEST_CASE
local crypto = require 'crypto'

local FAIL = function(str) return function() lunit.fail(str) end end

local _ENV = TEST_CASE"pkey"
if     not crypto.pkey   then test = FAIL"crypto.pkey is unavaliable"
elseif not crypto.sign   then test = FAIL"crypto.sign is unavaliable"
elseif not crypto.verify then test = FAIL"crypto.verify is unavaliable"
else

local function test_verify(kpub, kpriv)
  local message = 'This message will be signed'

  local sig = assert_string(crypto.sign('md5', message, kpriv))
  local verified = crypto.verify('md5', message, sig, kpub)
  assert_true(verified, "message not verified")

  local nverified = crypto.verify('md5', message..'x', sig, kpub)
  assert_false(nverified, "message verified, when it shouldn't be")
end

local RSA_PUBLIC_KEY = [[
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAIy7sjJXo3ePWF1PZ81DelW1E
4VphWD+VPBzT8oCYY9dViJ4lszW/t5LX0IYAm+veuJyF5ffkAeeOWvI7vCg+5s3b
l9QqXgU8izuiXD0W6Wfm0YUU9VLGiFWnyTHpvZwqhnqmSEFCqPh+bWshCn/J5pZa
g8GOfgG42UgCrxnNWwIDAQAB
-----END PUBLIC KEY-----
]]

local RSA_PRIV_KEY = [[
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDAIy7sjJXo3ePWF1PZ81DelW1E4VphWD+VPBzT8oCYY9dViJ4l
szW/t5LX0IYAm+veuJyF5ffkAeeOWvI7vCg+5s3bl9QqXgU8izuiXD0W6Wfm0YUU
9VLGiFWnyTHpvZwqhnqmSEFCqPh+bWshCn/J5pZag8GOfgG42UgCrxnNWwIDAQAB
AoGAa2R++trNg75adbTOOnlEj1ToIWLwWI6x42EZH+JgvEy59GYLNzlG5qTd3+D+
tWJxYSjA3BqhBwGFgs0UrgzKVPwKbj1nbX0w91PmfdyGEutN84xRtZWkdMBiFacV
Hy8Y0rvw/xmlf39xkv1n8whtb7sKxZjxRwVWpSU2i5ovQ5kCQQD98agvwLRoJQ3e
AkuIpSNHfk9lRkr2A0ZHJjRRYOWN+xl/bShxMKCSrlzHqmIEd8wIkgXkWFSCDO4M
WcE3G2y3AkEAwbFr6SFQHqh48hO8Lq040S8y+wVZrH7DIwYM3Ckc7JnurFQP9B6U
2BOPsLuCNoWeMJOwyJiIXwd4KT7XvzAIfQJAbNAJ0zxtkVqfUIwHNawdK9tRxgGS
yUup537VWDF+65G24UUy2R2PEIsqMlwt1+BFSz7Wy3uV6owDzMMA6c4UjQJAJC/V
jVSf91paXj+5pK7QMqSyzZsOSd/U7TIwLOGxebK4mJGL+XvNKyFccxRVG4KTL1go
axG0SKzIkkwfWqTKsQJAf58QgbmGIwDwQgk2StWuulY9HhGpd73JySPyTKR2Lmpe
wDJiqtOCnY3hEss2co97U/vzL+Cic4hXT3gGAQiDwQ==
-----END RSA PRIVATE KEY-----
]]

function setup()
end

function teardown()
  os.remove('pub.pem')
  os.remove('priv.pem')
end

function test_predefine()
  local kpub  = assert_userdata(crypto.pkey.from_pem(RSA_PUBLIC_KEY))
  local kpriv = assert_userdata(crypto.pkey.from_pem(RSA_PRIV_KEY, true))

  assert_equal(RSA_PUBLIC_KEY, kpub:to_pem())
  assert_equal(RSA_PRIV_KEY,   kpriv:to_pem(true))

  test_verify(kpub, kpriv)
end

function test_generate()
  local k = crypto.pkey.generate('rsa', 1024)
  assert(k, "no key generated")

  k:write('pub.pem', 'priv.pem')
  local kpub = assert(crypto.pkey.read('pub.pem'))
  local kpriv = assert(crypto.pkey.read('priv.pem', true))

  test_verify(kpub, kpriv)
end

end

if not _TEST then lunit.run() end