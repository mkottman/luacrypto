local lunit = require "lunit"
local TEST_CASE = lunit.TEST_CASE

-- example of AES-256-CTR with custom counter

local function ichunks(len, chunk_size)
  return function(_, b)
    b = b + chunk_size
    if b > len then return nil end
    local e = b + chunk_size - 1
    if e > len then e = len end
    return b, e
  end, nil, -chunk_size + 1
end

-- custom IV counter
-- compatible with WinZip
local function inciv(iv)
  for k, v in ipairs(iv) do
    if v == 255 then iv[k] = 0
    else iv[k] = v + 1 return iv end
  end
end

-- compatible with OpenSSL
local function std_inciv(iv)
  for i = #iv, 1, -1 do
    if iv[i] == 255 then iv[i] = 0
    else iv[i] = iv[i] + 1 return iv end
  end
end

local crypto = require "crypto"

local _ENV = TEST_CASE"resetiv"

local IV, ctx
local block_size = 16
local msg        = ("012"):rep(3):rep(1333) .. 'abcd'
local KEY        = {0x04, 0xF9, 0x4A, 0xFB, 0x60, 0xAF, 0x47, 0x44, 0xD4, 0xDB, 0x9B, 0x3A, 0xE7, 0x23, 0x3E, 0xC6}

function setup()
  IV  = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
  ctx = assert_userdata(crypto.encrypt.new('aes-256-ctr', KEY))
end

function test_winzip()
  local t1 = {} ctx:set_writer(table.insert, t1)

  local t2 = {}

  for b, e in ichunks(#msg, block_size) do
    -- use same ctx, do not call msg:sub and use writer
    ctx:resetiv(inciv(IV))
    assert_equal(ctx, ctx:update(msg, b, e))

    -- each time call EVP Init/Update/Final
    local chunk = assert_string(crypto.encrypt('aes-256-ctr', msg:sub(b, e), KEY, IV))
    table.insert(t2, chunk)

    assert_equal(t2[#t2], t1[#t1])
  end

  assert_equal(ctx, ctx:final())

  assert_equal(table.concat(t2), table.concat(t1))
end

function test_std()
  local etalon = assert_string(crypto.encrypt('aes-256-ctr', msg, KEY, IV))

  local t = {} ctx:set_writer(table.insert, t)
  for b, e in ichunks(#msg, block_size) do
    ctx:resetiv(IV) std_inciv(IV)
    ctx:update(msg, b, e)
  end

  assert_equal(ctx, ctx:final())

  assert_equal(etalon, table.concat(t))
end

function test_fail()
  local etalon = assert_string(crypto.encrypt('aes-256-ctr', msg, KEY, IV))

  local t = {} ctx:set_writer(table.insert, t)
  for b, e in ichunks(#msg, block_size) do
    ctx:resetiv(IV) inciv(IV)
    ctx:update(msg, b, e)
  end

  assert_equal(ctx, ctx:final())

  assert_not_equal(etalon, table.concat(t))
end

if not _TEST then lunit.run() end