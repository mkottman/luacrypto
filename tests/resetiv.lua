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

local crypto = require "crypto"

local msg        = ("012"):rep(3):rep(1333) .. 'abcd'
local KEY        = {0x04, 0xF9, 0x4A, 0xFB, 0x60, 0xAF, 0x47, 0x44, 0xD4, 0xDB, 0x9B, 0x3A, 0xE7, 0x23, 0x3E, 0xC6}
local IV         = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
local block_size = 16

-- custom IV counter
-- compatible with WinZip
local function inciv(iv)
  for k, v in ipairs(iv) do
    if iv == 255 then iv[k] = 0
    else iv[k] = v + 1 return iv end
  end
end

local ctx = crypto.encrypt.new('aes-256-ctr', KEY)

local t1 = {} ctx:set_writer(table.insert, t1)

local t2 = {}

for b, e in ichunks(#msg, block_size) do
  -- use same ctx, do not call msg:sub and use writer
  ctx:resetiv(inciv(IV))
  ctx:update(msg, b, e)

  -- each time call EVP Init/Update/Final
  local chunk = crypto.encrypt('aes-256-ctr', msg:sub(b, e), KEY, IV)
  table.insert(t2, chunk)

  assert(t2[#t2] == t1[#t1])
end

assert(ctx == ctx:final())

assert(table.concat(t1) == table.concat(t2))

print("OK")