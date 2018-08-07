--[[
-- $Id: test.lua,v 1.3 2006/08/25 03:24:17 nezroy Exp $
-- See Copyright Notice in license.html
--]]

local crypto = require("crypto")

local digest = crypto.digest
local hmac = crypto.hmac

md5_KNOWN = "f43a1e7c387d09db960c9608e5131418"
sha1_KNOWN = "b7ccc1777da5235737f6a65918b379e790f25b07"
hmac_KNOWN = "db66c0954cd5f65b8fd48a651990f33f89ec4b96"

print("LuaCrypto version: " .. crypto._VERSION)
print("")

function report(w, s, F, t)
  print(w, s .. "  " .. F)
  assert(s == _G[t .. "_KNOWN"])
end

F = arg[1] or 'message'
for i, t in ipairs({"sha1", "md5", "sha1", "hmac"}) do
  print("testing " .. t)
  local d
  if (t == "hmac") then
    d = crypto.hmac.new("sha1", "luacrypto")
  else
    d = crypto.digest.new(t)
  end
  
  assert(io.input(F))
  report("all", d:final(io.read("*all")), F, t)
  
  d:reset()
  
  assert(io.input(F))
  while true do
   local c = io.read(1)
   if c == nil then break end
   d:update(c)
  end
  report("loop", d:final(), F, t)
  if (t ~= "hmac") then
    report("again", d:final(), F, t)
    assert(io.input(F))
    report("alone", digest(t, io.read("*all")), F, t)
  else
    assert(io.input(F))
    report("alone", hmac.digest("sha1", io.read("*all"), "luacrypto"), F, t);
  end
  
  assert(io.input(F))
  d:reset()
  while true do
   local c = io.read(math.random(1, 16))
   if c == nil then break end
   d:update(c)
  end
  report("reset", d:final(d), F, t)
  report("known", _G[t .. "_KNOWN"], F, t)
  print("")
end

print("all tests passed")
