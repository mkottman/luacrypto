#!/usr/local/bin/lua50
--[[
-- Copyright (c) 2006 Keith Howe <nezroy@luaforge.net>
--
-- Permission is hereby granted, free of charge, to any person obtaining a
-- copy of this software and associated documentation files (the "Software"),
-- to deal in the Software without restriction, including without limitation
-- the rights to use, copy, modify, merge, publish, distribute, sublicense,
-- and/or sell copies of the Software, and to permit persons to whom the
-- Software is furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included
-- in all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
-- OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
-- FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
-- DEALINGS IN THE SOFTWARE.
--
--]]

require("crypto")
local evp = crypto.evp
local hmac = crypto.hmac

md5_KNOWN = "09920f6f666f8e7b09a8d00bd4d06873"
sha1_KNOWN = "d6ed6e26ebeb37ba0792ec75a3d0b4dcec279d25"
hmac_KNOWN = "70a7ea81a287d094c534cdd67be82e85066e13be"

print("LuaCrypto version: " .. crypto._VERSION)
print("")

function report(w, s, F, t)
  print(w, s .. "  " .. F)
  assert(s == _G[t .. "_KNOWN"])
end

F = arg[1]
for i, t in ipairs({"sha1", "md5", "sha1", "hmac"}) do
  print("testing " .. t)
  local d
  if (t == "hmac") then
    d = hmac.new("sha1", "luacrypto")
  else
    d = evp.new(t)
  end
  
  assert(io.input(F))
  report("all", d:digest(io.read("*all")), F, t)
  
  d:reset(d)
  
  assert(io.input(F))
  while true do
   local c = io.read(1)
   if c == nil then break end
   d:update(c)
  end
  report("loop", d:digest(), F, t)
  if (t ~= "hmac") then
    report("again", d:digest(), F, t)
    assert(io.input(F))
    report("alone", evp.digest(t, io.read("*all")), F, t)
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
  report("reset", d:digest(d), F, t)
  report("known", _G[t .. "_KNOWN"], F, t)
  print("")
end

print("all tests passed")
