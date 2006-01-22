/*
 * Copyright (c) 2006 Keith Howe <nezroy@luaforge.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include <stdio.h>

#include "crypto.h"

#include "lua.h"
#include "lauxlib.h"
#ifdef USE_COMPAT
  #include "compat-5.1.h"
#endif

/* code registered as functions */
static const luaL_reg f[] =
{
  { NULL, NULL }
};

/* code registered as methods */
static const luaL_reg m[] =
{
  { NULL, NULL }
};

extern int luaopen_crypto_core(lua_State *L)
{
  OpenSSL_add_all_digests();
  
  luaL_newmetatable(L, CRYPTO_TYPE);
  
  lua_pushstring(L, "__index");
  lua_pushvalue(L, -2);
  lua_settable(L, -3);
  
  luaL_openlib(L, NULL, m, 0);
  luaL_openlib(L, CRYPTO_NAME, f, 0);
  
  lua_pushliteral(L, "version");
  lua_pushliteral(L, CRYPTO_VERSION);
  lua_settable(L, -3);
  
  return 1;
}
