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

#include "hmac.h"

#include "lua.h"
#include "lauxlib.h"
#ifdef USE_COMPAT
  #include "compat-5.1.h"
#endif

static HMAC_CTX *Pget(lua_State *L, int i)
{
 if (luaL_checkudata(L, i, HMAC_TYPE) == NULL) luaL_typerror(L, i, HMAC_TYPE);
 return lua_touserdata(L, i);
}

static HMAC_CTX *Pnew(lua_State *L)
{
  HMAC_CTX *c = lua_newuserdata(L, sizeof(HMAC_CTX));
  luaL_getmetatable(L, HMAC_TYPE);
  lua_setmetatable(L, -2);
  return c;
}

static int Lnew(lua_State *L)			/** new(type, key) */
{
  HMAC_CTX *c = Pnew(L);
  const char *s = luaL_checkstring(L, 1);
  const char *k = luaL_checkstring(L, 2);
  const EVP_MD *type = EVP_get_digestbyname(s);
  
  if (type == NULL) {
    luaL_argerror(L, 1, "invalid digest type");
    return 0;
  }
  
  HMAC_CTX_init(c);
  HMAC_Init_ex(c, k, lua_strlen(L, 2), type, NULL);
  
  return 1;
}

static int Lclone(lua_State *L)			/** clone(c) */
{
 HMAC_CTX *c = Pget(L, 1);
 HMAC_CTX *d = Pnew(L);
 *d = *c;
 return 1;
}

static int Lreset(lua_State *L)			/** reset(c) */
{
  HMAC_CTX *c = Pget(L, 1);
  HMAC_Init_ex(c, NULL, 0, NULL, NULL);
  return 0;
}

static int Lupdate(lua_State *L)		/** update(c, s) */
{
  HMAC_CTX *c = Pget(L, 1);
  const char *s = luaL_checkstring(L, 2);
  
  HMAC_Update(c, (unsigned char *)s, lua_strlen(L, 2));
  
  return 0;
}

static int Ldigest(lua_State *L)		/** digest(c, s, [raw]) */ 
{
  HMAC_CTX *c = Pget(L, 1);
  unsigned char digest[EVP_MAX_MD_SIZE];
  size_t written = 0;
  
  if (lua_isstring(L, 2))
  {  
    const char *s = luaL_checkstring(L, 2);
    HMAC_Update(c, (unsigned char *)s, lua_strlen(L, 2));
  }
  
  HMAC_Final(c, digest, &written);
  
  if (lua_toboolean(L, 3))
    lua_pushlstring(L, (char *)digest, written);
  else
  {
    int i;
    char *hex;
    hex = calloc(sizeof(char), written*2 + 1);
    for (i = 0; i < written; i++)
      sprintf(hex + 2*i, "%02x", digest[i]);
    lua_pushlstring(L, hex, written*2);
    free(hex);
  }
  
  return 1;
}

static int Ltostring(lua_State *L)		/** tostring(c) */
{
  HMAC_CTX *c = Pget(L, 1);
  char s[64];
  sprintf(s, "%s %p", HMAC_NAME, (void *)c);
  lua_pushstring(L, s);
  return 1;
}

static int Lgc(lua_State *L)
{
  HMAC_CTX *c = Pget(L, 1);
  HMAC_CTX_cleanup(c);
  return 1;
}

static int Lfdigest(lua_State *L)	/** digest(type, s, key, [raw]) */ 
{
  HMAC_CTX c;
  unsigned char digest[EVP_MAX_MD_SIZE];
  size_t written = 0;
  const char *t = luaL_checkstring(L, 1);
  const char *s = luaL_checkstring(L, 2);
  const char *k = luaL_checkstring(L, 3);
  const EVP_MD *type = EVP_get_digestbyname(t);
  
  if (type == NULL) {
    luaL_argerror(L, 1, "invalid digest type");
    return 0;
  }
  
  HMAC_CTX_init(&c);
  HMAC_Init_ex(&c, k, lua_strlen(L, 3), type, NULL);
  HMAC_Update(&c, (unsigned char *)s, lua_strlen(L, 2));
  HMAC_Final(&c, digest, &written);
  
  if (lua_toboolean(L, 4))
    lua_pushlstring(L, (char *)digest, written);
  else
  {
    int i;
    char *hex;
    hex = calloc(sizeof(char), written*2 + 1);
    for (i = 0; i < written; i++)
      sprintf(hex + 2*i, "%02x", digest[i]);
    lua_pushlstring(L, hex, written*2);
    free(hex);
  }
  
  return 1;
}

static const luaL_reg f[] =
{
  { "new", Lnew },
  { "digest", Lfdigest },
  { NULL, NULL }
};

static const luaL_reg m[] =
{
  { "__tostring",	Ltostring },
  { "__gc", Lgc },
  { "clone", Lclone },
  { "digest", Ldigest },
  { "reset", Lreset },
  { "tostring",	Ltostring },
  { "update",	Lupdate },
  { NULL, NULL }
};

extern int luaopen_crypto_hmac_core(lua_State *L)
{
  luaL_newmetatable(L, HMAC_TYPE);
  lua_pushstring(L, "__index");
  lua_pushvalue(L, -2);
  lua_settable(L, -3);
  
  luaL_openlib(L, NULL, m, 0);
  luaL_openlib(L, HMAC_NAME, f, 0);
  
  lua_pushliteral(L, "version");
  lua_pushliteral(L, HMAC_VERSION);
  lua_settable(L, -3);
  
  return 1;
}
