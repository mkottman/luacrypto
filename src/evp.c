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

#include "evp.h"

#include "lua.h"
#include "lauxlib.h"

static EVP_MD_CTX *Pget(lua_State *L, int i)
{
 if (luaL_checkudata(L, i, EVP_TYPE) == NULL) luaL_typerror(L, i, EVP_TYPE);
 return lua_touserdata(L, i);
}

static EVP_MD_CTX *Pnew(lua_State *L)
{
  EVP_MD_CTX *c = lua_newuserdata(L, sizeof(EVP_MD_CTX));
  luaL_getmetatable(L, EVP_TYPE);
  lua_setmetatable(L, -2);
  return c;
}

static int Lnew(lua_State *L)			/** new(type) */
{
  EVP_MD_CTX *c = NULL;
  const char *s = luaL_checkstring(L, 1);
  const EVP_MD *type = EVP_get_digestbyname(s);
  
  if (type == NULL) {
    luaL_argerror(L, 1, "invalid digest type");
    return 0;
  }
  
  c = Pnew(L);
  EVP_MD_CTX_init(c);
  EVP_DigestInit_ex(c, type, NULL);
  
  return 1;
}

static int Lclone(lua_State *L)			/** clone(c) */
{
 EVP_MD_CTX *c = Pget(L, 1);
 EVP_MD_CTX *d = Pnew(L);
 EVP_MD_CTX_init(d);
 EVP_MD_CTX_copy_ex(d, c);
 return 1;
}

static int Lreset(lua_State *L)			/** reset(c) */
{
  EVP_MD_CTX *c = Pget(L, 1);
  const EVP_MD *t = EVP_MD_CTX_md(c);
  EVP_MD_CTX_cleanup(c);
  EVP_MD_CTX_init(c);
  EVP_DigestInit_ex(c, t, NULL);
  return 0;
}

static int Lupdate(lua_State *L)		/** update(c, s) */
{
  EVP_MD_CTX *c = Pget(L, 1);
  const char *s = luaL_checkstring(L, 2);
  
  EVP_DigestUpdate(c, s, lua_strlen(L, 2));
  
  return 0;
}

static int Ldigest(lua_State *L)		/** digest(c, s, [raw]) */ 
{
  EVP_MD_CTX *c = Pget(L, 1);
  EVP_MD_CTX *d = NULL;
  unsigned char digest[EVP_MAX_MD_SIZE];
  size_t written = 0;
  
  if (lua_isstring(L, 2))
  {  
    const char *s = luaL_checkstring(L, 2);
    EVP_DigestUpdate(c, s, lua_strlen(L, 2));
  }
  
  d = EVP_MD_CTX_create();
  EVP_MD_CTX_copy_ex(d, c);
  EVP_DigestFinal_ex(d, digest, &written);
  EVP_MD_CTX_destroy(d);
  
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
  EVP_MD_CTX *c = Pget(L, 1);
  char s[64];
  sprintf(s, "%s %p", EVP_NAME, (void *)c);
  lua_pushstring(L, s);
  return 1;
}

static int Lgc(lua_State *L)
{
  EVP_MD_CTX *c = Pget(L, 1);
  EVP_MD_CTX_cleanup(c);
  return 1;
}

static int Lfdigest(lua_State *L)		/** digest(type, s, [raw]) */ 
{
  EVP_MD_CTX *c = NULL;
  const char *type_name = luaL_checkstring(L, 1);
  const char *s = luaL_checkstring(L, 2);
  const EVP_MD *type = EVP_get_digestbyname(type_name);
  unsigned char digest[EVP_MAX_MD_SIZE];
  size_t written = 0;
  
  if (type == NULL) {
    luaL_argerror(L, 1, "invalid digest type");
    return 0;
  }
  
  c = EVP_MD_CTX_create();
  EVP_DigestInit_ex(c, type, NULL);
  EVP_DigestUpdate(c, s, lua_strlen(L, 2));
  EVP_DigestFinal_ex(c, digest, &written);
  
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

static const luaL_reg f[] =
{
  { "digest", Lfdigest },
  { "new", Lnew },
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

extern int luaopen_crypto_evp_core(lua_State *L)
{
  luaL_newmetatable(L, EVP_TYPE);
  lua_pushstring(L, "__index");
  lua_pushvalue(L, -2);
  lua_settable(L, -3);
  
  luaL_openlib(L, NULL, m, 0);
  luaL_openlib(L, EVP_NAME, f, 0);
  
  lua_pushliteral(L, "version");
  lua_pushliteral(L, EVP_VERSION);
  lua_settable(L, -3);
  
  return 1;
}
