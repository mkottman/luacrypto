/*
** $Id: lcrypto.h,v 1.1 2006-08-22 19:18:42 nezroy Exp $
** See Copyright Notice in license.html
*/

#ifndef _LUACRYPTO_
#define _LUACRYPTO_

#ifndef LUACRYPTO_API
#define LUACRYPTO_API
#endif

#define LUACRYPTO_PREFIX "LuaCrypto: "
#define LUACRYPTO_CORENAME "crypto"
#define LUACRYPTO_EVPNAME "crypto.evp"
#define LUACRYPTO_HMACNAME "crypto.hmac"
#define LUACRYPTO_RANDNAME "crypto.rand"

LUACRYPTO_API int luacrypto_createmeta (lua_State *L, const char *name, const luaL_reg *methods);
LUACRYPTO_API void luacrypto_setmeta (lua_State *L, const char *name);
LUACRYPTO_API void luacrypto_set_info (lua_State *L);


#endif
