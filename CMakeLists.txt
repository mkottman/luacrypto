# Copyright (C) 2007-2009 LuaDist.
# Created by Peter Kapec
# Redistribution and use of this file is allowed according to the terms of the MIT license.
# For details see the COPYRIGHT file distributed with LuaDist.
# Please note that the package source code is licensed under its own license.

PROJECT(luacrypto C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
INCLUDE(dist.cmake)

# Find libraries
FIND_PATH( OPENSSL_INCLUDE_DIR NAMES openssl/err.h)
INCLUDE_DIRECTORIES( ${OPENSSL_INCLUDE_DIR})
FIND_LIBRARY ( CRYPTO_LIBRARY NAMES crypto )
FIND_LIBRARY ( SSL_LIBRARY NAMES ssl)
IF(WIN32)
	SET(LIBS gdi32)
ENDIF()
INCLUDE_DIRECTORIES(src)

IF (WIN32)
	ADD_DEFINITIONS("-DLUACRYPTO_API=__declspec(dllexport)")
ENDIF (WIN32)

ADD_LUA_MODULE(crypto src/lcrypto.c)
TARGET_LINK_LIBRARIES(crypto ${CRYPTO_LIBRARY} ${SSL_LIBRARY} ${LIBS})

# Install all files and documentation
INSTALL (TARGETS crypto DESTINATION ${INSTALL_CMOD})
INSTALL (FILES README DESTINATION ${INSTALL_DATA})
INSTALL (DIRECTORY doc DESTINATION ${INSTALL_DATA})
INSTALL (DIRECTORY tests/ DESTINATION ${INSTALL_TEST})
