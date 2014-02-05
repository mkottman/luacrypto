package = "LuaCrypto"
version = "git-1"
description = {
	summary = "A Lua frontend to OpenSSL",
	detailed = [[LuaCrypto is a Lua frontend to the OpenSSL cryptographic library. The OpenSSL features that are currently exposed are: 
digests (MD5, SHA-1, HMAC, and more), encryption, decryption and crypto-grade random number generators.]],
	homepage = "http://mkottman.github.com/luacrypto/",
	license = "MIT",
}
dependencies = {
	"lua >= 5.1",
}
external_dependencies = {
	OPENSSL = {
		header = "openssl/evp.h"
	}
}
source = {
	url = "https://github.com/mkottman/luacrypto/archive/master.zip",
	dir = "luacrypto-master",
}
build = {
	platforms = {
		windows = {
			type = "command",
			build_command = [[vcbuild ./luacrypto.vcproj Release /useenv /rebuild]],
			install_command = [[copy ".\Release\crypto.dll" "$(LIBDIR)\crypto.dll" /y ]]
		},
		unix = {
			type = "builtin",
			modules = {
				crypto = {
					sources = "src/lcrypto.c",
					incdirs = "$(OPENSSL_INCDIR)",
					libdirs = "$(OPENSSL_LIBDIR)",
					libraries = "crypto",
				}
			}
		}
	},
	copy_directories = { "doc" }
}
