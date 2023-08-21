@echo off
mkdir bin 2> NUL
where /q cl
IF ERRORLEVEL 1 (
   where /q gcc
   @echo on
   IF ERRORLEVEL 1 (
        echo "ERROR: Make sure to have msvc or mingw installed!"
	exit /b
   ) ELSE (     	
  	::gcc -DHTTP_OPEN_SSL -Wall -Wextra -pedantic -ggdb -o bin\twitch src\main.c -lws2_32 -lssl -lcrypto
	gcc -DHTTP_WIN32_SSL -Wall -Wextra -pedantic -ggdb -o bin\twitch src\main.c -lws2_32 -lsecur32
   )
) ELSE (
  @echo on
  ::cl /DHTTP_OPEN_SSL /Fe:bin\twitch src\main.c ws2_32.lib libsslMD.lib libcryptoMD.lib
  cl /DHTTP_WIN32_SSL /Fe:bin\twitch src\main.c ws2_32.lib secur32.lib
)

