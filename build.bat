mkdir bin 2> NUL
::gcc -DHTTP_WIN32_SSL -Wall -Wextra -pedantic -ggdb -o bin\twitch src\main.c -lws2_32 -lsecur32
gcc -DHTTP_OPEN_SSL -Wall -Wextra -pedantic -ggdb -o bin\twitch src\main.c -lws2_32 -lssl -lcrypto
