MAKEFLAGS += -s

PROJECT = spawn

CCX64	= x86_64-w64-mingw32-gcc
CCX86	= i686-w64-mingw32-gcc

INC      = -I include

all: x64

x64: 
	$(CCX64) $(INC) -w -Os -nostdlib src/qa.c -o dist/"$(PROJECT).x64.exe" -lkernel32 -lmsvcrt
