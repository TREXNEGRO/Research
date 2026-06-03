# Cross-compile BYOVD LSASS dump with MinGW-w64.
# Target: x86_64 Windows. PE output requires no MSVC.

CC      := x86_64-w64-mingw32-gcc
STRIP   := x86_64-w64-mingw32-strip

CFLAGS  := -Wall -Wextra -O2 -municode \
           -DWIN32_LEAN_AND_MEAN \
           -D_WIN32_WINNT=0x0A00 \
           -Iinclude -Isrc

LDFLAGS := -static -lkernel32 -ladvapi32 -ldbghelp -luser32 -lntdll

OUT     := build/byovd_lsass_dump.exe
SRCS    := src/main.c \
           src/driver_loader.c \
           src/driver_io.c \
           src/kernel_walker.c \
           src/ppl_disable.c \
           src/process_clone.c \
           src/minidump_inmemory.c \
           src/xor_obfusc.c \
           src/output.c
OBJS    := $(SRCS:.c=.o)

all: $(OUT)

$(OUT): $(OBJS)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	$(STRIP) $@
	@echo "[+] built $@ ($$(stat -c%s $@) bytes)"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(OUT)

.PHONY: all clean
