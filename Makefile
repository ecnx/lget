# LGet Utility Makefile
INCLUDES=-I include
INDENT_FLAGS=-br -ce -i4 -bl -bli0 -bls -c4 -cdw -ci4 -cs -nbfda -l100 -lp -prs -nlp -nut -nbfde -npsl -nss

OBJS = \
	release/main.o \
	release/dns.o

all: host

internal: prepare
	@echo "  CC    src/main.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/main.c -o release/main.o
	@echo "  CC    src/dns.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/dns.c -o release/dns.o
	@echo "  LD    release/lget"
	@$(LD) -o release/lget $(OBJS) $(LDFLAGS)

prepare:
	@mkdir -p release

host:
	@make internal \
		CC=gcc \
		LD=gcc \
		CFLAGS='-c -Wall -Wextra -Os -ffunction-sections -fdata-sections' \
		LDFLAGS='-s -Wl,--gc-sections -Wl,--relax'

install:
	cp -v release/lget /usr/bin/lget

uninstall:
	rm -fv /usr/bin/lget

indent:
	@indent $(INDENT_FLAGS) ./*/*.h
	@indent $(INDENT_FLAGS) ./*/*.c
	@rm -rf ./*/*~

clean:
	@echo "  CLEAN ."
	@rm -rf release

analysis:
	@scan-build make
	@cppcheck --force */*.h
	@cppcheck --force */*.c
