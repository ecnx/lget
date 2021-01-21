# Lemonade Get Utility Makefile
INCLUDES=-I include -I lib
INDENT_FLAGS=-br -ce -i4 -bl -bli0 -bls -c4 -cdw -ci4 -cs -nbfda -l100 -lp -prs -nlp -nut -nbfde -npsl -nss

OBJS = \
	bin/main.o \
	bin/http.o \
	bin/socks5.o \
	bin/dns.o \
	bin/util.o

all: host

internal: prepare
	@echo "  CC    src/main.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/main.c -o bin/main.o
	@echo "  CC    src/http.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/http.c -o bin/http.o
	@echo "  CC    src/socks5.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/socks5.c -o bin/socks5.o
	@echo "  CC    lib/dns.c"
	@$(CC) $(CFLAGS) $(INCLUDES) lib/dns.c -o bin/dns.o
	@echo "  CC    src/util.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/util.c -o bin/util.o
	@echo "  LD    bin/lget"
	@$(LD) -o bin/lget $(OBJS) $(LDFLAGS)

prepare:
	@mkdir -p bin

host:
	@make internal \
		CC=gcc \
		LD=gcc \
		CFLAGS='-c -Wall -Wextra -O2 -ffunction-sections -fdata-sections -Wstrict-prototypes' \
		LDFLAGS='-s -Wl,--gc-sections -Wl,--relax'

host32:
	@make internal \
		CC=gcc \
		LD=gcc \
		CFLAGS='-c -Wall -Wextra -Os -ffunction-sections -fdata-sections -Wstrict-prototypes -m32' \
		LDFLAGS='-s -Wl,--gc-sections -Wl,--relax -m32'

x86_64:
	@make internal \
		CC=gcc \
		LD=gcc \
		CFLAGS='-c -Wall -Wextra -ffunction-sections -fdata-sections -Os' \
		LDFLAGS='-s -Wl,--gc-sections -Wl,--relax -nostdlib -L $(ESLIB_DIR) -les-x86_64'

x86_32:
	@make internal \
		CC=gcc \
		LD=gcc \
		CFLAGS='-m32 -c -Wall -Wextra -ffunction-sections -fdata-sections -Os' \
		LDFLAGS='-m32 -s -Wl,--gc-sections -Wl,--relax -nostdlib -L $(ESLIB_DIR) -les-x86_32'

mipsel:
	@make internal \
		CC=mips-unknown-linux-gnu-gcc \
		LD=mips-unknown-linux-gnu-gcc \
		CFLAGS='-c $(MIPSEL_CFLAGS) -I $(ESLIB_INC) -Os -EL' \
		LDFLAGS='$(MIPSEL_LDFLAGS) -L $(ESLIB_DIR) -les-mipsel-Os -EL'

mipseb:
	@make internal \
		CC=mips-unknown-linux-gnu-gcc \
		LD=mips-unknown-linux-gnu-gcc \
		CFLAGS='-c $(MIPSEB_CFLAGS) -I $(ESLIB_INC) -Os -EB' \
		LDFLAGS='$(MIPSEB_LDFLAGS) -L $(ESLIB_DIR) -les-mipseb-Os -EB'

arm:
	@make internal \
		CC=arm-linux-gnueabi-gcc \
		LD=arm-linux-gnueabi-gcc \
		CFLAGS='-c $(ARM_CFLAGS) -I $(ESLIB_INC) -Os' \
		LDFLAGS='$(ARM_LDFLAGS) -L $(ESLIB_DIR) -les-arm-Os'

install:
	cp -v bin/lget /usr/bin/lget

uninstall:
	rm -fv /usr/bin/lget

post:
	@echo "  STRIP lget"
	@sstrip bin/lget
	@echo "  UPX   lget"
	@upx bin/lget
	@echo "  LCK   lget"
	@perl -pi -e 's/UPX!/EsNf/g' bin/lget
	@echo "  AEM   lget"
	@nogdb bin/lget

post2:
	@echo "  STRIP lget"
	@sstrip bin/lget
	@echo "  AEM   lget"
	@nogdb bin/lget

indent:
	@indent $(INDENT_FLAGS) ./*/*.h
	@indent $(INDENT_FLAGS) ./*/*.c
	@rm -rf ./*/*~

clean:
	@echo "  CLEAN ."
	@rm -rf bin

analysis:
	@scan-build make
	@cppcheck --force */*.h
	@cppcheck --force */*.c
