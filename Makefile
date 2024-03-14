CC = cc
SRC = alloctracker.c bt.c
OBJ = $(patsubst %.c, bin/%.o, $(SRC))

default: bin/alloctracker.so

clean:
	rm -rf bin

bin:
	mkdir -p bin

bin/%.o : src/%.c bin
	$(CC) -O0 -g $(CFLAGS) -O0 -g -Wall -std=c99 -Wformat -Wformat-security -Wunused -Wno-unknown-pragmas -fPIC -c $< -o $@

bin/alloctracker.so: $(OBJ)
	$(CC) -O0 -g $(CFLAGS) -O0 -g -Wall -shared $(OBJ) -o $@ $(LDFLAGS) -Wl,--no-as-needed -ldl
	
