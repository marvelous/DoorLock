CC      := gcc -g
CCFLAGS := -std=gnu11 -Wall -Wextra 
# CCFLAGS := -pedantic -std=gnu11 -Wall -Wextra -fsanitize=address -fsanitize=leak -fsanitize=undefined
# LDFLAGS := -lm -lSDL2 -lnetpbm -lSDL2_image

TARGETS := main
SOURCES := $(wildcard *.c)
OBJECTS := $(subst .c,.o,$(SOURCES)) main.o

.PHONY: all clean

all: $(TARGETS)

clean:
	rm -f $(TARGETS) $(OBJ);  clear

$(OBJ): %.o : %.c 
	$(CC) -c -o $@ $< $(CCFLAGS)

$(TARGETS): $(OBJECTS)
	$(CC) -o $@ $(LIBS) $^ $(CCFLAGS) $(LDFLAGS)

run:
	@echo "Launching main process ... "
	./main