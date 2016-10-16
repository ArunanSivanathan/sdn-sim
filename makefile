INCLUDES =./include
CC=gcc
CFLAGS =-I$(INCLUDES)

BIN=./bin
BUILD=./build
SOURCE=./src
BINDIR=./bin

LIBS=-lpcap

_DEPS =equeue.h service.h dbg.h controller.h dsetime.h detect_PF.h dosCheck.h
DEPS = $(patsubst %,$(INCLUDES)/%,$(_DEPS))

_OBJ = equeue.o service.o main.o dbg.o controller.o  dsetime.o detect_PF.o dosCheck.o
OBJ = $(patsubst %,$(BUILD)/%,$(_OBJ))

$(BUILD)/%.o: $(SOURCE)/%.c $(DEPS)
	$(CC) -c -g -Wall -DNDEBUG -o $@ $< $(CFLAGS)

$(BIN)/sim: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(BUILD)/*.o $(BIN)/sim 