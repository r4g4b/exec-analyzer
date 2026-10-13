CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = exec_analyzer
SRC = src/main.c src/options.c src/output.c src/binary.c src/pe.c src/elf.c src/macho.c

all: $(TARGET)

$(TARGET): $(SRC) $(wildcard src/*.h)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET) $(TARGET).exe
