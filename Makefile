CC = gcc
FLAGS = --std=c99
DEVFLAGS = -Wall -Wextra

CFILES = main.c sha1.c commander.c
TARGET = hash_extension

all:
	$(CC) $(FLAGS) $(CFILES) -o $(TARGET)

devel:
	$(CC) $(FLAGS) $(DEVFLAGS) -g $(CFILES) -o $(TARGET)

install:
	cp $(TARGET) /usr/bin/$(TARGET)

clean:
	rm hash_extension

