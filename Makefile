CC = gcc
FLAGS = --std=c99
DEVFLAGS = -Wall -Wextra

OBJECTS = sha1.o commander.o
CFILES = main.c sha1.c commander.c
TARGET = hash_extension

all: $(OBJECTS)
	$(CC) $(FLAGS) $(CFILES) -o $(TARGET)

devel: $(OBJECTS)
	$(CC) $(FLAGS) $(DEVFLAGS) -g $(CFILES) -o $(TARGET)

%.o: %.c
	$(CC) $(FLAGS) -c $<

clean:
	rm *.o hash_extension

