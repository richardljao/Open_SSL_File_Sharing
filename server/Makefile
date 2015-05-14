LIBS = -l ssl -l crypto
CC = g++

## Global header files
INCLUDE =

## Object files and executables
MAIN_OUT = server

## Requirements for each command
MAIN_REQS = server.cpp

## Targets to compile for each command
MAIN_TARGETS = server.cpp

all: main

## Main 
main: $(MAIN_REQS)
	$(CC) $(MAIN_TARGETS) $(LIBS) -o $(MAIN_OUT)

clean:
	rm -f *~ *.o *.out
