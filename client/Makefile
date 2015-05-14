LIBS = -l ssl -l crypto
CC = g++

## Global header files
INCLUDE =

## Object files and executables
MAIN_OUT = client

## Requirements for each command
MAIN_REQS = client.cpp

## Targets to compile for each command
MAIN_TARGETS = client.cpp

all: main

## Main 
main: $(MAIN_REQS)
	$(CC) $(MAIN_TARGETS) $(LIBS) -o $(MAIN_OUT)

clean:
	rm -f *~ *.o *.out
