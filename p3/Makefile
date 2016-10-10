OBJS = Main2.o EncryptionLibrary.o
CC = g++
DEBUG = -g
CFLAGS = -Wall -c $(DEBUG)
LFLAGS = -Wall $(DEBUG)

Main2.o : Main2.cpp EncryptionLibrary.h
    $(CC) $(CFLAGS) Main2.cpp

EncryptionLibrary.o : EncryptionLibrary.cpp EncryptionLibrary.h 
    $(CC) $(CFLAGS) EncryptionLibrary.cpp

clean:
    \rm *.o *~ p1
