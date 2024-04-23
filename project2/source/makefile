CFLAGS=-lpthread -Wall
CC=g++
COMMON_DEPDENDENCIES=spoofAttack.o arpSocket.o ipSocket.o

all: mitm_attack pharm_attack
	cp mitm_attack ..
	cp pharm_attack ..

.PHONY: clean

mitm_attack: $(COMMON_DEPDENDENCIES) mitmAttack.o mitm_main.o
	$(CC) -o $@ $^ $(CFLAGS)

pharm_attack: $(COMMON_DEPDENDENCIES) pharmAttack.o pharm_main.o
	$(CC) -o $@ $^ $(CFLAGS)

%.o: %.cpp
	$(CC) -c $< -o $@ $(CFLAGS)

clean: 
	rm -f *.o mitm_attack pharm_attack