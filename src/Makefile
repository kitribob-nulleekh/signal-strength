LDLIBS=-lpcap

all: signal-strength

signal-strength: main.o packet.h mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm *.o beacon-flood
