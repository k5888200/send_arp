all: send_arp

send_arp: main.o ty_network.o
	g++ -o send_arp ty_network.o main.o -lpcap -O2

ty_network.o: ty_network.cpp ty_network.h
	g++ -c -o ty_network.o ty_network.cpp

main.o: main.cpp ty_network.h
	g++ -c -o main.o main.cpp

clean:
	rm *.o send_arp
