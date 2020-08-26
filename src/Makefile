include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o Main.o Main.cpp
	g++ $(PCAPPP_INCLUDES) -c -o Parser.o Parser.cpp
	g++ $(PCAPPP_LIBS_DIR) -o Main Main.o Parser.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm Main.o Parser.o
	rm Main
