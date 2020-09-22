include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o Main.o Main.cpp
	g++ $(PCAPPP_INCLUDES) -c -o Parser.o Parser.cpp
	g++ $(PCAPPP_INCLUDES) -c -o Matcher.o Matcher.cpp
	g++ $(PCAPPP_INCLUDES) -c -o RuleReader.o RuleReader.cpp
	g++ $(PCAPPP_INCLUDES) -c -o ActionTaker.o ActionTaker.cpp
	g++ $(PCAPPP_INCLUDES) -c -o Logger.o Logger.cpp
	g++ $(PCAPPP_INCLUDES) -c -o IptablesSetup.o IptablesSetup.cpp
	g++ $(PCAPPP_LIBS_DIR) -o Main Main.o Parser.o Matcher.o RuleReader.o ActionTaker.o Logger.o IptablesSetup.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm Main.o Parser.o Matcher.o
	rm Main
