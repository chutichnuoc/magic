include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o out/Main.o cpp/Main.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/Parser.o cpp/Parser.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/Matcher.o cpp/Matcher.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/RuleReader.o cpp/RuleReader.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/ActionTaker.o cpp/ActionTaker.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/Logger.o cpp/Logger.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/IptablesSetup.o cpp/IptablesSetup.cpp
	g++ $(PCAPPP_LIBS_DIR) -o out/Main out/Main.o out/Parser.o out/Matcher.o out/RuleReader.o out/ActionTaker.o out/Logger.o out/IptablesSetup.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm Main out/Main.o out/Parser.o out/Matcher.o out/RuleReader.o out/ActionTaker.o out/Logger.o out/IptablesSetup.o
	rm out/Main
