
### COMMON ###

# includes
PCAPPP_INCLUDES := -I/usr/local/include/pcapplusplus


# libs
PCAPPP_LIBS := -lPcap++ -lPacket++ -lCommon++

# post build
PCAPPP_POST_BUILD :=

# build flags
PCAPPP_BUILD_FLAGS :=

ifdef PCAPPP_ENABLE_CPP_FEATURE_DETECTION
	PCAPPP_BUILD_FLAGS += -DPCAPPP_CPP_FEATURE_DETECTION -std=c++11
endif

ifndef CXXFLAGS
CXXFLAGS := -O2 -g -Wall
endif

PCAPPP_BUILD_FLAGS += $(CXXFLAGS)
### LINUX ###

# includes
PCAPPP_INCLUDES += -I/usr/include/netinet

# libs
PCAPPP_LIBS += -lpcap -lpthread

# allow user to add custom LDFLAGS
PCAPPP_BUILD_FLAGS += $(LDFLAGS)


# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o out/Main.o cpp/Main.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/Parser.o cpp/Parser.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/Matcher.o cpp/Matcher.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/RuleReader.o cpp/RuleReader.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/ActionTaker.o cpp/ActionTaker.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/Logger.o cpp/Logger.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/IptablesSetup.o cpp/IptablesSetup.cpp
	g++ $(PCAPPP_INCLUDES) -c -o out/ConfigReader.o cpp/ConfigReader.cpp
	g++ $(PCAPPP_LIBS_DIR) -o out/Magic out/Main.o out/Parser.o out/Matcher.o out/RuleReader.o out/ActionTaker.o out/Logger.o out/IptablesSetup.o out/ConfigReader.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm out/Magic out/Main.o out/Parser.o out/Matcher.o out/RuleReader.o out/ActionTaker.o out/Logger.o out/IptablesSetup.o out/ConfigReader.o
