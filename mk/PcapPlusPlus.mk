PCAPPLUSPLUS_HOME := /PcapPlusPlus/Home/Dir

### COMMON ###

# includes
PCAPPP_INCLUDES := -I$(PCAPPLUSPLUS_HOME)/header

# libs dir
PCAPPP_LIBS_DIR := -L$(PCAPPLUSPLUS_HOME)/

# libs
PCAPPP_LIBS := -lPcap++ -lPacket++ -lCommon++

# post build
PCAPPP_POST_BUILD :=

# build flags
PCAPPP_BUILD_FLAGS :=

ifdef PCAPPP_ENABLE_CPP_FEATURE_DETECTION
	PCAPPP_BUILD_FLAGS += -DPCAPPP_CPP_FEATURE_DETECTION -std=c++11 
endif
### LINUX ###

# includes
PCAPPP_INCLUDES += -I/usr/include/netinet

# libs
PCAPPP_LIBS += -lpcap -lpthread

# allow user to add custom LDFLAGS
PCAPPP_BUILD_FLAGS += $(LDFLAGS)

