PLUGIN_NAME := fpp-TuyaBridge
SONAME      := lib$(PLUGIN_NAME).so

# FPP source tree — override with: make FPP_SRC=/path/to/fpp/src
FPP_SRC ?= /opt/fpp/src

CXX      ?= g++
CXXFLAGS  = -std=gnu++20 -O2 -fPIC -Wall -Wextra
CXXFLAGS += -I$(FPP_SRC) -DNOPCH
# Silence "unused parameter" noise from FPP headers
CXXFLAGS += -Wno-unused-parameter

LDFLAGS   = -shared -fPIC
LDFLAGS  += -Wl,-rpath,'$$ORIGIN/../../../../src'   # find libfpp.so via relative path
LDFLAGS  += -Wl,-rpath,$(FPP_SRC)
LDLIBS    = -L$(FPP_SRC) -lfpp -ljsoncpp -lcrypto -lz

SRCS := src/TuyaProtocol.cpp \
        src/TuyaDevice.cpp   \
        src/TuyaBridgePlugin.cpp

OBJS := $(SRCS:.cpp=.o)

.PHONY: all install clean

all: $(SONAME)

$(SONAME): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Install the .so into the plugin directory (run as fpp user or with sudo)
INSTALL_DIR ?= /home/fpp/media/plugins/$(PLUGIN_NAME)

install: $(SONAME)
	install -m 755 $(SONAME) $(INSTALL_DIR)/

clean:
	rm -f $(OBJS) $(SONAME)
