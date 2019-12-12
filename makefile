CFLAGS := -Wall -Wextra -O2 -pthread
CXXFLAGS := $(CFLAGS) --std=c++17

LIBS := -ldl -lcrypto -lssl

SCANNER_DIR := Scanner
OBJDIR := build

SCANNER_SOURCES := $(wildcard $(SCANNER_DIR)/*.c) $(wildcard $(SCANNER_DIR)/*.cpp)
SCANNER_OBJS := $(patsubst $(SCANNER_DIR)/%.c,$(OBJDIR)/%.o,$(patsubst $(SCANNER_DIR)/%.cpp,$(OBJDIR)/%.o,$(SCANNER_SOURCES)))

all: scanner

clean:
	@rm -rf $(OBJDIR)/*

scanner: $(SCANNER_OBJS)
	$(CXX) -pthread $^ -o tlsscanner $(LIBS)

$(OBJDIR)/%.o: $(SCANNER_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

$(OBJDIR)/%.o: $(SCANNER_DIR)/%.c
	$(CC) $(CFLAGS) -c $^ -o $@