#
CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Iinclude
LDFLAGS  := 

SRC_DIR  := source
TEST_DIR := tests
BUILD_DIR:= build

SRCS     := $(wildcard $(SRC_DIR)/*.cpp)
OBJS     := $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRCS))
TARGET   := $(BUILD_DIR)/libmy_crypto.a

TEST_SRCS := $(wildcard $(TEST_DIR)/*.cpp)
TEST_BINS := $(patsubst $(TEST_DIR)/%.cpp, $(BUILD_DIR)/%, $(TEST_SRCS))

.PHONY: all clean tests run_tests

all: $(TARGET) tests

$(TARGET): $(OBJS)
	@mkdir -p $(BUILD_DIR)
	ar rcs $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

tests: $(TARGET) $(TEST_BINS)

$(BUILD_DIR)/%: $(TEST_DIR)/%.cpp $(TARGET)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< -L$(BUILD_DIR) -lmy_crypto -o $@ $(LDFLAGS)

run_tests: tests
	@for test in $(TEST_BINS); do \
		echo "Running $$test..."; \
		./$$test || exit 1; \
	done


clean:
	rm -rf $(BUILD_DIR)