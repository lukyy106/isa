#AUTHOR : Eduard Frlička


# =========================================================================
# Names and Directories

# Flags for compiling
CFLAGS:=-std=c++11 -Wall -Wextra -pedantic -Wno-unused-variable

LFLAGS:=-lpcap

# Name of target binary file
BINARY_NAME:=binary

# Name / Path to bin folder (for storing binary files)
BIN:=bin

# Name / Path to folder, where .o files will be stored
OBJ:=obj

# Name / Path to folder, where source files are (.h .c .cpp ...)
SRC:=src

# Compiler
CC:=g++

# Suffix of files to compile (E.x.: c, cpp, c++)
SUFFIX:=cpp

# rm command
RM:=rm


# =========================================================================
# initializing global variables
BINARY_PATH=$(BIN)/$(BINARY_NAME)

SRC_DIRECTORIES=$(shell find $(SRC) -type d)

vpath %.$(SUFFIX) $(SRC_DIRECTORIES)
vpath %.h $(SRC_DIRECTORIES)

# Adding -I
INCLUDE:=$(foreach DIR, $(SRC_DIRECTORIES),-I $(DIR))

SOURCES := $(foreach DIR,$(SRC_DIRECTORIES),$(notdir $(wildcard $(DIR)/*.$(SUFFIX))))
OBJECTS := $(patsubst %.$(SUFFIX),$(OBJ)/%.o,$(SOURCES))
HEADERS := $(foreach DIR,$(SRC_DIRECTORIES),$(notdir $(wildcard $(DIR)/*.h)))


# =========================================================================
# Targets
.PHONY:  all run clean cleanall source


# =========================================================================
# Rules
all: $(BINARY_PATH)

run: $(BINARY_PATH)
	./$(BINARY_PATH)

$(BINARY_PATH) : $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ -o $@ $(LFLAGS) $(INCLUDE)

$(OBJ)/%.o: %.$(SUFFIX) $(HEADERS)
	@mkdir -p $(@D)
	$(CC)  $< -c -o $@ $(CFLAGS) $(INCLUDE)


source:
	@echo "Sources: " $(SOURCES)
	@echo "Headers: " $(HEADERS)
	@echo "Objects: " $(OBJECTS)
	@echo "Source_Folders: " $(SRC_DIRECTORIES)


# =========================================================================
# Cleaning rules
clean:
	$(RM) $(OBJ)/*.o

cleanall:
	$(RM) -rf $(OBJ) $(BIN)
