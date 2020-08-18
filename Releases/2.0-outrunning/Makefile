CXX := g++
SYS = $(shell $(CXX) -dumpmachine)

STATIC := no
DEBUG  := no

SYG_SRC = sygcpp.cpp
SYGCPP  = build/sygcpp

ifeq ($(DEBUG),yes)
	CXXFLAGS := -g -Og
	LDFLAGS := -Og
else
	CXXFLAGS := -O3
	LDFLAGS := -s -O3
endif

CXXFLAGS += -fPIC
SYG_OBJS = $(patsubst %.cpp,obj/%.o,$(SYG_SRC))

ifneq (, $(findstring mingw, $(SYS))$(findstring cygwin, $(SYS)))
	include Makefile.mingw
else
	ifeq ($(STATIC),yes)
		LIBPATH = /usr/lib/$(SYS)
		LDLIBS  = -pthread $(LIBPATH)/libsodium.a -lpthread -ldl
	else
		LDLIBS = -lsodium -lpthread
	endif
endif

all: mk_obj_dir $(SYGCPP)

mk_obj_dir:
	@mkdir -p obj/windows
	@mkdir -p build

clean:
	$(RM) -r obj $(SYGCPP)

obj/%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(SYGCPP): $(SYG_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS)

.PHONY: all
.PHONY: clean
.PHONY: mk_obj_dir
