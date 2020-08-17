CXX := g++
SYS = $(shell $(CXX) -dumpmachine)

STATIC := no
DEBUG  := no

SYG_SRC = sygcpp.cpp
SYGCPP  = sygcpp

ifeq ($(DEBUG),yes)
	CXX_DEBUG = -g
else
	LD_DEBUG = -s -Os
endif

CXXFLAGS = $(CXX_DEBUG) -fPIC
LDFLAGS  = $(LD_DEBUG)

SYG_OBJS = $(patsubst %.cpp,obj/%.o,$(SYG_SRC))

ifneq (, $(findstring mingw, $(SYS))$(findstring cygwin, $(SYS)))
	include Makefile.mingw
else
	ifeq ($(STATIC),yes)
		LIBPATH = /usr/lib/$(SYS)
		LDLIBS  = -pthread $(LIBPATH)/libcrypto.a -lpthread -ldl
	else ifeq ($(STATIC),full)
		LIBPATH = /usr/lib/$(SYS)
		LDFLAGS += -static
		LDLIBS  = -pthread $(LIBPATH)/libcrypto.a -lpthread -ldl
	else
		LDLIBS = -lcrypto -lpthread
	endif
endif

all: mk_obj_dir $(SYGCPP)

mk_obj_dir:
	@mkdir -p obj/windows

clean:
	$(RM) -r obj $(SYGCPP)

obj/%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(SYGCPP): $(SYG_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS)

.PHONY: all
.PHONY: clean
.PHONY: mk_obj_dir
