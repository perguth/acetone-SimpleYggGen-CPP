SYS := $(shell $(CXX) -dumpmachine)
CXX      = g++

SYG_SRC = sygcpp2.0.cpp
SYGCPP  = sygcpp

LDFLAGS = -O3 -s
LDLIBS  = -lcrypto -lpthread

SYG_OBJS += $(patsubst %.cpp,obj/%.o,$(SYG_SRC))

ifneq (, $(findstring mingw, $(SYS))$(findstring cygwin, $(SYS)))
	include Makefile.mingw
endif

all: mk_obj_dir $(SYGCPP)

mk_obj_dir:
	@mkdir -p obj/windows

clean:
	$(RM) -r obj $(SYGCPP)

obj/%.o: %.cpp
	$(CXX) -c -o $@ $<

$(SYGCPP): $(SYG_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS)

.PHONY: all
.PHONY: clean
.PHONY: mk_obj_dir
