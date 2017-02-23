#
# This makefile system follows the structuring conventions
# recommended sby Peter Miller in his excellent paper:
#
#	Recursive Make Considered Harmful
#	http://aegis.sourceforge.net/auug97.pdf
#
BINDIR := bin

# Lists all the makefrags add to
SRCDIRS :=
# Include Makefrags for subdirectories
include src/Makefrag

# How to make:
TOP = .

CC	:= gcc -pipe
CPP	:= g++ -pipe

PERL	:= perl

# Compiler flags
# -MD is needed for mergedep.pl to work don't remove!
CFLAGS := $(CFLAGS) -MD
CFLAGS += -I../kern -Isrc

CFLAGS += -g -Wall -Wno-unused -Wpointer-arith -Wundef -fpermissive
CFLAGS += -O3

#C++ specific flags
CPPFLAGS := $(CFLAGS)
CPPFLAGS += -std=c++14

LDFLAGS :=

# Chacha
LDFLAGS += -lchacha

# Pthreads
CFLAGS += -pthread
LDFLAGS += -pthread

# Make sure that 'all' is the first target
all:

# Eliminate default suffix rules
.SUFFIXES:

# Delete target files if there is an error (or make is interrupted)
.DELETE_ON_ERROR:

# make it so that no intermediate .o files are ever deleted
#.PRECIOUS: %.o

# Set to nothing (i.e., V = ) to enable verbose outputs.
V = @

# Autoparallelize everything below
ifeq ($(MAKEFLAGS),)
%:
	@echo 'MAKEFLAGS not set, re-running make with -j8'
	@$(MAKE) -j8 $@
else

# How to build C++ files
APPS_OBJFILES := $(patsubst %.cc, $(BINDIR)/%.o, $(APPS_CPPFILES))
SRC_OBJFILES := $(patsubst %.cc, $(BINDIR)/%.o, $(SRC_CPPFILES))

# compile (C++)
$(SRC_OBJFILES) $(APPS_OBJFILES) : $(BINDIR)/%.o : %.cc
	@echo + cpp $<
	@mkdir -p $(@D)
	$(V)$(CPP) $(CPPFLAGS) $(SITEVM_CFLAGS) -c -o $@ $<

#Linker has the same args regardless of language of app
#APPS_CPPFILES must be a subset of SRC_CPPFILES
APPS_BINS := $(patsubst %.cc, $(BINDIR)/%, $(APPS_CPPFILES))
$(APPS_BINS) : $(BINDIR)/% : $(BINDIR)/%.o $(SRC_OBJFILES)
	@mkdir -p $(@D)
	@echo + mk $@
	$(V)$(CPP) -o $@ $^ $(LDFLAGS)

#Matter of style - by marking all as phony and giving it a body
#(that does nothing) - make doesn't emit the "nothing to do" message
#which otherwise just clutters script output
all: $(APPS_BINS)
	@true

# For deleting the build
clean:
	rm -rf $(BINDIR)

# This magic automatically generates makefile dependencies
# for header files included from C source files we compile,
# and keeps those dependencies up-to-date every time we recompile.
# See '../mergedep.pl' for more information.
$(BINDIR)/.deps: $(foreach dir, $(SRCDIRS), $(wildcard $(BINDIR)/$(dir)/*.d))
	@mkdir -p $(@D)
	@$(PERL) ../build-dep/mergedep.pl $@ $^

-include $(BINDIR)/.deps

endif
