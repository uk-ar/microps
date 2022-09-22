APPS = 

DRIVERS = driver/dummy.o \
		  driver/loopback.o \

OBJS = util.o \
		net.o \
		ip.o \
		icmp.o \
		ether.o \
		arp.o \

TESTS = test/step0.exe \
		test/step15.exe \
		test/step16.exe \

#CFLAGS=-DHEXDUMP
CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -iquote .

ifeq ($(shell uname),Linux)
  # Linux specific settings
  LDFLAGS := $(LDFLAGS) -lrt
  BASE = platform/linux
  CFLAGS := $(CFLAGS) -pthread -iquote $(BASE)
  OBJS := $(OBJS) $(BASE)/intr.o
  DRIVERS := $(DRIVERS) $(BASE)/driver/ether_tap.o
endif

ifeq ($(shell uname),Darwin)
  # macOS specific settings
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TESTS)

$(APPS): %.exe : %.o $(OBJS) $(DRIVERS) net.h ip.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TESTS): %.exe : %.o $(OBJS) $(DRIVERS) test/test.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:.exe=.o) $(OBJS) $(DRIVERS) $(TESTS) $(TESTS:.exe=.o)
