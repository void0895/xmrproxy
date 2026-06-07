# Makefile — Build system for xmr-proxy.
# Targets:
#   all      : build the xmr-proxy binary
#   clean    : remove object files and the binary

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -Isrc -pthread
LDFLAGS = -lpthread -lssl -lcrypto

SRCDIR = src
OBJDIR = obj
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))
TARGET = xmr-proxy

.PHONY: all clean

all: $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf $(OBJDIR) $(TARGET)
