# 
# Copyright (c) 2016, Christian Limpach <Christian.Limpach@gmail.com>
# 
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# 

TOOLSDIR ?= /uxen/tools
SRCDIR ?= .
VPATH = $(SRCDIR)

$(HOST_WINDOWS)CC := $(TOOLSDIR)/bin/x86_64-w64-mingw32-gcc
$(HOST_WINDOWS)HOST_EXE_SUFFIX = .exe

all dist: dwarfcv$(HOST_EXE_SUFFIX) dump-cv$(HOST_EXE_SUFFIX)
	@ :

dwarfcv_SRCS = dwarfcv.c image.c lines.c symtypes.c rbtree.c
dwarfcv_OBJS  = $(patsubst %.c,%.o,$(dwarfcv_SRCS))
dwarfcv_OBJS := $(subst /,_,$(dwarfcv_OBJS))

dumpcv_SRCS = dump-cv.c
dumpcv_OBJS  = $(patsubst %.c,%.o,$(dumpcv_SRCS))
dumpcv_OBJS := $(subst /,_,$(dumpcv_OBJS))

MULTILIBDIR := $(TOOLSDIR)/host-all/lib/`$(CC) -print-multi-os-directory`
CPPFLAGS += -I$(TOOLSDIR)/host-all/include
dwarfcv_LDLIBS = -L$(TOOLSDIR)/host-all/lib -L$(MULTILIBDIR) \
	-lbfd -liberty
dumpcv_LDLIBS = -L$(TOOLSDIR)/host-all/lib -L$(MULTILIBDIR) \
	-lbfd -liberty

CFLAGS += -g -Wall -Werror
CFLAGS += -Wp,-MD,.$(subst /,_,$@).d -Wp,-MT,$@
LDFLAGS += -g

dwarfcv$(HOST_EXE_SUFFIX): $(dwarfcv_OBJS)
	$(LINK.o) -o $@ $^ $(dwarfcv_LDLIBS)

dump-cv$(HOST_EXE_SUFFIX): $(dumpcv_OBJS)
	$(LINK.o) -o $@ $^ $(dumpcv_LDLIBS)

-include .*.d

install:
	@install dwarfcv$(HOST_EXE_SUFFIX) $(PREFIX)/bin
	@install dump-cv$(HOST_EXE_SUFFIX) $(PREFIX)/bin

clean:
	@rm -f $(dwarfcv_OBJS) dwarfcv$(HOST_EXE_SUFFIX)
	@rm -f $(dumpcv_OBJS) dump-cv$(HOST_EXE_SUFFIX)
	@rm -f .*.d
