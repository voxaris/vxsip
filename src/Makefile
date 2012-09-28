#****************************************************************************
# DEBUG can be set to YES to include debugging info, or NO otherwise
DEBUG          := YES
# PROFILE can be set to YES to include profiling info, or NO otherwise
PROFILE        := NO
# LIBRARY can be set to YES if the target is a shared object
LIBRARY        := NO
# QUIET can be set to YES if we don't want commands echo'd
QUIET          := NO
#****************************************************************************

#****************************************************************************
# The target
TARGET := sip_test

#****************************************************************************
# Programs
#****************************************************************************
CC      := gcc
LD      := $(CC)
INSTALL := ${shell which install} -m 644
RM      := ${shell which rm}

ifeq (YES, ${QUIET})
   CC      := @$(CC)
   LD      := @$(LD)
   INSTALL := @$(INSTALL)
   RM      := @$(RM)
endif

#****************************************************************************
# Platform
#****************************************************************************
UNAME := ${shell uname}

#****************************************************************************
# Directories
#****************************************************************************
OBJDIR := ../obj
LIBDIR := ../lib
DEPDIR := ../dep
BINDIR := ./

#****************************************************************************
# Includes
#****************************************************************************
#INCLUDES := -I../include
INCLUDES := -I.

LIBS := -lssl -lcrypto -lrt

#
# Compiler and Linker flags plus preprocessor defs
#
DEBUG_CFLAGS     := -pthread -g -Werror -Wall \
-std=c99 \
-Wdeclaration-after-statement \
-Wpointer-arith

RELEASE_CFLAGS   := $(DEBUG_CFLAGS)

DEBUG_LDFLAGS    := -g -ggdb
RELEASE_LDFLAGS  := 

ifeq (YES, ${DEBUG})
   CFLAGS        := ${DEBUG_CFLAGS}
   LDFLAGS       := ${DEBUG_LDFLAGS}
   DEFS          := -D${UNAME} -D_REENTRANT -D_GNU_SOURCE -DDEBUG
else
   CFLAGS        := ${RELEASE_CFLAGS}
   LDFLAGS       := ${RELEASE_LDFLAGS}
   DEFS          := -D${UNAME} -D_REENTRANT -D_GNU_SOURCE
endif

ifeq (YES, ${PROFILE})
   CFLAGS        := ${CFLAGS} -pg -O2
   LDFLAGS       := ${LDFLAGS} -pg
endif

ifeq (YES, ${LIBRARY})
   CFLAGS        := ${CFLAGS} -fPIC
   LDFLAGS       := ${LDFLAGS} -shared -fPIC
endif

#
# Source, Header, Object and Depends files
#
SOURCES := $(shell echo *.c)
HEADERS := $(shell echo *.h)
OBJECTS := $(addprefix $(OBJDIR)/, $(SOURCES:.c=.o))
DEPENDS := $(addprefix $(DEPDIR)/, $(SOURCES:.c=.d))

#
# Auto-dependency file create rule
#
$(addprefix $(DEPDIR)/, %.d) : %.c
	@echo "   [DEP] $@"
	$(CC) -MM $(INCLUDES) $^ -MT $(addprefix $(OBJDIR)/, $(^:.c=.o)) > $@

#
# Object-file creation rule
#
$(addprefix $(OBJDIR)/, %.o) : %.c
	@echo "   [CC]  $<"
	$(CC) -c $(DEFS) $(CFLAGS) $(INCLUDES) $< -o $@

#****************************************************************************
# The final product
#****************************************************************************
ifeq (YES, ${LIBRARY})
   TARGET := $(LIBDIR)/$(TARGET)
else
   TARGET := $(BINDIR)/$(TARGET)
endif

#****************************************************************************
# The build rule
#****************************************************************************
all: $(TARGET)

$(TARGET): $(OBJECTS)  
	@echo "   [LD]  $@"
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

#****************************************************************************
# Include auto-generated dependencies
#****************************************************************************
-include $(DEPENDS)

#****************************************************************************
# Clean it up
#****************************************************************************
clean:
	@echo "   [RM]  $(DEPENDS) $(OBJECTS) $(TARGET)"
	$(RM) $(OBJECTS) $(TARGET) $(DEPENDS)

#****************************************************************************
# List out some of the defined stuff
#****************************************************************************
list:
	@echo "TARGET : $(TARGET)"
	@echo "UNAME  : $(UNAME)"
	@echo "SOURCES: $(SOURCES)"
	@echo "OBJECTS: $(OBJECTS)"
	@echo "DEPENDS: $(DEPENDS)"
	@echo "HEADERS: $(HEADERS)"
	@echo "INCLUDE: $(INCLUDES)"
	@echo "CFLAGS : $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
	@echo "LIBS   : $(LIBS)"

#****************************************************************************
# Install
#****************************************************************************
install: $(TARGET)
	$(INSTALL) -p $(TARGET) /usr/local/lib
	$(INSTALL) -D -p $(HEADERS) /usr/local/include
