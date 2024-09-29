TARGET=netpipe
CFLAGS ?= -O3 -pipe
CFLAGS += -Wall --std=gnu99 -DNDEBUG -Wno-unused-function
OBJDIR=./obj

OBJ=\
	$(OBJDIR)/logging.o		\
	$(OBJDIR)/utils.o		\
	$(OBJDIR)/thread-context.c	\
	$(OBJDIR)/service.o		\
	$(OBJDIR)/vioproxy.o		\
	\

.PHONY: all
all: $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) $(LDLIBS) -o $@


.PHONY: clean
clean:
	$(RM) $(OBJ) $(TARGET)
