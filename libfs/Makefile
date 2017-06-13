targets := libfs.a
objs 	:= disk.o fs.o
header	:= disk.h fs.h


AR	:= ar
ARFLAGS := -rcs
CC 	:= gcc
CFLAGS	:= -Wall -Werror
CFLAGS	+= -g

ifneq ($(V),1) 
	Q = @ 
endif


all: $(targets)

%.a: $(objs)
	@echo "AR  $@"
	$(Q)$(AR) -rcs $@ $^

%.o: %.c $(header)
	@echo "CC $@"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@echo "CLEAN"
	$(Q)rm -f $(targets) $(objs)