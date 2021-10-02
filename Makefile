# -*- coding: utf-8 -*-
# Łukasz Czajka

CC          := gcc
CFLAGS      := -g -pedantic -Wall -c
LDFLAGS     := -Wall
SOURCES     := $(wildcard *.c)
MAINOBJECTS := $(subst .c,.o,$(shell egrep -l 'int[ \n\t]+main' $(SOURCES)))
ALL         := $(subst .o,,$(MAINOBJECTS))
DEPENDS     := $(subst .c,.d,$(SOURCES))
ALLOBJECTS  := $(subst .c,.o,$(SOURCES))
OBJECTS	    := $(filter-out $(MAINOBJECTS),$(ALLOBJECTS))

all: $(DEPENDS) $(ALL)

$(DEPENDS) : %.d : %.c
	$(CC) -MM $< > $@
	printf "\t$(CC) $(CFLAGS) $<" >> $@

$(ALL) : % : %.o $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

include $(DEPENDS)

clean:
	-rm -f *.o $(ALL) $(ALLOBJECTS) $(DEPENDS)

Makefile: $(DEPENDS)

test: tests/calc tests/hello

tests/calc: all tests/calc.asm
	./asm tests/calc.asm
	ld -o tests/calc tests/calc.o -lc -dynamic-linker /lib/ld-linux.so.2

tests/hello: all tests/hello.asm
	./asm tests/hello.asm
	ld -o tests/hello tests/hello.o
