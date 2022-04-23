# IPK - project 2
# Brief:	Makefile to compile and build project
# Author: 	David Drtil <xdrtil03@stud.fit.vutbr.cz>
# Date:		2022-04-09

CC=gcc
CFLAGS=-std=gnu11 -Wall -pedantic
FILES=./src/*.c ./src/*.h
EXECUTABLE=ipk-sniffer

$(EXECUTABLE): $(FILES)
		$(CC) $(CFLAGS) $(FILES) -o $(EXECUTABLE) -lpcap

tar: $(FILES) Makefile README.md manual.pdf
	tar cvf xdrtil03.tar $^

clean:
	rm -f $(EXECUTABLE)
