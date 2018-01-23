# Makefile to build monte_pi_sprng program
CC=gcc
#CFLAGS=-I.

hellomake: mydump.o
	$(CC) -o mydump mydump.c -lpcap
