all:
	$(CC) cryptowrite.c -o cwrite
	$(CC) cryptoread.c -o cread
	$(CC) normalwrite.c -o nwrite
	$(CC) normalread.c -o nread
clean:
	rm cwrite
	rm cread
	rm nwrite
	rm nread
