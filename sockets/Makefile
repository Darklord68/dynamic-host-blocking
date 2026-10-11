CFLAGS = -Wall -Wextra -pthread

all: server client mock_controller

server: server.c detect.c reporter.c hostblock.h
	gcc $(CFLAGS) -o server server.c detect.c reporter.c

client: client.c
	gcc $(CFLAGS) -o client client.c

mock_controller: mock_controller.c
	gcc $(CFLAGS) -o mock_controller mock_controller.c

test_detect: test_detect.c detect.c hostblock.h
	gcc $(CFLAGS) -o test_detect test_detect.c detect.c

test: test_detect
	./test_detect

clean:
	rm -f server client mock_controller test_detect
