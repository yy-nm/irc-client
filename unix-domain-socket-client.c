

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <unistd.h>


int main(int argc, void **args)
{
	if (argc < 2) {
		perror("must have one arg");
		return - 1;
	}
	char *unix_sock_name = (char *)args[1];
	if (0 == strlen(unix_sock_name)) {
		perror("must have unix domain socket path");
		return -2;
	}
	int socket_fd = 0;
	if (-1 == (socket_fd = socket(AF_UNIX, SOCK_STREAM, 0))) {
		perror("socket error");
		perror(strerror(errno));
		return -3;
	}

	struct sockaddr_un server_addr;
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, unix_sock_name);
	int len = strlen(server_addr.sun_path) 
		+ sizeof(server_addr.sun_family);
	if (-1 == (connect(socket_fd, (struct sockaddr *)&server_addr
					, len))) {
		perror("connect error");
		perror(strerror(errno));
		return -4;
	}
	
	printf("connect success\n");
	char buf[1024];
	int read_sz = 0;
	for(;;) {
		printf(">");
		read_sz = read(STDIN_FILENO, buf, sizeof(buf) - 1);
		if (read_sz < 0) {
			perror("read error");
			break;
		} else if (0 == read_sz) {
			perror("client exit");
			break;
		}
		buf[read_sz] = '\0';
		int send_sz = 0;
		while(send_sz < read_sz) {
			/*int ret = write(socket_fd, buf + send_sz*/
					/*, read_sz - send_sz);*/
			int ret = send(socket_fd, buf + send_sz
					, read_sz - send_sz, 0);
			if (-1 == ret) {
				perror("send data error");
				break;
			}
			send_sz += ret;
		}

		if (send_sz < read_sz)
			break;
	}
	close(socket_fd);

	return 0;
}



