#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/mman.h>

#define SOCK_PATH "IRC_Server"
#define SOCK_MAX_CLIENT 10
#define MAX_CLIENT_SEND_BUFF_SZ 4096
#define IRC_SERVER_URL "chat.au.freenode.net"
#define IRC_SERVER_PORT 6667

typedef struct node {
	struct node *next;
	void *v;
} node_t;

typedef struct irc_data {
	int socket_fd;
	char **channel_names;
	pthread_t thread_recv;
	pthread_t thread_send;
	pthread_mutex_t list_lock;
	node_t list;
	char *nickname;
	int ch_select;
	int ch_cur_count;
	int ch_total_count;
} irc_data_t;


void irc_init(irc_data_t *data)
{
	data->socket_fd = 0;
	data->channel_names = NULL;
	data->nickname = NULL;
	data->ch_select = -1;
	data->ch_cur_count = 0;
	data->ch_total_count = 0;

	pthread_mutex_init(&data->list_lock, NULL);

	data->list.next = NULL;
	data->list.v = NULL;
}

void irc_free(irc_data_t *data)
{
	close(data->socket_fd);
	if (NULL != data->nickname) {
		free(data->nickname);
		data->nickname = NULL;
	}
	pthread_cancel(data->thread_recv);
	pthread_cancel(data->thread_send);
	pthread_mutex_lock(&data->list_lock);
	while(data->list.next != NULL) {
		node_t *n = data->list.next;
		data->list.next = n->next;
		if (NULL != n->v)
			free(n->v);
		free(n);
	}
	pthread_mutex_unlock(&data->list_lock);
	pthread_mutex_destroy(&data->list_lock);

	for (int i = 0; i < data->ch_cur_count; ++i) {
		if (NULL != data->channel_names[i]) {
			free(data->channel_names[i]);
			data->channel_names[i] = NULL;
		}
	}
	free(data->channel_names);

}

void irc_channel_send_msg(irc_data_t *data, char *msg, int len)
{
	node_t *n = (node_t *) malloc(sizeof(node_t));
	n->v = malloc(len);
	memcpy(n->v, msg, len);
	pthread_mutex_lock(&data->list_lock);
	n->next = data->list.next;
	data->list.next = n;
	pthread_mutex_unlock(&data->list_lock);
}

/*
 * remove all \r \n 
 * */
void handle_msg_remove_illegal_ch(char *msg, int len)
{
	for (int i = 0; i < len; i++) {
		switch (msg[i]) {
		case '\n': 
		case '\r':
			msg[i] = ' ';
			break;
		}
	}
}

enum {
	IRC_COMMAND_NICK = 0,

};
char **IRC_COMMAND = {
	"NICK",
};

/*
 * handle msg from client
 * */
void handle_msg_from_client(irc_data_t *data, char *buf, int len)
{
	if (NULL == buf || 0 == len)
		return;
	if (*ch_cur > *ch_cur_count)
		return;
	if (*ch_cur_count > *ch_total_count)
		return;
	if ('/' != buf[0] || 1 == len) {
		if (*ch_cur > 0 && data[*ch_cur]) {
			irc_channel_send_msg(data, buf, len);
		} else {
			fprintf(stderr, "error: no channel or "
					"no channel select!");
		}
	}
	int len = MAX_CLIENT_SEND_BUFF_SZ;
	char msg[MAX_CLIENT_SEND_BUFF_SZ];
	int cur = 0;
	char *template = NULL;
	switch (buf[1]) {
	case 'n': /* nickname */
		{
			char *new_name = strchr(buf, ' ');
			if (NULL == new_name) {
				fprintf(stderr, "input new nickname");
				return;
			}
			if (NULL != data->nickname) {
				template = ":%s %s %s";
				cur += snprintf(msg, len - cur, template, data->nickname
					, IRC_COMMAND[IRC_COMMAND_NICK]
					, new_name);
			}
			else {
				template = "%s %s";
				cur += snprintf(msg, len - cur, template, IRC_COMMAND[IRC_COMMAND_NICK]
					, new_name);
			}
		}
		break;
	}

	if (cur + 1 > len)
	{
		fprintf(stderr, "send message can not bigger than %d\n", len);
		return;
	}
	else
	{
		irc_channel_send_msg(data, msg, cur);
	}
}

void * thread_recv_msg_from_server(void *args)
{
	irc_data_t *data = (irc_data_t *) args;
	node_t *n = NULL;
	struct timespec timespan;
	timespan.tv_sec = 0;
	timespan.tv_nsec = 1000 * 100; /* 100微秒 */

	int len = 0;
	int send_count = 0;
	int ret = 0;
	for (;;) {
		pthread_mutex_lock(&data->list_lock);
		if (NULL != data->list.next) {
			n = data->list.next;
			data->list.next = n->next;
		}
		pthread_mutex_unlock(&data->list_lock);
		if (NULL != n && NULL != n->v) {
			len = strlen(n->v);
			send_count = 0;
			while(len > send_count) {
				ret = send(data->socket_fd, n->v + send_count, len - send_count);
				if (-1 == ret)
					break;
				send_count += ret;
			}
			free(n->v);
			free(n);
			if (len != send_count)
			{
				perror("send fail, send thread exit");
				break;
			}
		} else if (NULL != n && NULL == n->v) {
			free(n);
		}
		nanosleep(&timespan, NULL);
		n = NULL;
	}

	pthread_exit(data);
	return data;
}

void * thread_send_msg_to_server(void *args)
{
	irc_data_t *data = (irc_data_t *) args;
	int ret = 0;
	int len = MAX_CLIENT_SEND_BUFF_SZ;
	char *buf = (void *)mmap(NULL, len, PROT_READ | PROT_WRITE
		, MAP_PRIVATE | MAP_ANON, -1, len);
	if (NULL == buf) {
		goto err
	}
	for (;;) {
		ret = recv(data->socket_fd, buf, len, 0);
		if (-1 == ret) {
			perror("recv error, recv thread exit!");
			break;
		}
		write(STDOUT_FILENO, buf, ret);
	}
err:
	if (NULL != buf)
		munmap(buf, len);
	buf = NULL;
	pthread_exit(data);
	return data;
}

int create_client_socket(char *ip, short port)
{
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(ip);
	server_addr.sin_port = htons(port);
	int s_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (0 > s_fd) {
		perror("socket error!\n")
		return -1;
	}
	if (-1 == connect(s_fd, &server_addr, sizeof(server_addr))) {
		perror("connect error");
		return -2;
	}
	return s_fd;
}

void handle_client(int client_fd)
{
	irc_data_t irc_channels;
	char buf[MAX_CLIENT_SEND_BUFF_SZ];
	int retn = 0;
	irc_init(&irc_channels);
	irc_channels.socket_fd = create_client_socket(IRC_SERVER_URL, IRC_SERVER_PORT);
	if (0 > irc_channels.socket_fd) {
		close(client_fd);
		irc_free(irc_channels);
		return;
	}
	if (0 != pthread_create(&irc_channels.thread_recv, NULL
		, thread_recv_msg_from_server, &irc_channels)) {
		perror("create recv thread error!");
		close(client_fd);
		irc_free(irc_channels);
		return;
	}
	if (0 != pthread_create(&irc_channels.thread_send, NULL
		, thread_send_msg_to_server, &irc_channels)) {
		perror("create send thread error!");
		close(client_fd);
		irc_free(irc_channels);
		return;
	}

	for(;;) {
		retn = recv(client_fd, buf, sizeof(buf) - 1, 0);
		if (retn > 0) {
			buf[retn] = '\0';
			fprintf(stdout, "recv: %s\n",buf);
			handle_msg_remove_illegal_ch(buf, retn + 1);
			handle_msg_from_client(&irc_channels, buf, retn + 1);
		} else if (0 == retn) {
			fprintf(stdout, "client offline");
			break;
		} else {
			fprintf(stderr, "client error");
			break;
		}
	}

	close(client_fd);
	irc_free(irc_channels);
}




int main(void)
{
	int socket_fd, client_fd;
	struct sockaddr_un local_addr, client_addr;
	if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error");
		perror(strerror(errno));
		return -1;
	}

	local_addr.sun_family = AF_UNIX;
	strcpy(local_addr.sun_path, SOCK_PATH);
	unlink(local_addr.sun_path);
	int len = strlen(local_addr.sun_path) 
		+ sizeof(local_addr.sun_family);
	if (-1 == bind(socket_fd, (struct sockaddr *)&local_addr, len)) {
		perror("bind error");
		perror(strerror(errno));
		return -2;
	}
	
	if (-1 == listen(socket_fd, SOCK_MAX_CLIENT)) {
		perror("listen error");
		perror(strerror(errno));
		return -3;
	}

	printf("unix domain socket start");
	for(;;) {
		memset(client_addr.sun_path, 0
				, sizeof(client_addr.sun_path));
		len = sizeof(client_addr);
		if (-1 == (client_fd = accept(socket_fd
					, (struct sockaddr *)&client_addr
					, &len))) {
			perror("accept error");
			perror(strerror(errno));
			exit(-4);
		}
		printf("client info: path: %s\n", client_addr.sun_path);
		if (0 == fork()) {
				handle_client(client_fd);
				exit(0);
		}
	}
	close(socket_fd);

	return 0;
}




