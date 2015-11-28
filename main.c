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
#include <netdb.h>

#define SOCK_PATH "IRC_Server"
#define SOCK_MAX_CLIENT 10
#define MAX_CLIENT_SEND_BUFF_SZ 4096
#define IRC_SERVER_URL "weber.freenode.net"
#define IRC_SERVER_PORT 6667
#define MIN(x, y) (x) > (y) ? (y) : (x)
#define MAX(x, y) (x) > (y) ? (x) : (y)

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

	int i = 0;
	for (i = 0; i < data->ch_cur_count; ++i) {
		if (NULL != data->channel_names[i]) {
			free(data->channel_names[i]);
			data->channel_names[i] = NULL;
		}
	}
	free(data->channel_names);

}

void irc_channel_send_msg(irc_data_t *data,const char *msg, int len)
{
	char *msg_end = "\r\n";
	node_t *n = (node_t *) malloc(sizeof(node_t));
	n->v = malloc(len + strlen(msg_end) + 1);
	memcpy(n->v, msg, len);
	memcpy(n->v + len, msg_end, strlen(msg_end));
	((char *)n->v)[len + strlen(msg_end)] = '\0';
	pthread_mutex_lock(&data->list_lock);
	n->next = data->list.next;
	data->list.next = n;
	pthread_mutex_unlock(&data->list_lock);
}

node_t * irc_channel_get_msg(irc_data_t *data)
{
	if (NULL == data)
		return NULL;
	pthread_mutex_lock(&data->list_lock);
	node_t *n = data->list.next;
	if (NULL != n)
		data->list.next = n->next;
	else
		data->list.next = NULL;
	pthread_mutex_unlock(&data->list_lock);
	return n;
}

/*
 * remove all \r \n 
 * */
void handle_msg_remove_illegal_ch(char *msg, int len)
{
	int i = 0;
	for (i = 0; i < len; i++) {
		switch (msg[i]) {
		case '\n': 
		case '\r':
			msg[i] = ' ';
			break;
		}
	}
}

typedef struct custom_command {
	const char cmd_shortcut;
	const char * const cmd_name;
	const char * const irc_cmd_name;
	int cmd_params_count;
	const char * const cmd_comment;
} custom_command_t;

static custom_command_t *IRC_COMMAND = {
	{ 'n', "name",		"NICK",		1,	"set nickname"},
	{ 'l', "login",		"USER",		1,	"login"},
	{ 'j', "join",		"JOIN",		1,	"join channel"},
	{ 'L', "leave",		"PART",		1,	"leave channel"},
	{ 'q', "quit",		"QUIT",		0,	"quit from irc"},
	{ 'N', "namelist",	"NAMES",	0,	"list name from channel"},
	{ 'c', "channel",	"LIST",		0,	"list channel or topic"},
	{ 'i', "invite",	"INVITE",	2,	"invite other to channel"}, 
	{ 'k', "kickout",	"KICK",		2,	"kick other out of channel"},
	{ 'm', "message",	"PRIVMSG",	1,	"send msg in cur channel"},
	{ 'M', "custom-msg",	"PRIVMSG",	2,	"send msg to other channel"},
	{ 'p', "person-talk",	"PRIVMSG",	2,	"talk to other user"},
	{ 'w', "who",		"WHO",		0,	"search user"},
	{ 'W', "whois",		"WHOIS",	1,	"search user info"},
	NULL
};

void print_usage()
{
	fprintf(stdout, "Command Usage:\n");
	custom_command_t *cmd = IRC_COMMAND;
	while (cmd) {
		fprintf(stdout, "cmd: %c, %s \t\t\t%s\n"
				, cmd->cmd_shortcut ? cmd->cmd_shortcut : ' '
				, cmd->cmd_name, cmd->cmd_comment);
	}
	fprintf(stdout, "\n");
}

void handle_custom_client_command(irc_data_t *data, char *buf, int len)
{
	if (len < 2) {
		fprintf(stderr, "error command!\n");
		print_usage();
		return;
	}

	int max_sz = MAX_CLIENT_SEND_BUFF_SZ - 1;
	char msg_buf[MAX_CLIENT_SEND_BUFF_SZ];
	int cur = 0;
	char *p = NULL;
	custom_command_t *cmd = IRC_COMMAND;
	while(NULL != cmd) {
		p = buf + 1;
		if (cmd->cmd_shortcut == *p && len >= 3 
				&& '\0' == *(p + 1)) {
			p++;
			break;
			
		}
		else if (cmd->cmd_shortcut == *p && len >= 3 
				&& ' ' == *(p + 1)) {
			p++;
			break;
		}
		else if (len >= 1 + strlen(cmd->cmd_name)
					&& 0 == strncmp(p, cmd->cmd_name
						, strlen(cmd->cmd_name))) {
			p += strlen(cmd->cmd_name);
			if ('\0' == *p) {
				break;
			} else if (' ' == *p) {
				/*p++;*/
				break;
			}
		}
	}
	
	if (!cmd)
		return;
	int params_count = cmd->cmd_params_count;
	char *params_p = p;
	while (params_count) {
		if (p - buf + 1 >= len)
			break;
		p = strchr(p, ' ');
		if (!p)
			break;
		p++;
		params_count --;
	}
	
	if (params_count) {
usage:
		fprintf(stderr, "cmd: %c, %s need %d args"
				, cmd->cmd_shortcut ? cmd->cmd_shortcut : ' '
				, cmd->cmd_name, cmd->cmd_params_count);
		return;
	}
	p = params_p;
	if (' ' == *p)
		p++;

	if (0 == strcmp("name", cmd->cmd_name)) {
		if (data->nickname && 2 + strlen(data->nickname) + cur < max_sz)
		{
			cur += sprintf(msg_buf + cur, ":%s ", data->nickname);
		}
		
		char *nickname = data->nickname;
		data->nickname = NULL;
		if (nickname)
			free(nickname);
		nickname = (char *)malloc(strlen(p) + 1);
		strcpy(nickname, p);
		nickname[strlen(p)] = '\0';
		data->nickname = nickname;
	} else if (0 == strcmp("login", cmd->cmd_name)) {
	}

	if (strlen(cmd->irc_cmd_name) + 1 + strlen(p) < max_sz) {
		cur += sprintf(msg_buf + cur, "%s %s", cmd->irc_cmd_name
				, p);
	} else
	{
		goto usage;
	}

	irc_channel_send_msg(data, msg_buf, cur);

}


/*
 * handle msg from client
 * */
void handle_msg_from_client(irc_data_t *data, char *buf, int len)
{
	if (NULL == buf || 0 == len)
		return;
	if ('/' != buf[0]) {
		printf("send msg to list\n");
		irc_channel_send_msg(data, buf, len);
		return;
	} else if('/' == buf[0]) {
		handle_custom_client_command(data, buf, len);
	}
}

void * thread_send_msg_to_server(void *args)
{
	irc_data_t *data = (irc_data_t *) args;
	node_t *n = NULL;
	struct timespec timespan;
	timespan.tv_sec = 0;
	timespan.tv_nsec = 1000 * 1000 * 100; /* 100 毫秒*/
	int timecount = 0; // 超过 1s 不发数据就需要发送 ping 包
	const int time_limit = 200;
	const char * const msg_ping = "PING :ALIVECHECK\r\n";

	int len = 0;
	int send_count = 0;
	int ret = 0;
	for (;;) {
		n = irc_channel_get_msg(data);

		if (NULL != n && NULL != n->v) {
			len = strlen(n->v);
			send_count = 0;
			while(len > send_count) {
				ret = send(data->socket_fd, n->v + send_count
						, len - send_count, 0);
				if (-1 == ret) {
					perror("send irc server error\n");
					break;
				}
				send_count += ret;
			}
			/*int i = 0;*/
			/*for (i = 0; i < len; ++i) {*/
				/*fprintf(stdout, "0x%.2X", ((char*) n->v)[i]);*/
			/*}*/
			/*fprintf(stdout, "\n");*/
			free(n->v);
			free(n);
			if (len != send_count)
			{
				perror("send fail, send thread exit");
				break;
			}
			printf("[local_client]: send msg success\n");
			timecount = 0;
		} else if (NULL != n && NULL == n->v) {
			timecount ++;
			free(n);
		} else {
			timecount ++;
		}
		if (timecount > time_limit) {
			timecount = 0;
			irc_channel_send_msg(data, msg_ping, strlen(msg_ping));
		}
		nanosleep(&timespan, NULL);
		n = NULL;

	}

	pthread_exit(data);
	return data;
}

void * thread_recv_msg_from_server(void *args)
{
	irc_data_t *data = (irc_data_t *) args;
	int ret = 0;
	int len = MAX_CLIENT_SEND_BUFF_SZ;
	char *buf = (char *)mmap(NULL, len, PROT_READ | PROT_WRITE
		, MAP_PRIVATE | MAP_ANON, -1, len);
	if (NULL == buf) {
		goto err;
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
	printf("socket success\n");
	if (0 > s_fd) {
		perror("socket error!\n");
		return -1;
	}
	printf("connect start\n");
	if (-1 == connect(s_fd, (struct sockaddr *)&server_addr
				, sizeof(server_addr))) {
		perror("connect error");
		return -2;
	}
	fprintf(stdout, "connect to %s\n", ip);
	return s_fd;
}
int get_ip_from_hostname(char *hostname, char *ip, int ip_len)
{
	// 128: ipv6 + :: <= 60 char
	struct hostent *host = gethostbyname(hostname);
	if (NULL == host) {
		fprintf(stderr, "get ip from host error: %s\n", hostname);
		return -1;
	}
	if (host->h_length < 1 || NULL == host->h_addr_list) {
		fprintf(stderr, "the hostname don't have ip list: %s\n", hostname);
		return -2;
	}
	if (strlen(host->h_addr_list[0]) > ip_len) {
		perror("ip array too short!\n");
		return -3;
	}
	struct in_addr **addr_list = (struct in_addr**)host->h_addr_list;
	strcpy(ip, inet_ntoa(*addr_list[0]));
	int i = 0;
	/*
	for (i = 0; i < host->h_length; ++i) {
		printf("ip: %s\n", inet_ntoa(*addr_list[i]));
	}
	*/
	return 0;
}

void handle_client(int client_fd)
{
	irc_data_t irc_channels;
	char buf[MAX_CLIENT_SEND_BUFF_SZ];
	int retn = 0;
	irc_init(&irc_channels);
	if (0 != get_ip_from_hostname(IRC_SERVER_URL, buf, sizeof(buf))) {
		perror("get ip from host error\n");
		goto err;
	}
	printf("ip: %s\n", buf);
	irc_channels.socket_fd = create_client_socket(buf, IRC_SERVER_PORT);
	if (0 > irc_channels.socket_fd) {
		goto err;
	}
	if (0 != pthread_create(&irc_channels.thread_recv, NULL
		, thread_recv_msg_from_server, &irc_channels)) {
		perror("create recv thread error!");
		goto err;
	}
	if (0 != pthread_create(&irc_channels.thread_send, NULL
		, thread_send_msg_to_server, &irc_channels)) {
		perror("create send thread error!");
		goto err;
	}

	for(;;) {
		retn = recv(client_fd, buf, sizeof(buf) - 1, 0);
		if (retn > 0) {
			buf[retn - 1] = '\0';
			fprintf(stdout, "[local-client]: recv: %s\n",buf);
			handle_msg_remove_illegal_ch(buf, retn);
			handle_msg_from_client(&irc_channels, buf, retn - 1);
		} else if (0 == retn) {
			fprintf(stdout, "client offline");
			break;
		} else {
			fprintf(stderr, "client error");
			break;
		}
	}

err:
	close(client_fd);
	irc_free(&irc_channels);
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




