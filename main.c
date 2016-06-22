#include "sysutil.h"
#include "session.h"
#include "str.h"
#include "tunable.h"
#include "parseconf.h"
#include "ftpproto.h"
#include "ftpcodes.h"

extern session_t *p_sess;
static unsigned int s_children;

void check_limits(session_t *sess);
void handle_sigchld(int sig);

int main()
{
	//list_common();
	/*
	char *str1 = "  		 a 	 b 	";
	char *str2 = "		 		  	";

	if(str_all_space(str1)){
		printf("str1 all space\n");
	}else {
		printf("str1 not all space\n");
	}
	if(str_all_space(str2)){
		printf("str2 all space\n");
	}else {
		printf("str2 not all space\n");
	}
	char str3[] = "abcdeF";
	str_upper(str3);
	printf("str3=%s\n",str3);

	long long result = str_to_longlong("12345678901234");
	printf("%lld\n",result);

	int n = str_octal_to_uint("711");
	printf("%d , %o\n",n,n);
	*/
/*
extern int tunable_pasv_enable;
extern int tunable_port_enable;
extern unsigned int tunable_listen_port;
extern unsigned int tunable_max_clients;
extern unsigned int tunable_max_per_ip;
extern unsigned int tunable_accept_timeout;
extern unsigned int tunable_connect_timeout;
extern unsigned int tunable_idle_session_timeout;
extern unsigned int tunable_data_connection_timeout;
extern unsigned int tunable_local_umask;
extern unsigned int tunable_upload_max_rate;
extern unsigned int tunable_download_max_rate;
extern const char  *tunable_listen_address;
*/

	parseconf_load_file(MINIFTPD_CONF);
	
	printf("tunable_pasv_enable=%d\n",tunable_pasv_enable);
	printf("tunable_port_enable=%d\n",tunable_port_enable);
	printf("tunable_listen_port=%u\n",tunable_listen_port);
	printf("tunable_max_clients=%u\n",tunable_max_clients);
	printf("tunable_max_per_ip=%u\n",tunable_max_per_ip);
	printf("tunable_accept_timeout=%u\n",tunable_accept_timeout);
	printf("tunable_connect_timeout=%u\n",tunable_connect_timeout);
	printf("tunable_idle_session_timeout=%u\n",tunable_idle_session_timeout);
	printf("tunable_data_connection_timeout=%u\n",tunable_data_connection_timeout);
	printf("tunable_local_umask=0%o\n",tunable_local_umask);
	printf("tunable_upload_max_rate=%d\n",tunable_upload_max_rate);
	printf("tunable_download_max_rate=%u\n",tunable_download_max_rate);

	if(tunable_listen_address == NULL){
		printf("tunable_listen_address=NULL\n");
	}else{
		printf("tunable_listen_address=%s\n",tunable_listen_address);
	}
	


	if(getuid() != 0){
		fprintf(stderr,"miniftpd: must be started as root\n");
		exit(EXIT_FAILURE);
	}


	
	session_t sess = 
	{
		//控制链接
		0,-1,"","","",
		//数据连接
		NULL,-1,-1,0,
		//限速
		0,0,0,0,
		//父子进程通道
		-1,-1,
		//ftp协议状态
		0,0,NULL,0,
		//连接数限制
		0
	};
	p_sess = &sess;
	
	sess.bw_upload_rate_max = tunable_upload_max_rate;
	sess.bw_download_rate_max = tunable_download_max_rate;
	
	signal(SIGCHLD,handle_sigchld);
	int listenfd = tcp_server(tunable_listen_address,tunable_listen_port);
	int conn;
	pid_t pid;
	while(1){
		conn = accept_timeout(listenfd,NULL,0);
		if(conn == -1){
			ERR_EXIT("accept_timeout");
		}

		++s_children;
		sess.num_clients = s_children;

		pid = fork();
		if(pid == -1){
			--s_children;
			ERR_EXIT("fork");
		}
		if(pid == 0){	//child
			close(listenfd);
			sess.ctrl_fd = conn;
			check_limits(&sess);
			signal(SIGCHLD,SIG_IGN);
			begin_session(&sess);
		}else {
			close(conn);
		}
	}


	return 0;
}

void check_limits(session_t *sess)
{
	if(tunable_max_clients > 0 && sess->num_clients > tunable_max_clients){
		ftp_reply(sess,FTP_TOO_MANY_USERS,"There are too many connected users.please try later.");
		exit(EXIT_FAILURE);
	}
}

void handle_sigchld(int sig)
{
	pid_t pid;
	while((pid = waitpid(-1,NULL,WNOHANG)) > 0){
		;
	}
	--s_children;
}