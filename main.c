#include "sysutil.h"
#include "session.h"
#include "str.h"

int main()
{
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

	if(getuid() != 0){
		fprintf(stderr,"miniftpd: must be started as root\n");
		exit(EXIT_FAILURE);
	}


	
	session_t sess = 
	{
		//控制链接
		-1,"","","",
		//父子进程通道
		-1,-1
	};
	int listenfd = tcp_server(NULL,5188);
	int conn;
	pid_t pid;
	while(1){
		conn = accept_timeout(listenfd,NULL,0);
		if(conn == -1){
			ERR_EXIT("accept_timeout");
		}

		pid = fork();
		if(pid == -1){
			ERR_EXIT("fork");
		}
		if(pid == 0){	//child
			close(listenfd);
			sess.ctrl_fd = conn;
			begin_session(&sess);
		}else {
			close(conn);
		}
	}


	return 0;
}
