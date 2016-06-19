#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcodes.h"
#include "tunable.h"
#include "privsock.h"

void ftp_reply(session_t * sess,int status,const char *text);
void ftp_lreply(session_t * sess,int status,const char *text);

int list_common(session_t *sess,int detail);
void upload_common(session_t *sess,int is_append);

int get_port_fd(session_t *sess);
int get_pasv_fd(session_t *sess);
int get_transfer_fd(session_t *sess);
int port_active(session_t *sess);
int pasv_active(session_t *sess);

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
static void do_stru(session_t *sess);
static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);

typedef struct ftpcmd
{
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
} ftpcmd_t;


static ftpcmd_t ctrl_cmds[] = {
	/* 访问控制命令 */
	{"USER",	do_user	},
	{"PASS",	do_pass	},
	{"CWD",		do_cwd	},
	{"XCWD",	do_cwd	},
	{"CDUP",	do_cdup	},
	{"XCUP",	do_cdup	},
	{"QUIT",	do_quit	},
	{"ACCT",	NULL	},
	{"SMNT",	NULL	},
	{"REIN",	NULL	},
	/* 传输参数命令 */
	{"PORT",	do_port	},
	{"PASV",	do_pasv	},
	{"TYPE",	do_type	},
	{"STRU",	do_stru	},
	{"MODE",	do_mode	},

	/* 服务命令 */
	{"RETR",	do_retr	},
	{"STOR",	do_stor	},
	{"APPE",	do_appe	},
	{"LIST",	do_list	},
	{"NLST",	do_nlst	},
	{"REST",	do_rest	},
	{"ABOR",	do_abor	},
	{"\377\364\377\362ABOR", do_abor},
	{"PWD",		do_pwd	},
	{"XPWD",	do_pwd	},
	{"MKD",		do_mkd	},
	{"XMKD",	do_mkd	},
	{"RMD",		do_rmd	},
	{"XRMD",	do_rmd	},
	{"DELE",	do_dele	},
	{"RNFR",	do_rnfr	},
	{"RNTO",	do_rnto	},
	{"SITE",	do_site	},
	{"SYST",	do_syst	},
	{"FEAT",	do_feat },
	{"SIZE",	do_size	},
	{"STAT",	do_stat	},
	{"NOOP",	do_noop	},
	{"HELP",	do_help	},
	{"STOU",	NULL	},
	{"ALLO",	NULL	}
};

void handle_child(session_t *sess)
{
	//writen(sess->ctrl_fd,"220 (miniftpd 0.1)\r\n",strlen("220 (miniftpd 0.1)\r\n"));
	ftp_reply(sess,FTP_GREET,"(miniftpd 0.1)");
	int ret;
	while(1){
		memset(sess->cmdline,0,sizeof(sess->cmdline));
		memset(sess->cmd,0,sizeof(sess->cmd));
		memset(sess->arg,0,sizeof(sess->arg));
		ret = readline(sess->ctrl_fd,sess->cmdline,MAX_COMMAND_LINE);
		if(ret == -1){
			ERR_EXIT("readline");
		}else if(ret == 0){
			printf("ret == 0\n");
			exit(EXIT_SUCCESS);
		}
		//printf("cmdline=[%s]\n",sess->cmdline);
		//出除\r\n
		str_trim_crlf(sess->cmdline);
		//printf("cmdline=[%s]\n",sess->cmdline);
		//解析FTP命令与参数
		str_split(sess->cmdline,sess->cmd,sess->arg,' ');
		printf("cmd=[%s] arg=[%s]\n",sess->cmd,sess->arg);
		// 将命令转换成大写
		str_upper(sess->cmd);
		//处理FTP命令
		/*
		if(strcmp("USER",sess->cmd) == 0){
			do_user(sess);
		}
		else if(strcmp("PASS",sess->cmd) == 0){
			do_pass(sess);
		}
		*/
		int i = 0;
		int size = sizeof(ctrl_cmds) / sizeof(struct ftpcmd);
		for(i = 0; i < size; i++){
			if(strcmp(ctrl_cmds[i].cmd,sess->cmd) == 0){
				if(ctrl_cmds[i].cmd_handler != NULL){
					ctrl_cmds[i].cmd_handler(sess);
				}else {
					ftp_reply(sess,FTP_COMMANDNOTIMPL,"Unimplement command");
				}
				// 找到了就break
				break;
			}
		}

		if(i == size){
			ftp_reply(sess,FTP_BADCMD,"Unknown command");
		}
	}
}

void ftp_reply(session_t *sess,int status,const char *text)
{
	char buf[1024] = {0};
	sprintf(buf,"%d %s\r\n",status,text);
	writen(sess->ctrl_fd,buf,sizeof(buf));
}

void ftp_lreply(session_t *sess,int status,const char *text)
{
	char buf[1024] = {0};
	sprintf(buf,"%d-%s\r\n",status,text);
	writen(sess->ctrl_fd,buf,sizeof(buf));
}

int list_common(session_t *sess,int detail)
{
	DIR *dir = opendir(".");
	if(dir == NULL){
		return 0;
	}

	struct dirent *dt;
	struct stat sbuf;
	while((dt = readdir(dir)) != NULL){
		if(lstat(dt->d_name,&sbuf) < 0){
			continue;
		}
		if(dt->d_name[0] == '.'){
			continue;
		}
		
		char buf[1024] = {0};
		if(detail){
			const char *perms = statbuf_get_perms(&sbuf);
			
			
			int off = 0;
			off += sprintf(buf,"%s",perms);
			off += sprintf(buf + off,"%3d %-8d %-8d ",(int)sbuf.st_nlink,sbuf.st_uid,sbuf.st_gid);
			off += sprintf(buf + off,"%8lu ",(unsigned long)sbuf.st_size);

			const char *datebuf = statbuf_get_date(&sbuf);

			off += sprintf(buf + off,"%s ",datebuf);

			if(S_ISLNK(sbuf.st_mode)){
				char tmp[1024] = {0};
				readlink(dt->d_name,tmp,sizeof(tmp));
				off += sprintf(buf + off,"%s -> %s\r\n",dt->d_name,tmp);
			}else {
				off += sprintf(buf + off,"%s\r\n",dt->d_name);
			}			
		}else{
			sprintf(buf,"%s\r\n",dt->d_name);
		}
		//printf("%s",buf);
		writen(sess->data_fd,buf,strlen(buf));
	}
	closedir(dir);
	return 1;
}

void upload_common(session_t *sess,int is_append)
{
	// 创建数据连接
	if(get_transfer_fd(sess) == 0){
		ftp_reply(sess,FTP_BADSENDCONN,"Use PORT OR PASV first");
		return;
	}
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;

	// 打开文件
	int fd = open(sess->arg,O_CREAT | O_WRONLY,0666);
	if(fd == -1){
		ftp_reply(sess,FTP_UPLOADFAIL,"could not create file.");
		return;
	}
	// 加写锁
	int ret;
	ret = lock_file_write(fd);
	if(ret == -1){
		ftp_reply(sess,FTP_UPLOADFAIL,"could not create file.");
		return;
	}
	// STOR
	// STOR+REST
	// APPE
	if(!is_append && offset == 0){	// STOR
		ftruncate(fd,0);
		if(lseek(fd,0,SEEK_SET) < 0){
			ftp_reply(sess,FTP_UPLOADFAIL,"could not create file.");
			return;
		}
	}else if(!is_append && offset != 0){	//REST + STOR
		if(lseek(fd,offset,SEEK_SET) < 0){
			ftp_reply(sess,FTP_UPLOADFAIL,"could not create file.");
			return;
		}
	}else if(is_append){	//APPE
		if(lseek(fd,0,SEEK_END) < 0){
			ftp_reply(sess,FTP_UPLOADFAIL,"could not create file.");
			return;
		}
	}

	struct stat sbuf;
	ret = fstat(fd,&sbuf);
	if(!S_ISREG(sbuf.st_mode)){
		ftp_reply(sess,FTP_FILEFAIL,"could not create file.");
		return;
	}

	//150 Opening ASCII mode data connection for a.out (14124 bytes).
	char text[1024] = {0};
	if(sess->is_ascii){
		sprintf(text,"Opening ASCII mode data connection for %s (%lld bytes).",sess->arg,(long long)sbuf.st_size);
	}else{
		sprintf(text,"Opening BINARY mode data connection for %s (%lld bytes).",sess->arg,(long long)sbuf.st_size);
	}
	// 150
	ftp_reply(sess,FTP_DATACONN,text);

	int flag = 0;

	// 上传文件
	char buf[1024];
	while(1){
		ret = read(sess->data_fd,buf,sizeof(buf));
		if(ret == -1){
			if(errno == EINTR){
				continue;
			}else{
				flag = 2;
				break;
			}
		}else if(ret == 0){
			flag = 0;
			break;
		}
		if(writen(fd,buf,ret) !=  ret){
			flag = 1;
			break;
		}
	}

	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	close(fd);
	if(flag == 0){
		// 226
		ftp_reply(sess,FTP_TRANSFEROK,"Transfer complete.");
	}else if(flag == 1){
		//426
		ftp_reply(sess,FTP_BADSENDFILE,"Failure writting to local file");
	}else if(flag == 2){
		//451
		ftp_reply(sess,FTP_BADSENDNET,"Failure reading from network stream.");
	}

}

int port_active(session_t *sess)
{
	if(sess->port_addr){
		if(pasv_active(sess)){
			fprintf((stderr), "both port and pasv are\n");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;
}

int pasv_active(session_t *sess)
{
	/*
	if(sess->pasv_listen_fd != -1){
		if(port_active(sess)){
			fprintf((stderr), "both port and pasv are\n");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	*/
	priv_sock_send_cmd(sess->child_fd,PRIV_SOCK_PASV_ACTIVE);
	int active = priv_sock_get_int(sess->child_fd);
	if(active){
		if(port_active(sess)){
			fprintf((stderr), "both port and pasv are\n");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;
}

int get_port_fd(session_t *sess)
{
			/*
	向nobody发送PRIV_SOCK_GET_DATA_SOCK命令
	向nobody发送一个整数port
	向nobody发送一个字符串ip
	*/
	priv_sock_send_cmd(sess->child_fd,PRIV_SOCK_GET_DATA_SOCK);
	unsigned short port = ntohs(sess->port_addr->sin_port);
	char *ip = inet_ntoa(sess->port_addr->sin_addr);
	priv_sock_send_int(sess->child_fd,(int)port);
	priv_sock_send_buf(sess->child_fd,ip,strlen(ip));

	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD){
		return 0;
	}else if(res == PRIV_SOCK_RESULT_OK){
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}

	return 1;
}

int get_pasv_fd(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd,PRIV_SOCK_PASV_ACCEPT);
	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD){
		return 0;
	}else if(res == PRIV_SOCK_RESULT_OK){
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}
	return 1;
}

int get_transfer_fd(session_t *sess)
{

	// 检测是否收到PORT或者PASV命令
	if(!port_active(sess) && !pasv_active(sess)){
		return 0;
	}

	int ret = 1;
	//如果是主动模式
	if(port_active(sess)){
		/*
		int fd = tcp_client(0);
		if(connect_timeout(fd,sess->port_addr,tunable_connect_timeout) < 0){
			close(fd);
			return 0;
		}
		sess->data_fd = fd;
		*/
		if(get_port_fd(sess) == 0){
			ret = 0;
		}

	}

	// 如果是被动模式
	if(pasv_active(sess)){
		/*
		int fd =accept_timeout(sess->pasv_listen_fd,NULL,tunable_accept_timeout);
		close(sess->pasv_listen_fd);
		if(fd == -1){
			return 0;
		}
		sess->data_fd = fd;
		*/
		if(get_pasv_fd(sess) == 0){
			ret = 0;
		}
	}

	if(sess->port_addr){
		free(sess->port_addr);
		sess->port_addr = NULL;
	}


	return ret;
}

static void do_user(session_t *sess)
{
	struct passwd *pw = getpwnam(sess->arg);
	if(pw == NULL){
		// 用户不存在
		ftp_reply(sess,FTP_LOGINERR,"Login incorrect.");
		return;
	}
	sess->uid = pw->pw_uid;
	ftp_reply(sess,FTP_GIVEPWORD,"Please specify the password.");

}

static void do_pass(session_t *sess)
{
	struct passwd *pw = getpwuid(sess->uid);
	if(pw == NULL){
		ftp_reply(sess,FTP_LOGINERR,"Login incorrect");
		return;
	}

	struct spwd *sp = getspnam(pw->pw_name);
	if(sp == NULL){
		ftp_reply(sess,FTP_LOGINERR,"Login incorrect");
		return;
	}

	// 将明文进行加密
	char *encrypted_pass = crypt(sess->arg,sp->sp_pwdp);
	// 验证密码
	if(strcmp(encrypted_pass,sp->sp_pwdp) != 0){
		ftp_reply(sess,FTP_LOGINERR,"Login incorrect");
		return;
	}
	umask(tunable_local_umask);
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);

	ftp_reply(sess,FTP_LOGINOK,"Login successful");
}


static void do_cwd(session_t *sess)
{
	if(chdir(sess->arg) < 0){
		ftp_reply(sess,FTP_FILEFAIL,"Failed to change directory.");
		return;
	}
	ftp_reply(sess,FTP_CWDOK,"Directory successfully changed");
}


static void do_cdup(session_t *sess)
{
	if(chdir("..") < 0){
		ftp_reply(sess,FTP_FILEFAIL,"Failed to change directory.");
		return;
	}
	ftp_reply(sess,FTP_CWDOK,"Directory successfully changed");

}
static void do_quit(session_t *sess)
{

}


static void do_port(session_t *sess)
{
	unsigned int v[6];
	sscanf(sess->arg,"%u,%u,%u,%u,%u,%u",&v[2],&v[3],&v[4],&v[5],&v[0],&v[1]);
	//printf("%u,%u,%u,%u,%u,%u\n",v[0],v[1],v[2],v[3],v[4],v[5]);
	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	memset(sess->port_addr,0,sizeof(struct sockaddr_in));
	sess->port_addr->sin_family = AF_INET;
	unsigned char *p = (unsigned char *)&sess->port_addr->sin_port;
	p[0] = v[0];
	p[1] = v[1];

	p = (unsigned char *)&sess->port_addr->sin_addr;
	p[0] = v[2];
	p[1] = v[3];
	p[2] = v[4];
	p[3] = v[5];

	ftp_reply(sess,FTP_PORTOK,"PORT command successful. Consider using PASV");
}


static void do_pasv(session_t *sess)
{
	char ip[16] = {0};
	getlocalip(ip);
	/*
	sess->pasv_listen_fd = tcp_server(ip,0);
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addrlen);
	if(getsockname(sess->pasv_listen_fd,(struct sockaddr*)&addr,&addrlen) < 0){
		ERR_EXIT("getsockname");
	}
	unsigned short port = ntohs(addr.sin_port);
	*/
	priv_sock_send_cmd(sess->child_fd,PRIV_SOCK_PASV_LISTEN);
	unsigned short port = (unsigned short)priv_sock_get_int(sess->child_fd);
	
	unsigned int v[4];
	sscanf(ip,"%u.%u.%u.%u",&v[0],&v[1],&v[2],&v[3]);
	char text[1024] = {0};
	sprintf(text,"Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
		v[0],v[1],v[2],v[3],port>>8,port & 0xff);
	ftp_reply(sess,FTP_PASVOK,text);

}


static void do_type(session_t *sess)
{
	if(strcmp(sess->arg,"A") == 0){
		sess->is_ascii = 1;
		ftp_reply(sess,FTP_TYPEOK,"Switching to ASCII mode.");
	}else if(strcmp(sess->arg,"I") == 0){
		sess->is_ascii = 0;
		ftp_reply(sess,FTP_TYPEOK,"Switching to Binary mode.");
	}else {
		ftp_reply(sess,FTP_BADCMD,"Unrecognised TYPE command");
	}
}


static void do_stru(session_t *sess)
{

}


static void do_mode(session_t *sess)
{

}


static void do_retr(session_t *sess)
{
	// 下载文件
	// 断点续载

	// 创建数据连接
	if(get_transfer_fd(sess) == 0){
		ftp_reply(sess,FTP_BADSENDCONN,"Use PORT OR PASV first");
		return;
	}
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;

	// 打开文件
	int fd = open(sess->arg,O_RDONLY);
	if(fd == -1){
		ftp_reply(sess,FTP_FILEFAIL,"Failed to open file");
		return;
	}
	// 加读锁
	int ret;
	ret = lock_file_read(fd);
	if(ret == -1){
		ftp_reply(sess,FTP_FILEFAIL,"Failed to open file");
		return;
	}

	// 判断是否是普通文件
	struct stat sbuf;
	ret = fstat(fd,&sbuf);
	if(!S_ISREG(sbuf.st_mode)){
		ftp_reply(sess,FTP_FILEFAIL,"Failed to open file");
		return;
	}

	if(offset != 0){
		ret = lseek(fd,offset,SEEK_SET);
		if(ret == -1){
			ftp_reply(sess,FTP_FILEFAIL,"Failed to open file");
			return;
		}
	}
	//150 Opening ASCII mode data connection for a.out (14124 bytes).
	char text[1024] = {0};
	if(sess->is_ascii){
		sprintf(text,"Opening ASCII mode data connection for %s (%lld bytes).",sess->arg,(long long)sbuf.st_size);
	}else{
		sprintf(text,"Opening BINARY mode data connection for %s (%lld bytes).",sess->arg,(long long)sbuf.st_size);
	}
	// 150
	ftp_reply(sess,FTP_DATACONN,text);

	int flag = 0;
	/*
	// 下载文件
	char buf[4096];
	while(1){
		ret = read(fd,buf,sizeof(buf));
		if(ret == -1){
			if(errno == EINTR){
				continue;
			}else{
				flag = 1;
				break;
			}
		}else if(ret == 0){
			flag = 0;
			break;
		}
		if(writen(sess->data_fd,buf,ret) !=  ret){
			flag = 2;
			break;
		}
	}
	*/
	long long bytes_to_send = sbuf.st_size;
	if(offset > bytes_to_send){
		bytes_to_send = 0;
	}else {
		bytes_to_send -= offset;
	}

	while(bytes_to_send){
		int num_this_time = bytes_to_send > 4096 ? 4096 : bytes_to_send;
		ret = sendfile(sess->data_fd,fd,NULL,num_this_time);
		if(ret == -1){
			flag = 2;
			break;
		}
		bytes_to_send -= ret;
	}

	if(bytes_to_send == 0){
		flag = 0;
	}
	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	close(fd);
	if(flag == 0){
		// 226
		ftp_reply(sess,FTP_TRANSFEROK,"Transfer complete.");
	}else if(flag == 1){
		//426
		ftp_reply(sess,FTP_BADSENDFILE,"Failure reading from local file");
	}else if(flag == 2){
		//451
		ftp_reply(sess,FTP_BADSENDNET,"Failure writting to network stream.");
	}
}


static void do_stor(session_t *sess)
{
	upload_common(sess,0);
}


static void do_appe(session_t *sess)
{
	upload_common(sess,1);
}


static void do_list(session_t *sess)
{
	// 创建数据连接
	if(get_transfer_fd(sess) == 0){
		ftp_reply(sess,FTP_BADSENDCONN,"Use PORT OR PASV first");
		return;
	}
	// 150
	ftp_reply(sess,FTP_DATACONN,"Here comes the directory listing.");

	// 传输列表
	list_common(sess,1);
	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	// 226
	ftp_reply(sess,FTP_TRANSFEROK,"Directory send OK.");

}


static void do_nlst(session_t *sess)
{
	// 创建数据连接
	if(get_transfer_fd(sess) == 0){
		ftp_reply(sess,FTP_BADSENDCONN,"Use PORT OR PASV first");
		return;
	}
	// 150
	ftp_reply(sess,FTP_DATACONN,"Here comes the directory listing.");

	// 传输列表
	list_common(sess,0);
	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	// 226
	ftp_reply(sess,FTP_TRANSFEROK,"Directory send OK.");


}


static void do_rest(session_t *sess)
{
	sess->restart_pos = str_to_longlong(sess->arg);
	char text[1024] = {0};
	sprintf(text,"Restart position accepted (%lld).",sess->restart_pos);
	ftp_reply(sess,FTP_RESTOK,text);
}


static void do_abor(session_t *sess)
{

}


static void do_pwd(session_t *sess)
{
	char text[1024] = {0};
	char dir[1024+1] = {0};
	getcwd(dir,1024);
	sprintf(text,"\"%s\"",dir);
	ftp_reply(sess,FTP_PWDOK,text);
}


static void do_mkd(session_t *sess)
{
	if(mkdir(sess->arg,0777) < 0){
		ftp_reply(sess,FTP_FILEFAIL,"Create directory operation Failed.");
		return;
	}
	char text[4096] = {0};
	if(sess->arg[0] == '/'){
		sprintf(text,"%s created",sess->arg);
	}else {
		char dir[4096 + 1] = {0};
		getcwd(dir,4096);
		if(dir[strlen(dir) - 1] == '/'){
			sprintf(text,"%s%s created",dir,sess->arg);
		}else {
			sprintf(text,"%s/%s created",dir,sess->arg);
		}
	}
	
	ftp_reply(sess,FTP_MKDIROK,text);
}


static void do_rmd(session_t *sess)
{
	if(rmdir(sess->arg) < 0){
		ftp_reply(sess,FTP_NOPERM,"Remove directory operation failed.");
		return;
	}
	ftp_reply(sess,FTP_RMDIROK,"Remove directory operation successful");

}


static void do_dele(session_t *sess)
{
	if(unlink(sess->arg) < 0){
		ftp_reply(sess,FTP_FILEFAIL,"Delete operation Failed");
		return;
	}
	ftp_reply(sess,FTP_DELEOK,"Delete operation successful");
}


static void do_rnfr(session_t *sess)
{
	sess->rnfr_name = (char *)malloc(strlen(sess->arg) + 1);
	memset(sess->rnfr_name,0,sizeof(strlen(sess->arg) + 1));
	strcpy(sess->rnfr_name,sess->arg);
	ftp_reply(sess,FTP_RNFROK,"Ready for RNTO");
}


static void do_rnto(session_t *sess)
{
	if(sess->rnfr_name == NULL){
		ftp_reply(sess,FTP_NEEDRNFR,"RNRF required first");
		return;
	}
	rename(sess->rnfr_name,sess->arg);
	ftp_reply(sess,FTP_RENAMEOK,"Rename successful");

	free(sess->rnfr_name);
	sess->rnfr_name = NULL;
}


static void do_site(session_t *sess)
{

}


static void do_syst(session_t *sess)
{
	ftp_reply(sess,FTP_SYSTOK,"UNIX Type:　L8");
}


static void do_feat(session_t *sess)
{
	ftp_lreply(sess,FTP_FEAT,"Features:");
	writen(sess->ctrl_fd," EPRT\r\n",strlen(" EPRT\r\n"));
	writen(sess->ctrl_fd," EPSV\r\n",strlen(" EPRT\r\n"));
	writen(sess->ctrl_fd," MDTM\r\n",strlen(" MDTM\r\n"));
	writen(sess->ctrl_fd," PASV\r\n",strlen(" PASV\r\n"));
	writen(sess->ctrl_fd," REST STREAM\r\n",strlen(" REST STREAM\r\n"));
	writen(sess->ctrl_fd," SIZE\r\n",strlen(" SIZE\r\n"));
	writen(sess->ctrl_fd," TVFS\r\n",strlen(" TVFS\r\n"));
	writen(sess->ctrl_fd," UTF8\r\n",strlen(" UTF8\r\n"));
	ftp_reply(sess,FTP_FEAT,"End\r\n");
}


static void do_size(session_t *sess)
{
	struct stat buf;

	if(stat(sess->arg,&buf) < 0){
		ftp_reply(sess,FTP_FILEFAIL,"SIZE operation Failed");
		return;
	}
	if(!S_ISREG(buf.st_mode)){
		ftp_reply(sess,FTP_FILEFAIL,"Could not get file size");
		return;
	}
	char text[1024] = {0};
	sprintf(text,"%lld",(long long)buf.st_size);
	ftp_reply(sess,FTP_SIZEOK,text);
}


static void do_stat(session_t *sess)
{

}


static void do_noop(session_t *sess)
{

}


static void do_help(session_t *sess)
{

}




