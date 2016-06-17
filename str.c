#include "str.h"
#include "common.h"

void str_trim_crlf(char *str)
{
	char *p = &str[strlen(str)-1];
	while(*p == '\r' || *p == '\n'){
		*p-- = '\0';
	}

}

void str_split(const char *str, char *left, char *right, char c)
{
	char *p = strchr(str,c);
	if(p == NULL){
		strcpy(left,str);
	}else{
		strncpy(left,str,p-str);
		strcpy(right,p+1);
	}
}

int str_all_space(const char *str)
{
	while(*str){
		if(!isspace(*str)){
			return 0;
		}
		str++;
	}
	return 1;
}

void str_upper(char *str)
{
	while(*str){
		*str = toupper(*str);
		str++;
	}
}

long long str_to_longlong(const char *str)
{
	//return atoll(str);
	long long result = 0;
	while(*str && *str >= '0' && *str <= '9'){
		result = result * 10 + (*str - '0');
		str++;
	}
	return result;
}

unsigned int str_octal_to_uint(const char *str)
{
	unsigned int result = 0;
	while(*str == '0'){
		str++;
	}
	while(*str && *str >= '0' && *str <= '7'){
		result = (result << 3) + (*str - '0');
		str++;
	}
	return result;
}
