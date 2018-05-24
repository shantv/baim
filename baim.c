/*
 * 12/28/99
 * BAIM - BitchX AIM Plugin/Module by Shant
 * 
 */

#include "irc.h"
#include "struct.h"
#include "dcc.h"
#include "ircaux.h"
#include "misc.h"
#include "output.h"
#include "lastlog.h"
#include "screen.h"
#include "status.h"
#include "window.h"
#include "vars.h"
#include "input.h"
#include "module.h"
#include "hook.h"
#include "log.h"
#define INIT_MODULE
#include "modval.h"

#include <stdio.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>

#define HOST 			"toc.oscar.aol.com"
#define PORT 			9993
#define INFO_PORT		80

#define CLIENT_NAME		"BAIM - BitchX AIM module v0.8a by Scewby"
#define CLIENT_SIGNON		"TIK:\\\$Revision: 112"

#define	SIGNON			1
#define	DATA			2
#define	ERROR			3
#define	SIGNOFF			4
#define KEEP_ALIVE		5

#define MAX_DATA_SIZE		1025
#define MAX_READ_SIZE		9192
#define MAX_NICK_SIZE		16+1
#define MAX_PASSWORD_SIZE	256
#define MAX_BUDDYS		150

#define IMIN			0
#define	IMOUT			1

#define BR			"BR"
#define BODY			"BODY"

typedef struct _fh
{
	char ast;
	char type;
	short seq;
	short datalen;
	char data[MAX_READ_SIZE];
} flap_header;

typedef struct _tc
{
	int fd;
	int seq_num;
} toc_conn;

typedef struct
{
	char sn[MAX_NICK_SIZE];
	int status;
	int signon_time;
	int idle;
	int appearances;
	int away;
} buddylist;

char *roast_password(char *);
toc_conn *toc_connect();
char *aim_encode(char *);
int aim_im_out(IrcCommandDll *, char *, char *, char *, char *);
int send_flap(int, int, char *, ...);
int aim_say(char *, ...);
int get_flap();
int aim_close();
char **aim_parse(char *, char *, int);
int load_list();
int check_on(char *, int);
int aim_who();
int add_buddy(char **);
int add_bud(IrcCommandDll *, char *, char *, char *, char *);
int del_bud(IrcCommandDll *, char *, char *, char *, char *);
int show_list(IrcCommandDll *, char *, char *, char *, char *);
int away_log(int type, char *, ...);
int aim_buddy_info(char *);
int aim_whois(IrcCommandDll *, char *, char *, char *, char *);
int aim_set_idle(IrcCommandDll *, char *, char *, char *, char *);
int aim_away(IrcCommandDll *, char *, char *, char *, char *);
int aim_back(IrcCommandDll *, char *, char *, char *, char *);
int Aim_Cleanup(IrcCommandDll **);
int set_info(void);
int check_connection();
void reset_timer();

toc_conn *a;
buddylist bl[MAX_BUDDYS];
int loffset=0;
int away=0;
char reason[MAX_DATA_SIZE];
char *user=NULL;
char aim[]="aim";

char *roast_password(char *pass) {
	char roaststring[]="Tic/Toc";
	char *final;
	int i;

	final=(char *) malloc(MAX_PASSWORD_SIZE);

	sprintf(final, "0x");
	for (i=0;(i<MAX_PASSWORD_SIZE) && (i<strlen(pass));i++)
		sprintf(final+strlen(final), "%02x", (pass[i] ^ roaststring[i % strlen(roaststring)]));

	return final;
}

toc_conn *toc_connect() { 
	struct sockaddr_in neat;
	struct hostent *he;
	char *roasted;
	flap_header fhread;
	flap_header fh;
	char signon_buff[2048];
	char sflap_buff[2048];
	char sh[] = {0,0,0,1};
	char tlv[] = {0,1};
	char *pass;
	short userlen;
	int c;

	a=(toc_conn *) malloc(sizeof(toc_conn));

	user=get_dllstring_var("aim_screenname");
	pass=get_dllstring_var("aim_password");

	if ((!user) || (!pass)) {
		aim_say("Error you did not set a username or password");
		return NULL;
	}

	userlen=htons(strlen(user));
	roasted=roast_password(pass);

	bzero((char *) &neat,sizeof(neat));
	neat.sin_family=AF_INET;
	neat.sin_addr.s_addr=inet_addr(HOST);
	neat.sin_port=htons(PORT);

	if ((a->fd=socket(AF_INET, SOCK_STREAM, 0))<1) {
		aim_say("Error creating socket failed");
		return NULL;
	}

	he=gethostbyname(HOST);
	bcopy(he->h_addr, (char *) &neat.sin_addr, he->h_length);

	aim_say("Connect Attempting connection");
	c=connect(a->fd,(struct sockaddr *) &neat,16);

	aim_say("Connect Connected to toc");

	send(a->fd, "FLAPON\r\n\r\n", 10, 0);
	recv(a->fd, &fhread, sizeof(fhread), 0);
	a->seq_num=ntohs(fhread.seq);

	fh.ast='*';
	fh.type=1;
	fh.seq=htons((short)a->seq_num++);
	fh.datalen=htons(strlen(user)+8);

	memcpy(sflap_buff, &fh, 6);
	memcpy(sflap_buff+6, sh, sizeof(sh));
	memcpy(sflap_buff+6+sizeof(sh), tlv, sizeof(tlv));
	memcpy(sflap_buff+6+sizeof(sh)+sizeof(tlv), &userlen, sizeof(userlen));
	memcpy(sflap_buff+6+sizeof(sh)+sizeof(tlv)+sizeof(userlen), user, strlen(user));

	send(a->fd, sflap_buff, strlen(user)+14, 0);

	sprintf(signon_buff, "toc_signon %s %d %s %s %s \"%s\"",
		"login.oscar.aol.com", 
		PORT, 
		user, 
		roasted, 
		"english", 
		CLIENT_SIGNON);

	aim_say("Connect Verifying username and password");
	send_flap(DATA, strlen(signon_buff)+1, signon_buff);

	if (get_flap()<0) return NULL;

	add_socketread(a->fd, PORT, 0, NULL, get_flap, NULL);
	loffset=0;
	if ((load_list()<0)) aim_say("BUDDY No buddy's in list");

	send_flap(DATA, -1, "toc_set_info \"%s\"\0", get_dllstring_var("aim_info"));
	send_flap(DATA, -1, "toc_init_done\0");
	send_flap(DATA, -1, "toc_set_idle 1\0");
	aim_say("Connect Starting Services");
	add_timer(0, "BAIM", (get_dllint_var("aim_keep_alive_check_time") * 1000), 1, (int)check_connection, NULL, NULL, NULL, "BAIM");

//	free(roasted);
	return a;
}

int send_flap(int type, int l, char *buf, ...) {
	flap_header fhead;
	char buff[MAX_DATA_SIZE];
	char aim_buff[MAX_DATA_SIZE];
	va_list args;
	va_start(args, buf);
	vsnprintf(aim_buff, MAX_DATA_SIZE, buf, args);
	va_end(args);

	fhead.ast = '*';
	fhead.type = type;
	fhead.seq = htons(a->seq_num++);
	if (l==-1) l=strlen(aim_buff)+1;
	fhead.datalen = htons((short)l);

	memcpy(buff, &fhead, 6);
	memcpy(buff+6, aim_buff, l);

	if (a->fd) {
		if (send(a->fd, buff, l+6, 0)<0) {
			aim_say("ERROR Sending data to toc");
			aim_close();
			return 0;
		}
	} else {
		aim_say("Error You are not connected to aim");
		return 0;
	}

	return 1;
}

int get_flap() {
	flap_header fh;
	int in,x=0,y=0,i,j;
	char **inbuff={0};
	char nick[MAX_NICK_SIZE];
	char final[MAX_READ_SIZE];
	char ar[MAX_DATA_SIZE+MAX_NICK_SIZE+2];

	fh.ast='\0';
	fh.type='\0';
	fh.seq=0;
	fh.datalen=0;
	bzero(fh.data, sizeof(fh.data));
	fh.data[0]='\0';

	if ((in=recv(a->fd, &fh, sizeof(fh), 0)>0)) {
		if (!(inbuff=aim_parse(":", fh.data, -1))) return -2;
		if (!strncmp(inbuff[0], "IM_IN", 4)) {
			for (x=0,y=0;*(inbuff[3]+x)!='\0';x++) {
				while (*(inbuff[3]+x)=='<') {
					while (*(inbuff[3]+x)!='>') {
						x++;
					}
					x++;
				}
				final[y++]=*(inbuff[3]+x);
				final[y]='\0';
			}
			for (i=0,j=0; i<strlen(inbuff[1]); i++)
				if (inbuff[1][i]!=' ') {
					nick[j++]=inbuff[1][i];
					nick[j]='\0';
				}
			addtabkey(nick, "im", 0);
			away_log(IMIN, "%s %s", nick, final);
			put_it("%s", 
				convert_output_format(
					get_dllstring_var("aim_im_in_format"),
					"%s %s %s",
					update_clock(GET_TIME),
					nick, 
					final)
			);
			if (away==1) {
				sprintf(ar, "%s <HR><font color=red><b>Auto response from %s:</b> %s</font><HR>", nick, user, reason);
				aim_im_out(NULL, NULL, ar, NULL, NULL);
			}
		}
		else if (!strncmp(inbuff[0], "ERROR", 5)) {
			inbuff[1][3]='\0';
			switch (atoi(inbuff[1])) {
				/* Auth errors */
				case 980:
					aim_say("Error 980: Incorrect nickname or password");
					aim_close();
					return -2;
					break;
				case 981:
					aim_say("Error 981: The service is temporarily unavailable");
					aim_close();
					return -2;
					break;
				case 982:
					aim_say("Error 982: Your warning level is currently too high to sign on");
					aim_close();
					return -2;
					break;
				case 983:
					aim_say("Error 983: Connecting and disconnecting too frequently, wait 10 minutes");
					aim_close();
					return -2;
					break;
				case 989:
					aim_say("Error 989: An unknown signon error has occurred");
					aim_close();
					return -2;
					break;

				 /* IM + Info Errors */
				case 960:
					aim_say("Error 960: You are sending message too fast to %s", inbuff[2]);
					return -2;
					break;
				case 961:
					aim_say("Error 961: You missed an im from %s because it was too big", inbuff[2]);
					return -2;
					break;
				case 962:
					aim_say("Error 962: You missed an im from %s because it was sent too fast", inbuff[2]);
					return -2;
					break;

				/* General Errors */
				case 901:
					aim_say("Error 901: %s not currently available", inbuff[2]);
					return -2;
					break;
				case 902:
					aim_say("Error 902: Warning of %s not currently available", inbuff[2]);
					return -2;
					break;
				case 903:
					aim_say("Error 903: A message has been dropped, you are exceeding the server speed limit");
					return -2;
					break;

				default:
					aim_say("Error An unknown error has occured");
					return -2;
					break;
			}
			aim_say("%s %s", inbuff[0], inbuff[1]);
			return -1;
		}
		else if (!strncmp(inbuff[0], "UPDATE_BUDDY", 12)) {
			check_on(fh.data, MAX_READ_SIZE);
//			if (do_hook(600, "BUDDY LOGIN")) aim_say("what the hell just happened?");
		}
		else if (!strncmp(inbuff[0], "GOTO_URL", 8)) {
			aim_buddy_info(inbuff[2]);
		}
	} 
	else {
		aim_say("ERROR Connection dropped by server");
		aim_close();
		return -1;
	}
	return 0;
}

char *aim_encode(char *encode) {
	char *encoded=NULL;
	int i, z=0, l;

	if (encode==NULL) return NULL;

	encoded=(char *) malloc(MAX_DATA_SIZE);
	sprintf(encoded, "\"");
	z+=strlen(encoded);

	for (i=0; i<strlen(encode); i++) {
		switch(encode[i]) {
			case '$':
			case '{':
			case '}':
			case '[':
			case ']':
			case '(':
			case ')':
			case '\"':
			case '\\':
				encoded[z++]='\\';
				encoded[z++]=encode[i];
				encoded[z]=0;
				break;
			default:
				encoded[z++]=encode[i];
				encoded[z]=0;
				break;
		}
	}

	l=strlen(encoded);
	encoded[l]='\"';
	encoded[l+1]='\0';

	return encoded;
}

int aim_close() {
//	aim_say("CONNECT Closing connection to aim");
	close_socketread(a->fd);
	loffset=0;
	bzero(bl, sizeof(bl));
//	free(user);
	free(a);
	return 0;
}

int aim_im_out(IrcCommandDll *intp, char *command, char *args, char *subargs, char *helparg) {
	char send_buff[MAX_DATA_SIZE];
	char **info;
	char *ret;

	if (!(info=aim_parse(" ", args, 1))) return 1;
	addtabkey(info[0], "im", 0);

	if (!(ret=aim_encode(info[1]))) return 1;
	ret[strlen(ret)]='\0';

	if (strlen(info[1])<1) return 1;

	if (!strncasecmp(info[0], user, strlen(user))) {
		aim_say("ERROR Cannot send IM to yourself.");
		// because if you are marked away on aim, you will
		// start an infinite loop of im's being sent back and forth
		// the bx session will crash.
		return 0;
	}
	
	put_it("%s",
		convert_output_format(
			get_dllstring_var("aim_im_out_format"),
			"%s %s %s",
			update_clock(GET_TIME),
			info[0], 
			info[1])
	);

	sprintf(send_buff, "toc_send_im %s %s", info[0], ret);
	if (!(send_flap(DATA, -1, send_buff))) return 0;
	send_flap(DATA, -1, "toc_set_idle 1\0");

	away_log(IMOUT, "%s %s", info[0], ret);
	
	free(ret);
	free(info);
	return 1;
}

int aim_say(char *format, ...) {
	char aim_buff[MAX_READ_SIZE];
	char tmp_buff[MAX_READ_SIZE];
	va_list args;

	va_start (args, format);
	vsnprintf(tmp_buff, MAX_DATA_SIZE, format, args);
	va_end(args);

	sprintf(aim_buff, "%s", convert_output_format(
		get_dllstring_var("aim_say_format"),
		"%s %s",
		update_clock(GET_TIME),
		tmp_buff));

	/* which works better? */
	add_to_screen(aim_buff);
//	put_it(aim_buff);

	return 0;
}

char **aim_parse(char *d, char *s, int i) {
	int z,offset=0,m=0,t=0,count=0;
	char **major;
	int slen=strlen(s);
	int ccount=0;

	if (i>0) {
		for (z=0; z<slen; z++)
			if (s[z]==d[0])	ccount++;

		if (ccount<i) return NULL;
	}

	if (i<0) {
		for (t=0; t<slen; t++)
			if (s[t]==d[0]) count++;
		i=count;
	}
	
	major=(char **) malloc((i+1)*sizeof(char **));
	for (z=0; z<(i+1); z++)
		major[z]=(char *) malloc(MAX_DATA_SIZE);

	for (z=0; z<strlen(s); z++) {
		if ((s[z]==d[0]) && (i>offset)) {
			offset++;
			m = 0;
			z++;
		}
		major[offset][m++]=s[z];
		major[offset][m]='\0';
	}
	return major;
}

int load_list() {
	FILE *fin;
	char read[MAX_DATA_SIZE];
	char **list=NULL;
	char add_buddy[MAX_DATA_SIZE];
	char in[MAX_DATA_SIZE];
	int x=0;
	int i=0;
	int y=0;
	int buddies=0;
	char *filename;
	char *file;

	filename=(char *) malloc(MAX_DATA_SIZE);
	sprintf(filename, "%s/%s", get_string_var(CTOOLZ_DIR_VAR), get_dllstring_var("aim_buddy_file"));
	file=expand_twiddle(filename);

	if(!(fin=fopen(file, "r"))) return -1;
	sprintf(add_buddy, "toc_add_buddy");
	while ((fgets(read, MAX_DATA_SIZE, fin))) {
		for (x=0,i=0; x<strlen(read); x++) {
			if ((read[x]=='\r')||(read[x]=='\n'))
				continue;
			in[i++]=read[x];
			in[i]='\0';
		}
		for (y=0;(*(in+y)!='\0');y++) {
			if (!(strncmp((in+y), "buddy", 5))) {
				if (buddies==45) {
					send_flap(DATA, -1, add_buddy);
//					add_buddy[0]='\0';
					bzero(add_buddy, sizeof(add_buddy));
					sprintf(add_buddy, "toc_add_buddy");
					buddies=0;
				}
				if (!(list=aim_parse("\"", in, -1))) return 0;
				sprintf(add_buddy+strlen(add_buddy), " \"%s\"", list[1]);
				buddies++;
			}
		}
	}
	if (buddies) {
		send_flap(DATA, -1, add_buddy);
	}
	fclose(fin);
//	free(file);
	free(filename);
	free(list);

	return 0;
}

int check_on(char *ns, int si) {
	int flapsize=6, ts=0, bout=0, woffset=0;
	char blah[MAX_READ_SIZE]={0};
	char **buds={0};

	while ((ts<si) && (!bout)) {
		ts+=flapsize;
		woffset=0;
		while (ns[ts]!='*') {
			blah[woffset++]=ns[ts];
			blah[woffset]=0;
			if (ts==si) {
				bout=1;
				break;
			}
			ts++;
		}
		if (!(buds=aim_parse(":", blah, 6))) return 1;
		add_buddy(buds);
	}
	free(buds);
	return 0;
}

int aim_who() {
	int i=0,count=0;
	char away[100];

	for (i=0; i<loffset; i++) {
		if ((bl[i].status==1)&&(bl[i].sn!='\0')) {
			count++;
			if (bl[i].away==1) 
				sprintf(away, "%s", convert_output_format("%p_AWAY_%n"));
			else 
				sprintf(away, "%s", convert_output_format("%PACTIVE%n"));

			put_it("%s",
				convert_output_format(
					get_dllstring_var("aim_who_format"),
					"%s %s %d %s",
					update_clock(GET_TIME),
					away, 
					bl[i].appearances,
					bl[i].sn)
			);
		}
	}
	put_it("%s",
		convert_output_format(
			get_dllstring_var("aim_buddy_count_format"),
			"%s %d",
			update_clock(GET_TIME),
			count)
	);
	return 0;
}

int add_buddy(char **buds) {
	int i;
	time_t t;
	int signon;
	int idle;
	
	signon=atoi(buds[4]);
	idle=atoi(buds[5]);
	
	/*
	 * do checking to see if its a duplicate,
	 * if its duplicate then set idle time, continue;
	 * else add to end of list
	 */

	t=time(NULL);

	if (buds[2][0]=='T') {
		for (i=0; i<loffset; i++) {
			if (!(strncmp(bl[i].sn, buds[1], strlen(buds[1])))) {

				/*
				 * doesnt matter if he's offline or online
				 * before, now he is online so lets set status
				 * to true, set idle time, then return success
				 */

				bl[i].signon_time=signon;
				bl[i].idle=idle;

				if(buds[6][2]!='U') {
					if ((bl[i].away!=1)&&(bl[i].status!=1)) bl[i].appearances++;
					bl[i].away=0;
				}
				else {
					bl[i].away=1;
				}

				if(bl[i].status!=1)
					aim_say("LOGIN %s", buds[1]);

				bl[i].status=1;
				return 0;
			}
		}
		/* didnt find user in list, add him to the end */
		sprintf(bl[loffset].sn, "%s", buds[1]);
		bl[loffset].status=1;
		bl[loffset].signon_time=signon;
		bl[loffset].idle=idle;
		bl[loffset].appearances=1;

		if(buds[6][2]!='U')
			bl[loffset].away=0;
		else 
			bl[loffset].away=1;

		aim_say("LOGIN %s", buds[1]);
		loffset++;
	}
	else if(buds[2][0]=='F') {
		/* user logged off, lets just set a flag for not online */
		for (i=0; i<loffset; i++) {
			if (!(strncmp(bl[i].sn, buds[1], strlen(buds[1])))) {
				bl[i].status=0;
				bl[i].idle=0;
				bl[i].away=0;
				aim_say("LOGOUT %s", buds[1]);
				break;
			}
		}
	}
	return 1;
}

int Aim_Cleanup(IrcCommandDll **interp) {
	aim_close();

	remove_module_proc(VAR_PROC, aim, NULL, NULL);
	remove_module_proc(COMMAND_PROC,aim,NULL,NULL);
	remove_module_proc(ALIAS_PROC,aim,NULL,NULL);

	return 0;
}

int aim_whois(IrcCommandDll *intp, char *command, char *args, char *subargs, char *helparg) {
	send_flap(DATA, -1, "toc_get_info %s", args);
	return 0;
}

int add_bud(IrcCommandDll *intp, char *command, char *args, char *subargs, char *helparg) {
	FILE *fp, *fout;
	char in[MAX_DATA_SIZE], *found, *gn, *final;
	int i=0;
	char *filename;
	char *file;
	char **data;
	int gfound=0;

	if (!(data=aim_parse(" ", args, 1))) return 0;
	if (!data[0] || !data[1]) {
		aim_say("Error Usage: /addbuddy <group> <screenname>");
		return 0;
	}

	filename=(char *) malloc(MAX_DATA_SIZE);
	sprintf(filename, "%s/%s", get_string_var(CTOOLZ_DIR_VAR), get_dllstring_var("aim_buddy_file"));
	file=expand_twiddle(filename);

	final=(char *) malloc(sizeof(char));

	if ((fp=fopen(file, "r"))==NULL) { 
		aim_say("Error opening %s for read", file);
		return 0;
	}
	while (fgets(in, MAX_DATA_SIZE, fp)) {
		final=(char *) realloc(final, (strlen(final)+strlen(in)));
		memcpy(final+i, in, strlen(in));
		i+=strlen(in);
		if ((found=strstr(in, "group"))) {
			if ((gn=strstr(found, data[0]))) {
				gfound=1;
				while (!strstr(in, "{")) {
					fgets(in, MAX_DATA_SIZE, fp);
					final=(char *) realloc(final, (strlen(final)+strlen(in)));
					memcpy(final+i, in, strlen(in));
					i+=strlen(in);
				}
				final=(char *) realloc(final, (strlen(final)+MAX_DATA_SIZE));
				i+=sprintf(final+i, "\tbuddy \"%s\"\n\t{\n\t}\n", data[1]);
			}
		}
	}
	fclose(fp);
	*(final+i)='\0';
	if (gfound==1) {
		if ((fout=fopen(file, "w"))!=NULL) {
			fprintf(fout, "%s", final);
			fclose(fout);
			send_flap(DATA, -1, "toc_add_buddy %s", aim_encode(data[1]));
			aim_say("Added %s to buddy list", data[1]);
		} else {
			aim_say("Error opening %s for write", file);
			return 0;
		}
	} else {
		aim_say("Error Group %s not found", data[0]);
	}

	free(final);

	return 0;
}

int away_log(int type, char *format, ...) {
	char tmp_buff[MAX_READ_SIZE];
	char *filelog;
	char *file;
	char **parsed={0};
	FILE *fplog;
	va_list args;

	va_start (args, format);
	vsnprintf(tmp_buff, MAX_DATA_SIZE, format, args);
	va_end(args);

	if (get_server_away(-2)==0) return -1;

	filelog=(char *) malloc(MAX_DATA_SIZE);
	sprintf(filelog, "%s/%s", get_string_var(CTOOLZ_DIR_VAR), get_string_var(MSGLOGFILE_VAR));
	file=expand_twiddle(filelog);
	if ((fplog=fopen(file, "a"))==NULL) {
		aim_say("Error opening %s for write", file);
		return 0;
	}
	if (!(parsed=aim_parse(" ", tmp_buff, 1))) return 0;
	switch(type) {
		case IMIN:
			set_int_var(MSGCOUNT_VAR, get_int_var(MSGCOUNT_VAR)+1);
			fprintf(fplog, "[AIM][%s(%s)(IM_IN)] %s\n", update_clock(GET_TIME), parsed[0], parsed[1]);
			break;
		case IMOUT:
			fprintf(fplog, "[AIM][%s(%s)(IM_OUT)] %s\n", update_clock(GET_TIME), parsed[0], parsed[1]);
			break;
		default:
			fprintf(fplog, "[AIM][%s(%s)(unknown)] %s\n", update_clock(GET_TIME), parsed[0], parsed[1]);
			break;
	}
	fclose(fplog);
	return 1;
}

int aim_buddy_info(char *ident) {
	int i;
	struct sockaddr_in info_host;
	struct hostent *h;
	char query[MAX_DATA_SIZE];
	char info[MAX_READ_SIZE];
	int x=0;
	int c;
	int len;
	char *com=NULL;
	char *arg;
	int start=0;

	bzero((char *) &info_host,sizeof(info_host));
	info_host.sin_family=AF_INET;
	info_host.sin_addr.s_addr=inet_addr(HOST);
	info_host.sin_port=htons(INFO_PORT);

	if (!(a->fd)) return 0;

	i=socket(AF_INET, SOCK_STREAM, 0);

	h=gethostbyname(HOST);
	bcopy(h->h_addr, (char *) &info_host.sin_addr, h->h_length);
	connect(i,(struct sockaddr *) &info_host,16);
	
	sprintf(query, "GET /%s HTTP/1.0\r\nAccept: */*\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", ident, HOST, CLIENT_NAME);
	write(i, query, strlen(query));
	recv(i, &info, sizeof(info), 0);

	len=strlen(info);

	arg=(char *) malloc(MAX_READ_SIZE);
	{
		int a=0;
		for (x=0;x<len;x++) {
			while (*(info+x)=='<') {
				com=(char *) malloc(MAX_READ_SIZE);
				c=0;
				x++;
				while (*(info+x)!='>') {
					if (*(info+x)=='\0') break;
					*(com+(c++))=*(info+(x++));
				}
				if (!strncasecmp(com, BODY, strlen(BODY))) start=1;
				if ((!strncasecmp(com, BR, strlen(BR)))) {
					*(arg+(a++))+='\n';
				}
				x++;
			}
			if ((*(info+x)=='\r') || (*(info+x)=='\n')) {
				continue;
			}
			if (start)
				*(arg+(a++))=*(info+x);
		}
	}
	aim_say("INFO \n%s", arg);
	close(i);
	free(com);
	return 1;
}

int aim_away(IrcCommandDll *intp, char *command, char *arg, char *subargs, char *helparg) {
	char send[MAX_DATA_SIZE];
	char *coded;

	if (!arg) {
		away=0;
		aim_say("BACK you are no longer marked as being away");
		send_flap(DATA, -1, send);
	} else {
		away=1;
		aim_say("AWAY reason: (%s)", arg);

		reason[0]='\0';
		strcpy(reason, arg);
	
		if ((coded=aim_encode(arg))==NULL) return 0;
		sprintf(send, "toc_set_away %s", coded);
		send_flap(DATA, -1, send);
	}
	return 0;
}

int aim_back(IrcCommandDll *intp, char *command, char *arg, char *subargs, char *helparg) {
	away=0;
	aim_say("BACK you are no longer marked as being away");
	send_flap(DATA, -1, "toc_set_away\0");
	return 1;
}

int aim_set_idle(IrcCommandDll *intp, char *command, char *args, char *subargs, char *helparg) {
	int idle=atoi(args);
	char buff[MAX_DATA_SIZE];

	if ((idle<0)) {
		aim_say("IDLE You entered an invalid idle time");
		return 1;
	}

	sprintf(buff, "toc_set_idle %s", args);
	send_flap(DATA, -1, buff);

	aim_say("IDLE Your AIM idle time has now been set to %s minutes", args);
	return 1;
}

int del_bud(IrcCommandDll *intp, char *command, char *args, char *subargs, char *helparg) {
	FILE *fp, *fout;
	char in[MAX_DATA_SIZE], *found, *gn, *final;
	int i=0;
	char *filename;
	char *file;

	if (!args) {
		aim_say("Error Usage: [/delbud <buddy>]");
		return 1;
	}
	
	final=(char *) malloc(sizeof(char));

	filename=(char *) malloc(MAX_DATA_SIZE);
	sprintf(filename, "%s/%s", get_string_var(CTOOLZ_DIR_VAR), get_dllstring_var("aim_buddy_file"));
	file=expand_twiddle(filename);

	if ((fp=fopen(file, "r"))==NULL) { 
		aim_say("Error opening %s for read", file);
		return 0;
	}
	while (fgets(in, MAX_DATA_SIZE, fp)) {
		final=(char *) realloc(final, (strlen(final)+strlen(in)));
		if ((found=strstr(in, "buddy"))) {
			if ((gn=strstr(found, args))) {
				while (!strstr(in, "{")) {
					fgets(in, MAX_DATA_SIZE, fp);
				}
				while (!strstr(in, "}")) {
					fgets(in, MAX_DATA_SIZE, fp);
				}
				fgets(in, MAX_DATA_SIZE, fp);
			}
		}
		memcpy(final+i, in, strlen(in));
		i+=strlen(in);
	}
	fclose(fp);
	*(final+i)='\0';

	if ((fout=fopen(file, "w"))!=NULL) {
		fprintf(fout, "%s", final);
		fclose(fout);
		aim_say("DELETED %s from buddy list", args);
	}

	send_flap(DATA, -1, "toc_remove_buddy %s\0", aim_encode(args));

	free(final);
	return 1;
}

int show_list(IrcCommandDll *intp, char *command, char *args, char *subargs, char *helparg) {
	char *file;
	char *filename;
	char **data;
	FILE *fp;
	char in[MAX_DATA_SIZE];
	int count=0;

	filename=(char *) malloc(MAX_DATA_SIZE);
	sprintf(filename, "%s/%s", get_string_var(CTOOLZ_DIR_VAR), get_dllstring_var("aim_buddy_file"));
	file=expand_twiddle(filename);

	if ((fp=fopen(file, "r"))==NULL) { 
		aim_say("Error opening %s for read", file);
		return 0;
	}

	while (fgets(in, MAX_DATA_SIZE, fp)) {
		if (strstr(in, "buddy")) {
			if (!(data=aim_parse("\"", in, -1))) return 0;
			put_it("%s",
				convert_output_format(
					get_dllstring_var("aim_show_list_format"),
					"%s",
					data[1])
			);
			free(data);
			count++;
		}
	}
	aim_say("LIST %d buddy's in list", count);
	return 1;
}

int set_info(void) {
	char *info;
	char *info_set;

	info=get_dllstring_var("aim_info");
	info_set=(char *) malloc(sizeof(char)*strlen(info)+19);

	sprintf(info_set, "toc_set_info \"%s\"", info);

	send_flap(DATA, -1, info_set);

	aim_say("INFO Your information has been changed");
	free(info_set);
	return 0;
}

int check_connection() {
	int i=0;
	add_timer(0, "BAIM", (get_dllint_var("aim_keep_alive_check_time") * 1000), 1, (int)check_connection, NULL, NULL, NULL, "BAIM");
	i=send_flap(KEEP_ALIVE, 0, NULL);
	if (i==0 && (get_dllint_var("aim_persistent_connect")==1))
		toc_connect();
	return i;
}

void reset_timer() {
	delete_timer("BAIM");
	check_connection();
}

int Baim_Init(IrcCommandDll **intp, Function_ptr *global_table) {
	char aim_say_format[]="%K[%RAIM%K][%P$0%K][%c(%B$1%c)%K]%n $2- ";
	char im_in_format[]="%K[%P$0%K][%B(%c$1%B)%K]%n $2- ";
	char im_out_format[]="%K[%P$0%K][%Pim_out%B(%P$1%B)%K]%n $2- ";
	char show_list_format[]="%K[ %Y$0-\t%K] ";
	char aim_who_format[]="%K[ $1 %K] %c(%B$2%c)(%B$3-%c)";
	char aim_buddy_count_format[]="%K[ %Y$1 Buddy's on line %K]";
	char *version;
	
	version=(char *) malloc(MAX_DATA_SIZE);
//	a=(toc_conn *) malloc(sizeof(toc_conn));

	initialize_module(aim);

	/*
	 * I'm trying to keep all vars together in a /set
	 * so they all start with "aim_"
	 */

	add_module_proc(VAR_PROC, aim, "aim_toc_server", "toc.oscar.aol.com", STR_TYPE_VAR, 0, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_toc_port", NULL, INT_TYPE_VAR, 5190, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_screenname", NULL, STR_TYPE_VAR, 0, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_password", NULL, STR_TYPE_VAR, 0, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_info", CLIENT_NAME, STR_TYPE_VAR, 0, set_info, NULL);
	add_module_proc(VAR_PROC, aim, "aim_buddy_file", "buddy.lst", STR_TYPE_VAR, 0, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_say_format", aim_say_format, STR_TYPE_VAR, 0, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_im_in_format", im_in_format, STR_TYPE_VAR, 0, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_im_out_format", im_out_format, STR_TYPE_VAR, 0, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_show_list_format", show_list_format, STR_TYPE_VAR, 0, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_who_format", aim_who_format, STR_TYPE_VAR, 0, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_buddy_count_format", aim_buddy_count_format, STR_TYPE_VAR, 0, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_persistent_connect", "persistent connect", BOOL_TYPE_VAR, 1, NULL, NULL);
	add_module_proc(VAR_PROC, aim, "aim_keep_alive_check_time", "keep alive check time", INT_TYPE_VAR, 120, reset_timer, NULL);

	add_module_proc(COMMAND_PROC, aim, "aim", NULL, 0, 0, toc_connect, "Login to aim [/aim]");
	add_module_proc(COMMAND_PROC, aim, "aclose", NULL, 0, 0, aim_close, "Close connection to aim [/aclose]");
	add_module_proc(COMMAND_PROC, aim, "im", NULL, 0, 0, aim_im_out, "Send Instant Message [/im <screnname> <msg>]");
	add_module_proc(COMMAND_PROC, aim, "aw", NULL, 0, 0, aim_who, "Show buddy list [/aw]");
	add_module_proc(COMMAND_PROC, aim, "awho", NULL, 0, 0, aim_whois, "Get user information [/awho <screenname>]");
	add_module_proc(COMMAND_PROC, aim, "delbuddy", NULL, 0, 0, del_bud, "Delete buddy, usage [/delbuddy <screenname>]");
	add_module_proc(COMMAND_PROC, aim, "aimidle", NULL, 0, 0, aim_set_idle, "Set your idle time, usage [/setidle <Idle Minutes>]");
	add_module_proc(COMMAND_PROC, aim, "showlist", NULL, 0, 0, show_list, "Displays your buddy list [/showlist]");
	add_module_proc(COMMAND_PROC, aim, "aaway", NULL, 0, 0, aim_away, "Set away reason [/aaway <reason>]");
	add_module_proc(COMMAND_PROC, aim, "aback", NULL, 0, 0, aim_back, "Set away untrue [/aback]");

	add_module_proc(COMMAND_PROC, aim, "addbuddy", NULL, 0, 0, add_bud, "Add buddy, usage [/addbuddy <group> <screenname>]");
//	add_module_proc(HOOK_PROC, aim, NULL, "*", 600, 1, NULL, NULL);

	sprintf(version, "$0+%s - $2 $3", CLIENT_NAME);
	fset_string_var(FORMAT_VERSION_FSET, version);

	aim_say("LOADED %s", CLIENT_NAME);

	free(version);
	return 0;
}
