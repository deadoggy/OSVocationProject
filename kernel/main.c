
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                            main.c
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                                                    Forrest Yu, 2005
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#include "type.h"
#include "stdio.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "fs.h"
#include "proc.h"
#include "tty.h"
#include "console.h"
#include "global.h"
#include "proto.h"
#include "time.h"
#include "io.h"

#define MINUTE 60
#define HOUR (60*MINUTE)
#define DAY (24*HOUR)
#define YEAR (365*DAY)

long startup_time =0;
extern long kernel_mktime(struct tm * tm);
// Getting time from CMOS
#define CMOS_READ(addr) ({ \
    outb_p(0x80|addr,0x70); \
    inb_p(0x71); \
})

#define BCD_TO_BIN(val) ((val)=((val)&15) + ((val)>>4)*10)

static void init_time(void)
{
	struct tm time;

	do {
		time.tm_sec = CMOS_READ(0);
		time.tm_min = CMOS_READ(2);
		time.tm_hour = CMOS_READ(4);
		time.tm_mday = CMOS_READ(7);
		time.tm_mon = CMOS_READ(8)-1;
		time.tm_year = CMOS_READ(9);
	} while (time.tm_sec != CMOS_READ(0));
	BCD_TO_BIN(time.tm_sec);
	BCD_TO_BIN(time.tm_min);
	BCD_TO_BIN(time.tm_hour);
	BCD_TO_BIN(time.tm_mday);
	BCD_TO_BIN(time.tm_mon);
	BCD_TO_BIN(time.tm_year);
	startup_time = kernel_mktime(&time);
}

struct time get_time_RTC()
{
	struct time t;
	MESSAGE msg;
	msg.type = GET_RTC_TIME;
	msg.BUF= &t;
	send_recv(BOTH, TASK_SYS, &msg);
	return t;
}
/*****************************************************************************
 *                               kernel_main
 *****************************************************************************/
/**
 * jmp from kernel.asm::_start.
 *
 *****************************************************************************/
PUBLIC int kernel_main()
{
	disp_str("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

        init_time();

	int i, j, eflags, prio;
        u8  rpl;
        u8  priv; /* privilege */

	struct task * t;
	struct proc * p = proc_table;

	char * stk = task_stack + STACK_SIZE_TOTAL;

	for (i = 0; i < NR_TASKS + NR_PROCS; i++,p++,t++) {
		if (i >= NR_TASKS + NR_NATIVE_PROCS) {
			p->p_flags = FREE_SLOT;
			continue;
		}

	        if (i < NR_TASKS) {     /* TASK */
                        t	= task_table + i;
                        priv	= PRIVILEGE_TASK;
                        rpl     = RPL_TASK;
                        eflags  = 0x1202;/* IF=1, IOPL=1, bit 2 is always 1 */
			prio    = 15;
                }
                else {                  /* USER PROC */
                        t	= user_proc_table + (i - NR_TASKS);
                        priv	= PRIVILEGE_USER;
                        rpl     = RPL_USER;
                        eflags  = 0x202;	/* IF=1, bit 2 is always 1 */
			prio    = 5;
                }

		strcpy(p->name, t->name);	/* name of the process */
		p->p_parent = NO_TASK;

		if (strcmp(t->name, "INIT") != 0) {
			p->ldts[INDEX_LDT_C]  = gdt[SELECTOR_KERNEL_CS >> 3];
			p->ldts[INDEX_LDT_RW] = gdt[SELECTOR_KERNEL_DS >> 3];

			/* change the DPLs */
			p->ldts[INDEX_LDT_C].attr1  = DA_C   | priv << 5;
			p->ldts[INDEX_LDT_RW].attr1 = DA_DRW | priv << 5;
		}
		else {		/* INIT process */
			unsigned int k_base;
			unsigned int k_limit;
			int ret = get_kernel_map(&k_base, &k_limit);
			assert(ret == 0);
			init_desc(&p->ldts[INDEX_LDT_C],
				  0, /* bytes before the entry point
				      * are useless (wasted) for the
				      * INIT process, doesn't matter
				      */
				  (k_base + k_limit) >> LIMIT_4K_SHIFT,
				  DA_32 | DA_LIMIT_4K | DA_C | priv << 5);

			init_desc(&p->ldts[INDEX_LDT_RW],
				  0, /* bytes before the entry point
				      * are useless (wasted) for the
				      * INIT process, doesn't matter
				      */
				  (k_base + k_limit) >> LIMIT_4K_SHIFT,
				  DA_32 | DA_LIMIT_4K | DA_DRW | priv << 5);
		}

		p->regs.cs = INDEX_LDT_C << 3 |	SA_TIL | rpl;
		p->regs.ds =
			p->regs.es =
			p->regs.fs =
			p->regs.ss = INDEX_LDT_RW << 3 | SA_TIL | rpl;
		p->regs.gs = (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;
		p->regs.eip	= (u32)t->initial_eip;
		p->regs.esp	= (u32)stk;
		p->regs.eflags	= eflags;

		p->ticks = p->priority = prio;

		p->p_flags = 0;
		p->p_msg = 0;
		p->p_recvfrom = NO_TASK;
		p->p_sendto = NO_TASK;
		p->has_int_msg = 0;
		p->q_sending = 0;
		p->next_sending = 0;

		for (j = 0; j < NR_FILES; j++)
			p->filp[j] = 0;

		stk -= t->stacksize;
	}

	k_reenter = 0;
	ticks = 0;

	p_proc_ready	= proc_table;

	init_clock();
        init_keyboard();

	restart();

	while(1){}
}


/*****************************************************************************
 *                                get_ticks
 *****************************************************************************/
PUBLIC int get_ticks()
{
	MESSAGE msg;
	reset_msg(&msg);
	msg.type = GET_TICKS;
	send_recv(BOTH, TASK_SYS, &msg);
	return msg.RETVAL;
}


/**
 * @struct posix_tar_header
 * Borrowed from GNU `tar'
 */
struct posix_tar_header
{				/* byte offset */
	char name[100];		/*   0 */
	char mode[8];		/* 100 */
	char uid[8];		/* 108 */
	char gid[8];		/* 116 */
	char size[12];		/* 124 */
	char mtime[12];		/* 136 */
	char chksum[8];		/* 148 */
	char typeflag;		/* 156 */
	char linkname[100];	/* 157 */
	char magic[6];		/* 257 */
	char version[2];	/* 263 */
	char uname[32];		/* 265 */
	char gname[32];		/* 297 */
	char devmajor[8];	/* 329 */
	char devminor[8];	/* 337 */
	char prefix[155];	/* 345 */
	/* 500 */
};

/*****************************************************************************
 *                                untar
 *****************************************************************************/
/**
 * Extract the tar file and store them.
 *
 * @param filename The tar file.
 *****************************************************************************/
void untar(const char * filename)
{
	printf("[extract `%s'\n", filename);
	int fd = open(filename, O_RDWR);
	assert(fd != -1);

	char buf[SECTOR_SIZE * 16];
	int chunk = sizeof(buf);
	int i = 0;
	int bytes = 0;

	while (1) {
		bytes = read(fd, buf, SECTOR_SIZE);
		assert(bytes == SECTOR_SIZE); /* size of a TAR file
					       * must be multiple of 512
					       */
		if (buf[0] == 0) {
			if (i == 0)
				printf("    need not unpack the file.\n");
			break;
		}
		i++;

		struct posix_tar_header * phdr = (struct posix_tar_header *)buf;

		/* calculate the file size */
		char * p = phdr->size;
		int f_len = 0;
		while (*p)
			f_len = (f_len * 8) + (*p++ - '0'); /* octal */

		int bytes_left = f_len;
		int fdout = open(phdr->name, O_CREAT | O_RDWR | O_TRUNC);
		if (fdout == -1) {
			printf("    failed to extract file: %s\n", phdr->name);
			printf(" aborted]\n");
			close(fd);
			return;
		}
		printf("    %s", phdr->name);
		while (bytes_left) {
			int iobytes = min(chunk, bytes_left);
			read(fd, buf,
			     ((iobytes - 1) / SECTOR_SIZE + 1) * SECTOR_SIZE);
			bytes = write(fdout, buf, iobytes);
			assert(bytes == iobytes);
			bytes_left -= iobytes;
			printf(".");
		}
		printf("\n");
		close(fdout);
	}

	if (i) {
		lseek(fd, 0, SEEK_SET);
		buf[0] = 0;
		bytes = write(fd, buf, 1);
		assert(bytes == 1);
	}

	close(fd);

	printf(" done, %d files extracted]\n", i);
}

/*****************************************************************************
 *                                shabby_shell
 *****************************************************************************/
/**
 * A very very simple shell.
 *
 * @param tty_name  TTY file name.
 *****************************************************************************/
void shabby_shell(const char * tty_name)
{
	int fd_stdin  = open(tty_name, O_RDWR);
	assert(fd_stdin  == 0);
	int fd_stdout = open(tty_name, O_RDWR);
	assert(fd_stdout == 1);

	while(0 == login())
    {
        printf("\nLogin failed!\n\n");
    }

    printf("\nLogin Success\n\n");



	char rdbuf[128];

	while (1) {
		write(1, "$ ", 2);
		int r = read(0, rdbuf, 70);
		rdbuf[r] = 0;

		int argc = 0;
		char * argv[PROC_ORIGIN_STACK];
		char * p = rdbuf;
		char * s;
		int word = 0;
		char ch;
		do {
			ch = *p;
			if (*p != ' ' && *p != 0 && !word) {
				s = p;
				word = 1;
			}
			if ((*p == ' ' || *p == 0) && word) {
				word = 0;
				argv[argc++] = s;
				*p = 0;
			}
			p++;
		} while(ch);
		argv[argc] = 0;

		if(1 == kernel_commond(argv,argc))
        {
            continue;
        }

		int fd = open(argv[0], O_RDWR);
		if (fd == -1) {
			if (rdbuf[0]) {
				write(1, "Unknown commond: ", 17);
				write(1, rdbuf, r);
				write(1, "\n", 1);
			}
		}
		else {
			close(fd);
			int pid = fork();
			if (pid != 0) { /* parent */
				int s;
				wait(&s);
			}
			else {	/* child */
				execv(argv[0], argv);
			}
		}
	}

	close(1);
	close(0);
}

/*****************************************************************************
 *                                Init
 *****************************************************************************/
/**
 * The hen.
 *
 *****************************************************************************/
void Init()
{
	int fd_stdin  = open("/dev_tty0", O_RDWR);
	assert(fd_stdin  == 0);
	int fd_stdout = open("/dev_tty0", O_RDWR);
	assert(fd_stdout == 1);

	printf("Init() is running ...\n");

	/* extract `cmd.tar' */
	untar("/cmd.tar");




        clear_screen();
	animation();
	char * tty_list[] = {"/dev_tty1", "/dev_tty2"};

	int i;
	for (i = 0; i < sizeof(tty_list) / sizeof(tty_list[0]); i++) {
		int pid = fork();
		if (pid != 0) { /* parent process */

		}
		else {	/* child process */

                close(fd_stdin);
                close(fd_stdout);

	        shabby_shell(tty_list[i]);
		assert(0);
		}
	}

	inittrans();


	while (1) {
        int s;
		int child = wait(&s);
		printf("child (%d) exited with status: %d.\n", child, s);
	}

	assert(0);
}


/*======================================================================*
                               TestA
 *======================================================================*/
void TestA()
{
	for(;;);
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestB()
{
	for(;;);
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestC()
{
	for(;;);
}

/*****************************************************************************
 *                                panic
 *****************************************************************************/
PUBLIC void panic(const char *fmt, ...)
{
	int i;
	char buf[256];

	/* 4 is the size of fmt in the stack */
	va_list arg = (va_list)((char*)&fmt + 4);

	i = vsprintf(buf, fmt, arg);

	printl("%c !!panic!! %s", MAG_CH_PANIC, buf);

	/* should never arrive here */
	__asm__ __volatile__("ud2");
}

PUBLIC void clear_screen()
{
    int times = 25;
    while(times--)
    {
        printf("\n");
    }
}



PUBLIC void wait_sec()
{
    int i = 500000;
    while(i--);
}


PUBLIC  void animation()
{

    printf("                        _ooOoo_                   \n");
    wait_sec();
    clear_screen();

    printf("                        _ooOoo_                   \n");
    printf("                       o8888888o                  \n");
    printf("                       88\" . \"88                  \n");
    wait_sec();
    clear_screen();

     printf("                        _ooOoo_                   \n");
    printf("                       o8888888o                  \n");
    printf("                       88\" . \"88                  \n");
    printf("                       (| -_- |)                  \n");
    printf("                       O\\  =  /O                  \n");
    wait_sec();
    clear_screen();

    printf("                        _ooOoo_                   \n");
    printf("                       o8888888o                  \n");
    printf("                       88\" . \"88                  \n");
    printf("                       (| -_- |)                  \n");
    printf("                       O\\  =  /O                  \n");
    printf("                    ____/`---'\\____               \n");
    printf("                  .'  \\\\|     |//  `.             \n");
    wait_sec();
    clear_screen();

     printf("                        _ooOoo_                   \n");
    printf("                       o8888888o                  \n");
    printf("                       88\" . \"88                  \n");
    printf("                       (| -_- |)                  \n");
    printf("                       O\\  =  /O                  \n");
    printf("                    ____/`---'\\____               \n");
    printf("                  .'  \\\\|     |//  `.             \n");
    printf("                 /  \\\\|||  :  |||//  \\            \n");
    printf("                /  _||||| -:- |||||-  \\           \n");
    wait_sec();
    clear_screen();

    printf("                        _ooOoo_                   \n");
    printf("                       o8888888o                  \n");
    printf("                       88\" . \"88                  \n");
    printf("                       (| -_- |)                  \n");
    printf("                       O\\  =  /O                  \n");
    printf("                    ____/`---'\\____               \n");
    printf("                  .'  \\\\|     |//  `.             \n");
    printf("                 /  \\\\|||  :  |||//  \\            \n");
    printf("                /  _||||| -:- |||||-  \\           \n");
    printf("                |   | \\\\\\  -  /// |   |           \n");
    printf("                | \_|  ''\\---/''  |   |           \n");
    wait_sec();
    clear_screen();

    printf("                        _ooOoo_                   \n");
    printf("                       o8888888o                  \n");
    printf("                       88\" . \"88                  \n");
    printf("                       (| -_- |)                  \n");
    printf("                       O\\  =  /O                  \n");
    printf("                    ____/`---'\\____               \n");
    printf("                  .'  \\\\|     |//  `.             \n");
    printf("                 /  \\\\|||  :  |||//  \\            \n");
    printf("                /  _||||| -:- |||||-  \\           \n");
    printf("                |   | \\\\\\  -  /// |   |           \n");
    printf("                | \_|  ''\\---/''  |   |           \n");
    printf("                \\  .-\\__  `-`  ___/-. /           \n");
    printf("              ___`. .'  /--.--\\  `. . __          \n");
    wait_sec();
    clear_screen();

    printf("                        _ooOoo_                   \n");
    printf("                       o8888888o                  \n");
    printf("                       88\" . \"88                  \n");
    printf("                       (| -_- |)                  \n");
    printf("                       O\\  =  /O                  \n");
    printf("                    ____/`---'\\____               \n");
    printf("                  .'  \\\\|     |//  `.             \n");
    printf("                 /  \\\\|||  :  |||//  \\            \n");
    printf("                /  _||||| -:- |||||-  \\           \n");
    printf("                |   | \\\\\\  -  /// |   |           \n");
    printf("                | \_|  ''\\---/''  |   |           \n");
    printf("                \\  .-\\__  `-`  ___/-. /           \n");
    printf("              ___`. .'  /--.--\\  `. . __          \n");
    printf("           .\"\" '<  `.___\\_<|>_/___.'  >'\"\".       \n");
    printf("          | | :  `- `.;`\\ _ /`;.`/ - ` : | |      \n");
    wait_sec();
    clear_screen();

    printf("                        _ooOoo_                   \n");
    printf("                       o8888888o                  \n");
    printf("                       88\" . \"88                  \n");
    printf("                       (| O_O |)                  \n");
    printf("                       O\\  =  /O                  \n");
    printf("                    ____/`---'\\____               \n");
    printf("                  .'  \\\\|     |//  `.             \n");
    printf("                 /  \\\\|||  :  |||//  \\            \n");
    printf("                /  _||||| -:- |||||-  \\           \n");
    printf("                |   | \\\\\\  -  /// |   |           \n");
    printf("                | \_|  ''\\---/''  |   |           \n");
    printf("                \\  .-\\__  `-`  ___/-. /           \n");
    printf("              ___`. .'  /--.--\\  `. . __          \n");
    printf("           .\"\" '<  `.___\\_<|>_/___.'  >'\"\".       \n");
    printf("          | | :  `- `.;`\\ _ /`;.`/ - ` : | |      \n");
    printf("          \\  \\ `-.   \\_ __\\ /__ _/   .-` /  /     \n");
    printf("     ======`-.____`-.___\\_____/___.-`____.-'======\n");
    printf("                        `=---='                   \n");
    printf("     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");

    wait_sec();
    wait_sec();
    wait_sec();
    wait_sec();
    clear_screen();

    printf("                        _ooOoo_                   \n");
    printf("                       o8888888o                  \n");
    printf("                       88\" . \"88                  \n");
    printf("                       (| -_- |)                  \n");
    printf("                       O\\  =  /O                  \n");
    printf("                    ____/`---'\\____               \n");
    printf("                  .'  \\\\|     |//  `.             \n");
    printf("                 /  \\\\|||  :  |||//  \\            \n");
    printf("                /  _||||| -:- |||||-  \\           \n");
    printf("                |   | \\\\\\  -  /// |   |           \n");
    printf("                | \_|  ''\\---/''  |   |           \n");
    printf("                \\  .-\\__  `-`  ___/-. /           \n");
    printf("              ___`. .'  /--.--\\  `. . __          \n");
    printf("           .\"\" '<  `.___\\_<|>_/___.'  >'\"\".       \n");
    printf("          | | :  `- `.;`\\ _ /`;.`/ - ` : | |      \n");
    printf("          \\  \\ `-.   \\_ __\\ /__ _/   .-` /  /     \n");
    printf("     ======`-.____`-.___\\_____/___.-`____.-'======\n");
    printf("                        `=---='                   \n");
    printf("     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
    wait_sec();
    wait_sec();
    wait_sec();
    wait_sec();
}



PUBLIC int login()
{
    char username[128];
    char pw[20];
    int userlen;
    int pwlen;

    printf("Login\nUser: ");
    userlen = read(0, username, 128);
    changerdtype(0);
    pwlen = read(0,pw,20);
    changerdtype(1);
    return checklogin(username, pw, userlen, pwlen);
}

PUBLIC int checklogin(char* username, char*pw, int userlen, int pwlen)
{
    char cuser[4] = "root";
    char cpw[4] = "root";
    int index = 0;
    for(index=0; index<4; index++)
    {
        if(username[index] != cuser[index] || pw[index] != cpw[index])
            return 0;
    }
    return 1;
}

/***********************************
commond:
  ps: show all process (quick shot)

************************************/

PUBLIC int kernel_commond(const char* arg[], const int argc)
{
    int ret = 0;
    if(0 == strcmp(arg[0],"ps"))
    {
        ps();
        ret = 1;
    }
    else if(0 == strcmp(arg[0],"time"))
    {
        struct time t = get_time_RTC();
        printf("%d/%d/%d %d:%d:%d\n", t.year, t.month, t.day, t.hour,  t.minute, t.second);
        ret=1;
    }
    return ret;
}

PUBLIC void ps()
{
    int i;
    char* state;

    printf("||--name--||--state--||--parent--||--priority--||--ticks--||\n");
    for(i=0; i<NR_TASKS + NR_PROCS; i++)
    {
        if(FREE_SLOT == proc_table[i].p_flags)
            continue;

        struct proc* p = &proc_table[i];
        if(0 == p->p_flags)
        {
            state = "Running\0";
        }
        else
        {
            state = "Block\0";
        }

        printf("||  %s  ||  %s  ||  %d  ||  %d  ||  %d   ||\n", p->name, state, p->p_parent, p->priority, p->ticks);
    }
}


PUBLIC void kill(const char* proc_name)
{
    int i;
    int flag = 0;
    if(0 == strcmp(proc_name, "Init") || 0 == strcmp(proc_name, "FS") || 0 == strcmp(proc_name, "MM") || 0 == strcmp(proc_name, "SYS")
       || 0 == strcmp(proc_name, "TTY") || 0 == strcmp(proc_name, "HD"))
    {
        printf("Can not kill the process\n");
        return;
    }

    for(i=0; i<NR_TASKS + NR_PROCS; i++)
    {
        if(0 == strcmp(proc_name, proc_table[i].name))
           {
               ;
           }
    }
}


