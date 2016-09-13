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

PUBLIC int inittrans()
{
    MESSAGE msg;
	msg.type = INITTRANS;
	msg.FD   = 1;
	msg.BUF  = "Welcome!\n";
	msg.CNT  = 9;

	send_recv(BOTH, TASK_FS, &msg);

	return msg.CNT;
}
