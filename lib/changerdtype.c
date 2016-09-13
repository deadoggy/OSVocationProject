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

PUBLIC void changerdtype(int index)
{
	MESSAGE msg;
	msg.type = CHANGERD;
	msg.FD   = 1;


	if(0 == index)
    {
        msg.BUF = "Password: ";
        msg.CNT = 10;
    }
    else
    {
        msg.BUF = "   \n";
        msg.CNT = 4;
    }

	send_recv(BOTH, TASK_FS, &msg);
}
