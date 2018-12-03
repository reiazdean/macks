#ifdef OS_WIN32
#include <Windows.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "wsserver.h"
#include "p11util.h"


int main(int argc, char * argv[])
{
    int				retCode = -1;
	wsServer        ws;
    
#ifdef OS_WIN32
    WSADATA     WSAData = { 0 };

    WSAStartup(MAKEWORD(2, 2), &WSAData);
#endif

    p11util::initialize();
	
	ws.serverSetup(1990);

    return 0;
}



