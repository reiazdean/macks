#ifdef OS_WIN32
#include <Windows.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "wsserver.h"
#include "p11util.h"

/*       4_U_2_DO 

This sample websocket server listens on localhost only and NO external interfaces. So,
1.  Does the traffic need to be encrypted?
2.  On multiuser system, how do we prevent an unwanted user from connecting to the service?

To satisfy 1 and 2, then don't run this as a service. Just run as a normal app to stop and start on demand.
Use a password, secretly and dynamically inputted to both this application and the JavaScript browser application.
Derive an AES key from the password and encrypt the traffic.

*/


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



