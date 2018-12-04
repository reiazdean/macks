#pragma once
#include <stdint.h>
#include <string>


using std::string;

#define				WS_CHUNK_SZ			0x8000

typedef struct {
    int       sock;
} IOThreadArgs;


class wsServer {
    //************   Cons/Destruction   ***************
public:
    wsServer();
    virtual ~wsServer();

    //************   Class Attributes   ****************
private:
    static	wsServer*               serverInstance;
public:

    //************   Class Methods   *******************
private:
protected:
    static void                     doWork(int newClientFD);
    static void                     closeSocket(int sock);
    static int                      sockRead(int fd, char* pcMessIn, size_t szMess);
    static int                      sockWrite(int fd, char* pcMessIn, size_t szMess);
    static void                     hashAndEncode(char* pcString, int szString, string& res);
    static bool                     writeToWebSocket(int webSock, char* pcData, int szData, bool isTextTransfer);
    static char*                    readFromWebSocket(int webSock, unsigned long long int &szRead);
public:

    //************ Instance Attributes  ****************
private:
    int                             myWsSock;
public:

    //************ Instance Methods  *******************
private:
    int                             openSocket(int port);
    void                            serverListen();
public:
    void                            serverSetup(int sslPort);

};

