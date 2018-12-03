#pragma once
#include <stdint.h>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <string>


using std::string;
using std::vector;
using std::map;
using std::thread;
using std::mutex;
using std::condition_variable;
using std::function;

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
	static	mutex                   myMutex;
public:
	static	bool                    Stopped;
	
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
	bool                            stopServer;
public:
	
//************ Instance Methods  *******************
private:
	int                             openSocket( int port );
	void                            serverListen( );
public:
	void                            serverSetup( int sslPort );
	
};

