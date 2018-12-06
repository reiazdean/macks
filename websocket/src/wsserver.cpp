#ifdef OS_WIN32
#include "winsock2.h"
#include <Ws2tcpip.h>
#include "strsafe.h"
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#endif

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <iostream>
#include <stdlib.h>
#include <assert.h>

#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include "wsserver.h"
#include "p11util.h"

using std::string;

static char            cChunk[4 + WS_CHUNK_SZ];

wsServer*              wsServer::serverInstance = NULL;

/******************************************************************************************
int wsServer::sockRead(int fd, char* pcMessIn, size_t szMess)
*******************************************************************************************/
int wsServer::sockRead(int fd, char* pcMessIn, size_t szMess)
{
    int         r = -1;
#ifdef OS_WIN32
    r = recv(fd, pcMessIn, szMess, 0);
#else
    r = read(fd, pcMessIn, szMess);
#endif

    return r;
}

/******************************************************************************************
int wsServer::sockWrite(int fd, char* pcMessIn, size_t szMess)
*******************************************************************************************/
int wsServer::sockWrite(int fd, char* pcMessIn, size_t szMess)
{
    int         r = -1;
#ifdef OS_WIN32
    r = send(fd, pcMessIn, szMess, 0);
#else
    r = write(fd, pcMessIn, szMess);
#endif

    return r;
}

/******************************************************************************************
Function Name:		Constructor/Destructor.
*******************************************************************************************/
wsServer::wsServer()
{
}

wsServer::~wsServer()
{
}


/******************************************************************************************
void wsServer::serverSetup(int sslPort)
*******************************************************************************************/
void wsServer::serverSetup(int sslPort)
{
    myWsSock = openSocket(sslPort);
    if (myWsSock == 0)
    {
        return;
    }

    serverListen();
}

/******************************************************************************************
int wsServer::openSocket(int port)
*******************************************************************************************/
int wsServer::openSocket(int port)
{
    struct           sockaddr_in address;
    int              sock, i;

#ifdef OS_WIN32
    int addrLen = (int)sizeof(struct sockaddr_in);
#else
    socklen_t addrLen = (socklen_t)sizeof(struct sockaddr_in);
#endif

    sock = socket(AF_INET, SOCK_STREAM, 0);

    memset(&address.sin_addr, 0, sizeof(address.sin_addr));
#ifdef OS_WIN32
    InetPton(AF_INET, "127.0.0.1", &address.sin_addr.s_addr);
#else
    address.sin_addr.s_addr = inet_addr("127.0.0.1");//use inet_pton or InetPton instead
#endif
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    i = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&i, sizeof(i));

    if (bind(sock, (struct sockaddr*)&address, sizeof(address)) < 0)
    {
        return 0;
    }

    return sock;
}

/******************************************************************************************
void wsServer::hashAndEncode(char* pcString, int szString, string& res)
*******************************************************************************************/
void wsServer::hashAndEncode(char* pcString, int szString, string& res)
{
    uint32_t             shalen = 0;
    SHA_CTX              shactx;
    uint8_t              digest[SHA_DIGEST_LENGTH];
    uint8_t              base64[SHA_DIGEST_LENGTH * 3];

    res = "";

    if (pcString == NULL)
        return;

    memset(digest, 0, sizeof(digest));

    SHA1_Init(&shactx);
    SHA1_Update(&shactx, pcString, szString);
    SHA1_Final(digest, &shactx);

    memset(base64, 0, sizeof(base64));
    EVP_EncodeBlock(base64, digest, SHA_DIGEST_LENGTH);

    res += (char*)base64;

}

/******************************************************************************************
void wsServer::doWork(int newClientFD)

WebSocket specification
https://tools.ietf.org/html/rfc6455#section-5.1
https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers

*******************************************************************************************/
void wsServer::doWork(int newClientFD)
{
    char                       cMessIn[4096];
    uint16_t                   keyNameLen = 0;
    char*                      pcData = NULL;
    unsigned long long int     szRead = 0;
    char                       *pcWSkey = NULL;
    uint8_t*                   pResult = NULL;
    CK_ULONG                   resultLen = 0;
    int                        r = 0;

    if (newClientFD <= 0)
        return;

    memset(cMessIn, 0, sizeof(cMessIn));
    r = sockRead(newClientFD, (char*)cMessIn, sizeof(cMessIn));
    if (r <= 0)
        goto doneIO;

    pcWSkey = strstr(cMessIn, "Sec-WebSocket-Key: ");
    if (pcWSkey == NULL)
    {
        goto doneIO;
    }
    else
    {
        char*             last = NULL;
        char*             pcKey = NULL;
        string            key = "";
        string            response = "";
        string            base64 = "";

#ifdef OS_WIN32
        pcKey = strtok_s(pcWSkey, ": \r\n", &last);
        if (pcKey)
            pcKey = strtok_s(NULL, ": \r\n", &last);
#else
        pcKey = strtok_r(pcWSkey, ": \r\n", &last);
        if (pcKey)
            pcKey = strtok_r(NULL, ": \r\n", &last);
#endif

        if (pcKey == NULL)
            goto doneIO;

        key += pcKey;
        key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        hashAndEncode((char*)key.c_str(), key.size(), base64);

        response += "HTTP/1.1 101 Switching Protocols\r\n";
        response += "Upgrade: websocket\r\n";
        response += "Connection: Upgrade\r\n";
        response += "Sec-WebSocket-Accept: ";
        response += base64;
        response += "\r\n\r\n";

#ifdef _DEBUG
        printf("ws response =\n%s", response.c_str());
#endif

        if (sockWrite(newClientFD, (char*)response.c_str(), response.size()) != response.size())
            goto doneIO;
    }

    {
        uint8_t*                   pcCmdData = NULL;
        uint32_t                   cmdDataLen = 0;
        CK_RV                      rv = CKR_DEVICE_ERROR;
        char*                      pctemp = NULL;

        pResult = NULL;
        resultLen = 0;

        pcData = readFromWebSocket(newClientFD, szRead);
        if (pcData == NULL)
            goto doneIO;

        /*
        we should get more than 8 bytes
        */
        if (szRead < 8)
            goto doneIO;
        
        pctemp = pcData + 2;
        memcpy(&keyNameLen, pctemp, 2);
        pctemp = pcData + 4;
        memcpy(&cmdDataLen, pctemp, 4);
        /*
        Make sure the sizes are sane
        */
        if ((keyNameLen + cmdDataLen + 8 + 1) > szRead)
            goto doneIO;

        /*
        Make sure there is a NULL at the end of the key name ANSI string
        */
        if (pcData[8 + keyNameLen] != 0x0)
            goto doneIO;

        switch ((uint8_t)pcData[0]) {
        case crypto_ops::OP_NONE:
            free(pcData);
            goto doneIO;
        case crypto_ops::OP_EXPORT_PUB_KEY:
            rv = p11util::getPublicKey((CK_BYTE_PTR)pcData + 8, keyNameLen, resultLen, pResult);
            break;
        case crypto_ops::OP_EXPORT_CERTIFICATE:
            rv = p11util::getCertificate((CK_BYTE_PTR)pcData + 8, keyNameLen, resultLen, pResult);
            break;
        case crypto_ops::OP_SIGN:
        {
            CK_MECHANISM_TYPE          mech = 0;
            rv = CKR_OK;
            switch ((uint8_t)pcData[1]) {
            case crypto_algs::ALG_RSA_PKCS:
                mech = CKM_RSA_PKCS;
                break;
            case  crypto_algs::ALG_RSA_PKCS_SHA1:
                mech = CKM_SHA1_RSA_PKCS;
                break;
            case  crypto_algs::ALG_RSA_PKCS_SHA256:
                mech = CKM_SHA256_RSA_PKCS;
                break;
            case  crypto_algs::ALG_RSA_PKCS_SHA384:
                mech = CKM_SHA384_RSA_PKCS;
                break;
            case  crypto_algs::ALG_RSA_PKCS_SHA512:
                mech = CKM_SHA512_RSA_PKCS;
                break;
            case  crypto_algs::ALG_ECDSA:
                mech = CKM_ECDSA;
                break;
            default:
                rv = CKR_MECHANISM_INVALID;
                break;
            }

            if (rv == CKR_OK)
            {
                rv = p11util::sign((CK_BYTE_PTR)pcData + 8, keyNameLen, mech, (CK_BYTE_PTR)pcData + 8 + keyNameLen + 1, cmdDataLen, resultLen, pResult);
            }

            break;
        }
        default:
            break;
        }

        if ((rv == CKR_OK) && pResult)
        {
            uint8_t*  pTemp = (uint8_t*)calloc(resultLen + 1, 1);
            if (pTemp == NULL)
                goto doneIO;
            memcpy(pTemp + 1, pResult, resultLen);
            pTemp[0] = 0x01;//one is success
            writeToWebSocket(newClientFD, (char*)pTemp, resultLen + 1, false);
            free(pTemp);
        }
        else
        {
            char      cBuffer[128];
            memset(cBuffer, 0, sizeof(cBuffer));
#ifdef OS_WIN32
            strcpy_s(cBuffer + 1, sizeof(cBuffer) - 2, p11util::getErrorString(rv));//the first byte remains zero to indicate an error and the error string is written to the end
#else
            strcpy(cBuffer + 1, p11util::getErrorString(rv));//the first byte remains zero to indicate an error and the error string is written to the end
#endif
            writeToWebSocket(newClientFD, (char*)cBuffer, sizeof(cBuffer), false);
        }
    }

doneIO:

    if (pcData)
        free(pcData);

    if (pResult)
        free(pResult);

    closeSocket(newClientFD);

    return;
}

/******************************************************************************************
void wsServer::serverListen()
*******************************************************************************************/
void wsServer::serverListen()
{
    int                   conn;
    struct                sockaddr_in address;

#ifdef OS_WIN32
    int addrLen = (int)sizeof(struct sockaddr_in);
#else
    socklen_t addrLen = (socklen_t)sizeof(struct sockaddr_in);
#endif

    listen(myWsSock, 64);

    while (1)
    {
        conn = accept(myWsSock, (struct sockaddr*)&address, &addrLen);
        doWork(conn);
    }

    closeSocket(myWsSock);

    return;
}

/******************************************************************************************
void wsServer::closeSocket(int sock)
*******************************************************************************************/
void wsServer::closeSocket(int sock)
{
#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

/******************************************************************************************
char* wsServer::readFromWebSocket(int webSock, unsigned long long int &szRead)
*******************************************************************************************/
char* wsServer::readFromWebSocket(int webSock, unsigned long long int &szRead)
{
    bool                                    bRc = false;
    int                                     r = 0;
    char                                    c = 0;
    unsigned short                          us = 0;
    unsigned long long int                  ll = 0;
    unsigned long long int                  len = 0;
    char                                    mask[4];
    char*                                   pcData = NULL;
    unsigned long long int                  i = 0;
    bool                                    bMore = false;

    szRead = 0;

    if (sockRead(webSock, &c, sizeof(c)) != sizeof(c))
        goto doneReadData;
    c = c & 0x80;
    if (c == 0x80)
        bMore = true;

    if (sockRead(webSock, &c, sizeof(c)) != sizeof(c))
        goto doneReadData;

    c = c ^ 0x80;
    if ((unsigned int)c < 126)
    {
        len = (unsigned long long int)c;
    }
    else if ((unsigned int)c == 126)
    {
        if (sockRead(webSock, (char*)&us, sizeof(us)) != sizeof(us))
            goto doneReadData;
        len = (unsigned long long int)us;
    }
    else if ((unsigned int)c == 127)
    {
        if (sockRead(webSock, (char*)&ll, sizeof(ll)) != sizeof(ll))
            goto doneReadData;
        len = (unsigned long long int)ll;
    }
    else
        goto doneReadData;

    if (sockRead(webSock, mask, sizeof(mask)) != sizeof(mask))
        goto doneReadData;

    pcData = (char*)calloc(len + 1, 1);
    if (pcData == NULL)
        goto doneReadData;

    if (sockRead(webSock, pcData, len) != len)
        goto doneReadData;

    for (i = 0; i < len; i++)
    {
        pcData[i] = pcData[i] ^ mask[i % 4];
    }

    bRc = true;
    szRead = len;

doneReadData:

    /* 4_U_2_DO
       If there is more data to read, then recursively call
       and append the output buffer!

    if (bRc && bMore)
    {
        char*                    pcMoreData = NULL;
        unsigned long long int   szMore = 0;

        pcMoreData = readFromWebSocket( webSock, szMore);
    }
    */

    return pcData;
}

/******************************************************************************************
bool wsServer::writeToWebSocket(int webSock, char* pcData, int szData, bool isTextTransfer)
*******************************************************************************************/
bool wsServer::writeToWebSocket(int webSock, char* pcData, int szData, bool isTextTransfer)
{
    bool                        bRc = false;
    int                         iPieces = 0;
    unsigned short              usLastSz = 0;
    int                         i = 0;
    char*                       pcTemp = pcData;
    short                       usSz = htons(WS_CHUNK_SZ);

    if (pcData == NULL)
        goto doneWrite;

    iPieces = szData / WS_CHUNK_SZ;
    usLastSz = szData % WS_CHUNK_SZ;

    memset(cChunk, 0, sizeof(cChunk));
    if (isTextTransfer)
        cChunk[0] = 0x01;
    else
        cChunk[0] = 0x02;
    cChunk[1] = 0x7E;
    memcpy(cChunk + 2, &usSz, sizeof(usSz));

    for (i = 0; i < iPieces; i++)
    {
        if (i > 0)
            cChunk[0] = 0x00;

        pcTemp = pcData + i * WS_CHUNK_SZ;
        memcpy(cChunk + 4, pcTemp, WS_CHUNK_SZ);
        sockWrite(webSock, cChunk, sizeof(cChunk));
    }

    usSz = htons(usLastSz);
    if (iPieces > 0)
        cChunk[0] = 0x80;
    else
    {
        if (isTextTransfer)
            cChunk[0] = 0x81;
        else
            cChunk[0] = 0x82;
    }

    pcTemp = pcData + iPieces * WS_CHUNK_SZ;

    if (usLastSz > 125)
    {
        cChunk[1] = 0x7E;
        memcpy(cChunk + 2, &usSz, sizeof(usSz));
        memcpy(cChunk + 4, pcTemp, usLastSz);
        sockWrite(webSock, cChunk, usLastSz + 4);
    }
    else
    {
        cChunk[1] = (char)usLastSz;
        if (usLastSz > 0)
            memcpy(cChunk + 2, pcTemp, usLastSz);
        sockWrite(webSock, cChunk, usLastSz + 2);
    }

    bRc = true;

doneWrite:

    return bRc;
}



