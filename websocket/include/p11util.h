#pragma once
#ifdef OS_WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <pthread.h>
#endif
#include "cryptoki.h"

#ifdef OS_WIN32
#define           LIB_NAME         "C:\\Program Files\\Macks\\MacksP11.dll"
#else
#define           LIB_NAME         "/opt/rdc/macks/libmackspkcs11.so"
#endif

#define           NUM_HANDLES          100


//*************************************************
//
//CLASS p11util
//
//*************************************************
class p11util {
    //************   Cons/Destruction   ***********
private:
    p11util() {};
public:
    virtual ~p11util() {};
    //************ Instance Attributes  ****************
private:
    static        CK_FUNCTION_LIST*            p11Functions;
#ifdef OS_WIN32
    static        HINSTANCE                    libHandle;
#else
    static        void*                        libHandle;
#endif
protected:
    static        CK_BBOOL                     loadP11Functions();

private:
    static        CK_RV                        findObject(
                                                          CK_SESSION_HANDLE hSession,
                                                          CK_ULONG ckClass,
                                                          CK_BYTE_PTR pLabel,
                                                          CK_ULONG ulLabLen,
                                                          CK_OBJECT_HANDLE &hObj);

    static       CK_RV                         getObjectAttribute(
                                                          CK_SESSION_HANDLE hSession,
                                                          CK_OBJECT_HANDLE hObject,
                                                          CK_ULONG ckAttribute,
                                                          CK_BYTE* pByte,
                                                          CK_ULONG& ulSize);

public:
    static       CK_BBOOL                      initialize();
    static       char*                         getErrorString(CK_RV rv);
    static       CK_RV                         getCertificate(
                                                          CK_BYTE_PTR pLabel,
                                                          CK_ULONG ulLabLen,
                                                          CK_ULONG &ulCertLen,
                                                          CK_BYTE_PTR &pByte);

    static       CK_RV                         getPublicKey(
                                                          CK_BYTE_PTR pLabel,
                                                          CK_ULONG ulLabLen,
                                                          CK_ULONG &ulPubLen,
                                                          CK_BYTE_PTR &pByte);

    static       CK_RV                         sign(
                                                  CK_BYTE_PTR pLabel,
                                                  CK_ULONG ulLabLen,
                                                  CK_MECHANISM_TYPE mechtype,
                                                  CK_BYTE_PTR pData,
                                                  CK_ULONG ulDataLen,
                                                  CK_ULONG &ulSigLen,
                                                  CK_BYTE_PTR &pByte);


};

