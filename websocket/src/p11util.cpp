#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include "p11util.h"

CK_FUNCTION_LIST*            p11util::p11Functions = NULL;
#ifdef OS_WIN32
HINSTANCE                    p11util::libHandle = NULL;
#else
void*                        p11util::libHandle = 0;
#endif

CK_BBOOL p11util::initialize()
{
    return loadP11Functions();
}

CK_BBOOL p11util::loadP11Functions()
{
    CK_BBOOL                        myRC = CK_FALSE;
    CK_C_GetFunctionList            C_GetFunctionList = NULL;
    CK_RV                           rv = CKR_TOKEN_NOT_PRESENT;

#ifdef OS_WIN32
    libHandle = LoadLibrary(LIB_NAME);
    if (libHandle)
    {
        C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(libHandle, "C_GetFunctionList");
    }
#else
    libHandle = dlopen(LIB_NAME, RTLD_NOW);
    if (libHandle)
    {
        C_GetFunctionList = (CK_C_GetFunctionList)dlsym(libHandle, "C_GetFunctionList");
    }
#endif

    if (!libHandle)
    {
        return CK_FALSE;
    }

    if (C_GetFunctionList)
    {
        rv = C_GetFunctionList(&p11Functions);
    }

    if (p11Functions)
    {
        rv = p11Functions->C_Initialize(NULL_PTR);
    }

    if (rv == CKR_OK)
    {
        myRC = CK_TRUE;
    }

    return myRC;
}

/*
    FUNCTION:		CK_RV GenerateRSAKeyPair( CK_SESSION_HANDLE hSession )
*/
CK_RV
p11util::getObjectAttribute(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ULONG ckAttribute,
    CK_BYTE* pByte,
    CK_ULONG& ulSize)
{
    CK_RV              retCode = CKR_TOKEN_NOT_PRESENT;
    CK_ATTRIBUTE       attrib;

    if (p11Functions == NULL)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    attrib.type = ckAttribute;
    attrib.pValue = NULL;
    attrib.ulValueLen = 0;

    retCode = p11Functions->C_GetAttributeValue(hSession, hObject, &attrib, 1);
    if (retCode != CKR_OK)
        goto doneGetAttrib;

    if (pByte == NULL)
    {
        ulSize = attrib.ulValueLen;
        return retCode;
    }

    if (ulSize < attrib.ulValueLen)
    {
        return CKR_BUFFER_TOO_SMALL;
    }

    attrib.pValue = pByte;
    retCode = p11Functions->C_GetAttributeValue(hSession, hObject, &attrib, 1);
    if (retCode != CKR_OK)
        goto doneGetAttrib;

    ulSize = attrib.ulValueLen;

doneGetAttrib:

    return retCode;
}

CK_RV
p11util::findObject(
    CK_SESSION_HANDLE hSession,
    CK_ULONG ckClass,
    CK_BYTE_PTR pLabel,
    CK_ULONG ulLabLen,
    CK_OBJECT_HANDLE &hObj)
{
    CK_RV                rv = CKR_TOKEN_NOT_PRESENT;
    CK_OBJECT_HANDLE     handles[NUM_HANDLES];
    CK_ULONG             numObjs = NUM_HANDLES;
    CK_ATTRIBUTE         attrib;

    hObj = 0;

    if (p11Functions == NULL)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pLabel == NULL)
        return CKR_DATA_INVALID;

    attrib.type = CKA_CLASS;
    attrib.pValue = (CK_VOID_PTR)&ckClass;
    attrib.ulValueLen = sizeof(CK_ULONG);

    rv = p11Functions->C_FindObjectsInit(hSession, &attrib, 1);
    if (rv != CKR_OK)
        goto done;

    rv = p11Functions->C_FindObjects(hSession, handles, NUM_HANDLES, &numObjs);
    if (rv != CKR_OK)
        goto done;

    for (CK_ULONG i = 0; i < numObjs; i++)
    {
        CK_BYTE*       pByte = NULL;
        CK_ULONG       ulSize = 0;

        rv = getObjectAttribute(hSession, handles[i], CKA_LABEL, NULL, ulSize);
        if (rv != CKR_OK)
            goto done;

        pByte = (CK_BYTE_PTR)calloc(ulSize, 1);
        if (pByte == NULL)
        {
            rv = CKR_DEVICE_ERROR;
            goto done;
        }

        rv = getObjectAttribute(hSession, handles[i], CKA_LABEL, pByte, ulSize);
        if (rv != CKR_OK)
        {
            free(pByte);
            goto done;
        }

        if (strcmp((char*)pLabel, (char*)pByte) == 0)
            hObj = handles[i];

        free(pByte);

        if (hObj != 0)
            break;
    }

done:

    return rv;
}

CK_RV
p11util::getCertificate(
    CK_BYTE_PTR pLabel,
    CK_ULONG ulLabLen,
    CK_ULONG &ulCertLen,
    CK_BYTE_PTR &pByte)
{
    CK_RV                     rv = CKR_TOKEN_NOT_PRESENT;
    CK_OBJECT_HANDLE          hObj = 0;
    CK_SESSION_HANDLE         hSession = 0;
    CK_ULONG                  ulSize = 0;

    if (p11Functions == NULL)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pLabel == NULL)
        return CKR_DATA_INVALID;

    rv = p11Functions->C_OpenSession(1, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK)
        goto done;

    rv = findObject(hSession, CKO_CERTIFICATE, pLabel, ulLabLen, hObj);
    if (rv != CKR_OK)
        goto done;

    if (hObj == 0)
    {
        rv = CKR_OBJECT_HANDLE_INVALID;
        goto done;
    }

    rv = p11util::getObjectAttribute(hSession, hObj, CKA_VALUE, NULL, ulSize);
    if (rv != CKR_OK)
        goto done;

    pByte = (CK_BYTE_PTR)calloc(ulSize, 1);
    if (pByte == NULL)
    {
        rv = CKR_DEVICE_MEMORY;
        goto done;
    }

    rv = p11util::getObjectAttribute(hSession, hObj, CKA_VALUE, pByte, ulSize);
    if (rv != CKR_OK)
    {
        free(pByte);
        pByte = NULL;
        goto done;
    }

    ulCertLen = ulSize;

done:

    if (hSession)
        p11Functions->C_CloseSession(hSession);

    if ((rv == CKR_DEVICE_ERROR) || (rv == CKR_DEVICE_MEMORY))
    {
        p11Functions->C_Finalize(NULL);
        p11Functions->C_Initialize(NULL_PTR);
    }

    return rv;
}

CK_RV
p11util::getPublicKey(
    CK_BYTE_PTR pLabel,
    CK_ULONG ulLabLen,
    CK_ULONG &ulPubLen,
    CK_BYTE_PTR &pbPubKey)
{
    CK_RV                     rv = CKR_TOKEN_NOT_PRESENT;
    int                       iSize = 0;
    CK_BYTE_PTR               pbCert = NULL;
    CK_ULONG                  ulCertSize = 0;
    X509*                     x509cert = NULL;
    EVP_PKEY*                 pk = NULL;

    pbPubKey = NULL;

    rv = getCertificate(pLabel, ulLabLen, ulCertSize, pbCert);
    if (rv != CKR_OK)
        goto done;

    if (pbCert == NULL)
    {
        rv = CKR_DEVICE_MEMORY;
        goto done;
    }

    x509cert = d2i_X509(NULL, (const unsigned char**)&pbCert, ulCertSize);
    if (x509cert == NULL)
    {
        rv = CKR_DEVICE_MEMORY;
        goto done;
    }

    pk = X509_get_pubkey(x509cert);
    if (pk == NULL)
    {
        rv = CKR_DEVICE_MEMORY;
        goto done;
    }

    //https://www.openssl.org/docs/man1.1.0/crypto/d2i_X509.html
    iSize = i2d_PUBKEY(pk, &pbPubKey);
    if (iSize <= 0)
    {
        if (pbPubKey)
        {
            free(pbPubKey);
            pbPubKey = NULL;
        }
        rv = CKR_DEVICE_MEMORY;
        goto done;
    }

    if (pbPubKey == NULL)
    {
        rv = CKR_DEVICE_MEMORY;
        goto done;
    }

    ulPubLen = iSize;

done:

    if (pk)
        EVP_PKEY_free(pk);

    if (x509cert)
        X509_free(x509cert);

    return rv;
}

CK_RV
p11util::sign(
    CK_BYTE_PTR pLabel,
    CK_ULONG ulLabLen,
    CK_MECHANISM_TYPE mechtype,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_ULONG &ulSigLen,
    CK_BYTE_PTR &pSigByte)
{
    CK_RV                     rv = CKR_TOKEN_NOT_PRESENT;
    CK_OBJECT_HANDLE          hObj = 0;
    CK_SESSION_HANDLE         hSession = 0;
    CK_MECHANISM              mech;

    pSigByte = NULL;

    if (p11Functions == NULL)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pLabel == NULL)
        return CKR_DATA_INVALID;

    mech.mechanism = mechtype;// CKM_SHA256_RSA_PKCS;//CKM_SHA1_RSA_PKCS;//CKM_ECDSA
    mech.pParameter = (void*)NULL;
    mech.ulParameterLen = 0;

    rv = p11Functions->C_OpenSession(1, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK)
        goto done;

    rv = findObject(hSession, CKO_PRIVATE_KEY, pLabel, ulLabLen, hObj);
    if (rv != CKR_OK)
        goto done;

    if (hObj == 0)
    {
        rv = CKR_OBJECT_HANDLE_INVALID;
        goto done;
    }

    rv = p11Functions->C_SignInit(hSession, &mech, hObj);
    if (rv != CKR_OK)
        goto done;

    ulSigLen = 0;
    rv = p11Functions->C_Sign(hSession, pData, ulDataLen, NULL, &ulSigLen);
    if (rv != CKR_OK)
        goto done;

    pSigByte = (CK_BYTE_PTR)calloc(ulSigLen, 1);
    if (pSigByte == NULL)
    {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    rv = p11Functions->C_Sign(hSession, pData, ulDataLen, pSigByte, &ulSigLen);
    if (rv != CKR_OK)
        goto done;

done:

    if (hSession)
        p11Functions->C_CloseSession(hSession);

    if ((rv == CKR_DEVICE_ERROR) || (rv == CKR_DEVICE_MEMORY))
    {
        p11Functions->C_Finalize(NULL);
        p11Functions->C_Initialize(NULL_PTR);
    }

    return rv;
}

char* p11util::getErrorString(
    CK_RV rv)
{
    switch (rv) {
    case CKR_OK:
        return (char*)"CKR_OK";
    case CKR_CANCEL:
        return (char*)"CKR_CANCEL";
    case CKR_HOST_MEMORY:
        return (char*)"CKR_HOST_MEMORY";
    case CKR_SLOT_ID_INVALID:
        return (char*)"CKR_SLOT_ID_INVALID";
    case CKR_GENERAL_ERROR:
        return (char*)"CKR_GENERAL_ERROR";
    case CKR_FUNCTION_FAILED:
        return (char*)"CKR_FUNCTION_FAILED";
    case CKR_ARGUMENTS_BAD:
        return (char*)"CKR_ARGUMENTS_BAD";
    case CKR_NO_EVENT:
        return (char*)"CKR_NO_EVENT";
    case CKR_NEED_TO_CREATE_THREADS:
        return (char*)"CKR_NEED_TO_CREATE_THREADS";
    case CKR_CANT_LOCK:
        return (char*)"CKR_CANT_LOCK";
    case CKR_ATTRIBUTE_READ_ONLY:
        return (char*)"CKR_ATTRIBUTE_READ_ONLY";
    case CKR_ATTRIBUTE_SENSITIVE:
        return (char*)"CKR_ATTRIBUTE_SENSITIVE";
    case CKR_ATTRIBUTE_TYPE_INVALID:
        return (char*)"CKR_ATTRIBUTE_TYPE_INVALID";
    case CKR_ATTRIBUTE_VALUE_INVALID:
        return (char*)"CKR_ATTRIBUTE_VALUE_INVALID";
    case CKR_DATA_INVALID:
        return (char*)"CKR_DATA_INVALID";
    case CKR_DATA_LEN_RANGE:
        return (char*)"CKR_DATA_LEN_RANGE";
    case CKR_DEVICE_ERROR:
        return (char*)"CKR_DEVICE_ERROR";
    case CKR_DEVICE_MEMORY:
        return (char*)"CKR_DEVICE_MEMORY";
    case CKR_DEVICE_REMOVED:
        return (char*)"CKR_DEVICE_REMOVED";
    case CKR_ENCRYPTED_DATA_INVALID:
        return (char*)"CKR_ENCRYPTED_DATA_INVALID";
    case CKR_ENCRYPTED_DATA_LEN_RANGE:
        return (char*)"CKR_ENCRYPTED_DATA_LEN_RANGE";
    case CKR_FUNCTION_CANCELED:
        return (char*)"CKR_FUNCTION_CANCELED";
    case CKR_FUNCTION_NOT_PARALLEL:
        return (char*)"CKR_FUNCTION_NOT_PARALLEL";
    case CKR_FUNCTION_NOT_SUPPORTED:
        return (char*)"CKR_FUNCTION_NOT_SUPPORTED";
    case CKR_KEY_HANDLE_INVALID:
        return (char*)"CKR_KEY_HANDLE_INVALID";
    case CKR_KEY_SIZE_RANGE:
        return (char*)"CKR_KEY_SIZE_RANGE";
    case CKR_KEY_TYPE_INCONSISTENT:
        return (char*)"CKR_KEY_TYPE_INCONSISTENT";
    case CKR_KEY_NOT_NEEDED:
        return (char*)"CKR_KEY_NOT_NEEDED";
    case CKR_KEY_CHANGED:
        return (char*)"CKR_KEY_CHANGED";
    case CKR_KEY_NEEDED:
        return (char*)"CKR_KEY_NEEDED";
    case CKR_KEY_INDIGESTIBLE:
        return (char*)"CKR_KEY_INDIGESTIBLE";
    case CKR_KEY_FUNCTION_NOT_PERMITTED:
        return (char*)"CKR_KEY_FUNCTION_NOT_PERMITTED";
    case CKR_KEY_NOT_WRAPPABLE:
        return (char*)"CKR_KEY_NOT_WRAPPABLE";
    case CKR_KEY_UNEXTRACTABLE:
        return (char*)"CKR_KEY_UNEXTRACTABLE";
    case CKR_MECHANISM_INVALID:
        return (char*)"CKR_MECHANISM_INVALID";
    case CKR_MECHANISM_PARAM_INVALID:
        return (char*)"CKR_MECHANISM_PARAM_INVALID";
    case CKR_OBJECT_HANDLE_INVALID:
        return (char*)"CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_ACTIVE:
        return (char*)"CKR_OPERATION_ACTIVE";
    case CKR_OPERATION_NOT_INITIALIZED:
        return (char*)"CKR_OPERATION_NOT_INITIALIZED";
    case CKR_PIN_INCORRECT:
        return (char*)"CKR_PIN_INCORRECT";
    case CKR_PIN_INVALID:
        return (char*)"CKR_PIN_INVALID";
    case CKR_PIN_LEN_RANGE:
        return (char*)"CKR_PIN_LEN_RANGE";
    case CKR_PIN_EXPIRED:
        return (char*)"CKR_PIN_EXPIRED";
    case CKR_PIN_LOCKED:
        return (char*)"CKR_PIN_LOCKED";
    case CKR_SESSION_CLOSED:
        return (char*)"CKR_SESSION_CLOSED";
    case CKR_SESSION_COUNT:
        return (char*)"CKR_SESSION_COUNT";
    case CKR_SESSION_HANDLE_INVALID:
        return (char*)"CKR_SESSION_HANDLE_INVALID";
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
        return (char*)"CKR_SESSION_PARALLEL_NOT_SUPPORTED";
    case CKR_SESSION_READ_ONLY:
        return (char*)"CKR_SESSION_READ_ONLY";
    case CKR_SESSION_EXISTS:
        return (char*)"CKR_SESSION_EXISTS";
    case CKR_SESSION_READ_ONLY_EXISTS:
        return (char*)"CKR_SESSION_READ_ONLY_EXISTS";
    case CKR_SESSION_READ_WRITE_SO_EXISTS:
        return (char*)"CKR_SESSION_READ_WRITE_SO_EXISTS";
    case CKR_SIGNATURE_INVALID:
        return (char*)"CKR_SIGNATURE_INVALID";
    case CKR_SIGNATURE_LEN_RANGE:
        return (char*)"CKR_SIGNATURE_LEN_RANGE";
    case CKR_TEMPLATE_INCOMPLETE:
        return (char*)"CKR_TEMPLATE_INCOMPLETE";
    case CKR_TEMPLATE_INCONSISTENT:
        return (char*)"CKR_TEMPLATE_INCONSISTENT";
    case CKR_TOKEN_NOT_PRESENT:
        return (char*)"CKR_TOKEN_NOT_PRESENT";
    case CKR_TOKEN_NOT_RECOGNIZED:
        return (char*)"CKR_TOKEN_NOT_RECOGNIZED";
    case CKR_TOKEN_WRITE_PROTECTED:
        return (char*)"CKR_TOKEN_WRITE_PROTECTED";
    case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
        return (char*)"CKR_UNWRAPPING_KEY_HANDLE_INVALID";
    case CKR_UNWRAPPING_KEY_SIZE_RANGE:
        return (char*)"CKR_UNWRAPPING_KEY_SIZE_RANGE";
    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
        return (char*)"CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_USER_ALREADY_LOGGED_IN:
        return (char*)"CKR_USER_ALREADY_LOGGED_IN";
    case CKR_USER_NOT_LOGGED_IN:
        return (char*)"CKR_USER_NOT_LOGGED_IN";
    case CKR_USER_PIN_NOT_INITIALIZED:
        return (char*)"CKR_USER_PIN_NOT_INITIALIZED";
    case CKR_USER_TYPE_INVALID:
        return (char*)"CKR_USER_TYPE_INVALID";
    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
        return (char*)"CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
    case CKR_USER_TOO_MANY_TYPES:
        return (char*)"CKR_USER_TOO_MANY_TYPES";
    case CKR_WRAPPED_KEY_INVALID:
        return (char*)"CKR_WRAPPED_KEY_INVALID";
    case CKR_WRAPPED_KEY_LEN_RANGE:
        return (char*)"CKR_WRAPPED_KEY_LEN_RANGE";
    case CKR_WRAPPING_KEY_HANDLE_INVALID:
        return (char*)"CKR_WRAPPING_KEY_HANDLE_INVALID";
    case CKR_WRAPPING_KEY_SIZE_RANGE:
        return (char*)"CKR_WRAPPING_KEY_SIZE_RANGE";
    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
        return (char*)"CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_RANDOM_SEED_NOT_SUPPORTED:
        return (char*)"CKR_RANDOM_SEED_NOT_SUPPORTED";
    case CKR_RANDOM_NO_RNG:
        return (char*)"CKR_RANDOM_NO_RNG";
    case CKR_DOMAIN_PARAMS_INVALID:
        return (char*)"CKR_DOMAIN_PARAMS_INVALID";
    case CKR_BUFFER_TOO_SMALL:
        return (char*)"CKR_BUFFER_TOO_SMALL";
    case CKR_SAVED_STATE_INVALID:
        return (char*)"CKR_SAVED_STATE_INVALID";
    case CKR_INFORMATION_SENSITIVE:
        return (char*)"CKR_INFORMATION_SENSITIVE";
    case CKR_STATE_UNSAVEABLE:
        return (char*)"CKR_STATE_UNSAVEABLE";
    case CKR_CRYPTOKI_NOT_INITIALIZED:
        return (char*)"CKR_CRYPTOKI_NOT_INITIALIZED";
    case CKR_CRYPTOKI_ALREADY_INITIALIZED:
        return (char*)"CKR_CRYPTOKI_ALREADY_INITIALIZED";
    case CKR_MUTEX_BAD:
        return (char*)"CKR_MUTEX_BAD";
    case CKR_MUTEX_NOT_LOCKED:
        return (char*)"CKR_MUTEX_NOT_LOCKED";
    case CKR_NEW_PIN_MODE:
        return (char*)"CKR_NEW_PIN_MODE";
    case CKR_NEXT_OTP:
        return (char*)"CKR_NEXT_OTP";
    case CKR_FUNCTION_REJECTED:
        return (char*)"CKR_FUNCTION_REJECTED";
    case CKR_VENDOR_DEFINED:
        return (char*)"CKR_VENDOR_DEFINED";
    default:
        return (char*)"CKR_UNKNOWN";
    }
}
