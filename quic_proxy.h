#ifndef _QUIC_PROXY_H
#define _QUIC_PROXY_H

#include "include.h"
#include "msquic.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

typedef struct QUIC_CHAINNODE {
    char * Buffer;
    int Length;
    struct QUIC_CHAINNODE *Next;
} QUIC_CHAINNODE;

typedef struct QUIC_PROXY_CONTEXT {
    HQUIC UpstreamConnection;
    HQUIC UpstreamStream;
    HQUIC DownstreamConnection;
    HQUIC DownstreamStream;
    BOOLEAN TargetParsed;
    BOOLEAN UpstreamConnected;
    BOOLEAN DownstreamFinished;
    char Target[MAX_TARGET_LENGTH];
    char ParsedData[MAX_HEADER_LENGTH];
    uint16_t ParsedLength;
    QUIC_CHAINNODE * Data;
    pthread_rwlock_t DataLock;
    void *Worker;
} QUIC_PROXY_CONTEXT;

typedef enum QUIC_HANDLE_TYPE {
    QUIC_HANDLE_TYPE_REGISTRATION,
    QUIC_HANDLE_TYPE_CONFIGURATION,
    QUIC_HANDLE_TYPE_LISTENER,
    QUIC_HANDLE_TYPE_CONNECTION_CLIENT,
    QUIC_HANDLE_TYPE_CONNECTION_SERVER,
    QUIC_HANDLE_TYPE_STREAM
} QUIC_HANDLE_TYPE;

typedef struct CXPLAT_LIST_ENTRY {
    struct CXPLAT_LIST_ENTRY* Flink;
    struct CXPLAT_LIST_ENTRY* Blink;
} CXPLAT_LIST_ENTRY;

typedef struct QUIC_CONNECTION {
    QUIC_HANDLE_TYPE Type;
    void* ClientContext;
    CXPLAT_LIST_ENTRY RegistrationLink;
    CXPLAT_LIST_ENTRY WorkerLink;
    CXPLAT_LIST_ENTRY TimerLink;
    void* Worker;
} QUIC_CONNECTION;

#endif
