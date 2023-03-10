#include "include.h"

typedef struct CONNECTION_LINK {
    char Target[MAX_TARGET_LENGTH];
    HQUIC Connection;
    struct CONNECTION_LINK* Next;
} CONNECTION_LINK;

typedef struct CONNECTION_POOL {
    void* Worker;
    CONNECTION_LINK* Link;
    pthread_rwlock_t ConnectionLinkLock;
    struct CONNECTION_POOL* Next;
} CONNECTION_POOL;

static CONNECTION_POOL* G_ConnectionPool = NULL;
static pthread_rwlock_t G_ConnectionPoolLock;

void ConnectionPoolLockInit() {
    pthread_rwlock_init(&G_ConnectionPoolLock, NULL);
}

int SetConnection(void* Worker, HQUIC Connection, char* Target)
{
    if (!Worker || !Connection) {
        WriteLog("invalid pointer, Worker: %p, Connection: %p\n", Worker, Connection);
        return 0;
    }

    pthread_rwlock_wrlock(&G_ConnectionPoolLock);
    CONNECTION_POOL* p = G_ConnectionPool;
    while (p) {
        if (p->Worker == Worker) {
            CONNECTION_LINK* NewLink = (CONNECTION_LINK*)calloc(1, sizeof(CONNECTION_LINK));
            if (!NewLink) {
                WriteLog("alloc failed\n");
                pthread_rwlock_unlock(&G_ConnectionPoolLock);
                return 0;
            }

            memcpy(NewLink->Target, Target, strlen(Target));
            NewLink->Connection = Connection;

            pthread_rwlock_wrlock(&p->ConnectionLinkLock);
            NewLink->Next = p->Link;
            p->Link = NewLink;
            pthread_rwlock_unlock(&p->ConnectionLinkLock);

            pthread_rwlock_unlock(&G_ConnectionPoolLock);
            return 1;
        }
        p = p->Next;
    }

    CONNECTION_POOL* NewPool = (CONNECTION_POOL*)calloc(1, sizeof(CONNECTION_POOL));
    if (!NewPool) {
        WriteLog("alloc failed\n");
        pthread_rwlock_unlock(&G_ConnectionPoolLock);
        return 0;
    }
    CONNECTION_LINK* NewLink = (CONNECTION_LINK*)calloc(1, sizeof(CONNECTION_LINK));
    if (!NewLink) {
        WriteLog("alloc failed\n");
        pthread_rwlock_unlock(&G_ConnectionPoolLock);
        return 0;
    }

    memcpy(NewLink->Target, Target, strlen(Target));
    NewLink->Connection = Connection;
    NewLink->Next = NULL;

    NewPool->Worker = Worker;
    NewPool->Link = NewLink;
    pthread_rwlock_init(&NewPool->ConnectionLinkLock, NULL);

    NewPool->Next = G_ConnectionPool;
    G_ConnectionPool = NewPool;
    pthread_rwlock_unlock(&G_ConnectionPoolLock);

    return 1;
}

HQUIC GetConnection(void* Worker, char* Target)
{
    if (!Worker) {
        WriteLog("empty Worker\n");
        return NULL;
    }

    pthread_rwlock_rdlock(&G_ConnectionPoolLock);
    CONNECTION_POOL* p = G_ConnectionPool;
    while (p) {
        if (p->Worker == Worker) {
            pthread_rwlock_unlock(&G_ConnectionPoolLock);

            pthread_rwlock_rdlock(&p->ConnectionLinkLock);
            CONNECTION_LINK* q = p->Link;
            while (q) {
                if (strlen(q->Target) == strlen(Target) && strncmp(q->Target, Target, strlen(Target)) == 0) {
                    pthread_rwlock_unlock(&p->ConnectionLinkLock);
                    return q->Connection;
                }
                q = q->Next;
            }
            pthread_rwlock_unlock(&p->ConnectionLinkLock);
            return NULL;
        }
        p = p->Next;
    }

    pthread_rwlock_unlock(&G_ConnectionPoolLock);
    return NULL;
}

void RemoveConnection(void* Worker, HQUIC Connection)
{
    WriteLog("remove link, worker:%p, Connection:%p\n", Worker, Connection);
    if (!Worker) {
        WriteLog("empty Worker\n");
        return;
    }

    pthread_rwlock_rdlock(&G_ConnectionPoolLock);
    CONNECTION_POOL* p = G_ConnectionPool;
    while (p) {
        if (p->Worker == Worker) {
            pthread_rwlock_unlock(&G_ConnectionPoolLock);

            pthread_rwlock_wrlock(&p->ConnectionLinkLock);
            CONNECTION_LINK *q = p->Link;
            CONNECTION_LINK *l;
            int Head = 1;
            while (q) {
                if (q->Connection == Connection) {
                    if (Head) {
                        p->Link = q->Next;
                        free(q);
                        q = NULL;
                    } else {
                        l->Next = q->Next;
                        free(q);
                        q = NULL;
                    }
                    pthread_rwlock_unlock(&p->ConnectionLinkLock);
                    return;
                }
                Head = 0;
                l = q;
                q = q->Next;
            }
            pthread_rwlock_unlock(&p->ConnectionLinkLock);
            return;
        }
        p = p->Next;
    }
    pthread_rwlock_unlock(&G_ConnectionPoolLock);
}

void ShowConnectionPool() {
    printf("#####################\n");
    printf("   CONNECTION POOL   \n");
    printf("#####################\n");
    CONNECTION_POOL* p = G_ConnectionPool;
    while (p) {
        printf("Worker: %p\n", p->Worker);
        printf("=====================\n");
        CONNECTION_LINK *q = p->Link;
        while (q) {
            printf("Target: %s\n", q->Target);
            printf("Connection: %p\n", q->Connection);
            q = q->Next;
            printf("=====================\n");
        }
        p = p->Next;
        printf("#####################\n");
    }
}
