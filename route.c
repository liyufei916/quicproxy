#include "include.h"

typedef struct RouteConf {
    char * Destination;
    int DestinationLength;
    char * NextHop;
    int NextHopLength;
    struct RouteConf * Next;
} RouteConf;

static RouteConf* G_RouteConf = NULL;
static RouteConf* DefaultRouteConf = NULL;
static pthread_rwlock_t G_RouteLock;
static char* ConfigFile = "./ConfigFile";

void RouteLockInit() {
    pthread_rwlock_init(&G_RouteLock, NULL);
}

static int SetDefaultRoute(char* DefaultNextHop) {
    if (!DefaultNextHop) {
        return 0;
    }

    RouteConf* Route = (RouteConf*)calloc(1, sizeof(RouteConf));
    if (!Route) {
        goto error;
    }

    int Length = strlen(DefaultNextHop);
    Route->NextHop = (char*)calloc(1, Length);
    if (!Route->NextHop) {
        goto error1;
    }
    memcpy(Route->NextHop, DefaultNextHop, Length);
    Route->NextHopLength = Length;
    Route->Destination = NULL;
    Route->DestinationLength = 0;
    Route->Next = NULL;

    pthread_rwlock_wrlock(&G_RouteLock);
    if (DefaultRouteConf) {
        if (DefaultRouteConf->NextHop) {
            free(DefaultRouteConf->NextHop);
        }
        free(DefaultRouteConf);
    }
    DefaultRouteConf = Route;

    pthread_rwlock_unlock(&G_RouteLock);
    return 1;

error1:
    free(Route);
    Route = NULL;
error:
    WriteLog("SetDefaultRouteConf failed\n");
    return 0;
}

int GetDefaultRoute(char * NextHop, int Length) {
    pthread_rwlock_rdlock(&G_RouteLock);
    if (!DefaultRouteConf) {
        WriteLog("no default route, error\n");
        pthread_rwlock_unlock(&G_RouteLock);
        return 0;
    }

    if (Length < DefaultRouteConf->NextHopLength) {
        WriteLog("too small buffer\n");
        pthread_rwlock_unlock(&G_RouteLock);
        return 0;
    }

    memcpy(NextHop, DefaultRouteConf->NextHop, DefaultRouteConf->NextHopLength);
    pthread_rwlock_unlock(&G_RouteLock);
    return 1;
}

void RemoveRoute(char* Destination) {
    if (!Destination) {
        return;
    }

    int DestinationLength = strlen(Destination);
    int Head = 1;

    pthread_rwlock_wrlock(&G_RouteLock);
    RouteConf* p = G_RouteConf;
    RouteConf* q;
    while (p) {
        if (p->DestinationLength == DestinationLength &&
            strncmp(p->Destination, Destination, DestinationLength) == 0) {
            if (Head) {
                G_RouteConf = p->Next;
                free(p->Destination);
                free(p->NextHop);
                free(p);
                p = NULL;
            } else {
                q->Next = p->Next;
                free(p->Destination);
                free(p->NextHop);
                free(p);
                p = NULL;
            }
            pthread_rwlock_unlock(&G_RouteLock);
            return;
        }
        Head = 0;
        q = p;
        p = p->Next;
    }
    pthread_rwlock_unlock(&G_RouteLock);
}

int AddRoute(char* Destination, char* NextHop) {
    if (!Destination || !NextHop) {
        goto error;
    }

    if (!strncmp(Destination, "default", strlen("default"))) {
        return SetDefaultRoute(NextHop);
    }

    RouteConf* Route = (RouteConf*)calloc(1, sizeof(RouteConf));
    if (!Route) {
        goto error;
    }

    int DestinationLength = strlen(Destination);
    Route->Destination = (char*)calloc(1, DestinationLength);
    if (!Route->Destination) {
        goto error1;
    }
    memcpy(Route->Destination, Destination, DestinationLength);
    Route->DestinationLength = DestinationLength;

    int NextHopLength = strlen(NextHop);
    Route->NextHop = (char*)calloc(1, NextHopLength);
    if (!Route->NextHop) {
        goto error2;
    }
    memcpy(Route->NextHop, NextHop, NextHopLength);
    Route->NextHopLength = NextHopLength;

    RemoveRoute(Destination);

    pthread_rwlock_wrlock(&G_RouteLock);
    Route->Next = G_RouteConf;
    G_RouteConf = Route;
    pthread_rwlock_unlock(&G_RouteLock);

    return 1;

error2:
    free(Route->Destination);
    Route->Destination = NULL;
error1:
    free(Route);
    Route = NULL;
error:
    WriteLog("add route failed\n");
    return 0;
}

int GetRoute(char* Destination, char*NextHop, int Length) {
    if (!Destination) {
        WriteLog("empty destination\n");
        return 0;
    }

    int DestinationLength = strlen(Destination);
    pthread_rwlock_rdlock(&G_RouteLock);
    RouteConf* p = G_RouteConf;
    while (p) {
        if (p->DestinationLength == DestinationLength &&
            strncmp(p->Destination, Destination, DestinationLength) == 0) {
            if (Length < p->NextHopLength) {
                WriteLog("too small buffer\n");
                pthread_rwlock_unlock(&G_RouteLock);
                return 0;
            }

            memcpy(NextHop, p->NextHop, p->NextHopLength);
            pthread_rwlock_unlock(&G_RouteLock);
            return 1;
        }
        p = p->Next;
    }
    pthread_rwlock_unlock(&G_RouteLock);

    return GetDefaultRoute(NextHop, Length);
}

void ShowRoutes() {
    if (DefaultRouteConf) {
        printf("##################################\n");
        printf("Defalut Next Hop: %s\n", DefaultRouteConf->NextHop);
    }

    printf("##################################\n");
    printf("Route Table: \n");
    RouteConf* p = G_RouteConf;
    while (p) {
        printf("%s     %s\n", p->Destination, p->NextHop);
        p = p->Next;
    }
    printf("##################################\n");
}

void DumpRoutes() {
    FILE *Fp;
    if ((Fp = fopen(ConfigFile, "w+")) == NULL) {
        WriteLog("open config file failed\n");
        return;
    }

    pthread_rwlock_rdlock(&G_RouteLock);
    if (DefaultRouteConf) {
        fprintf(Fp, "default\t%s\n", DefaultRouteConf->NextHop);
    }
    RouteConf* p = G_RouteConf;
    while (p) {
        fprintf(Fp, "%s\t%s\n", p->Destination, p->NextHop);
        p = p->Next;
    }
    pthread_rwlock_unlock(&G_RouteLock);

    fclose(Fp);
}

int LoadRoutes() {
    char Buffer[MAX_TARGET_LENGTH * 2] = {0};
    FILE *Fp;
    if ((Fp = fopen(ConfigFile, "r")) == NULL) {
        WriteLog("open config file failed\n");
        return 1;
    }

    int LineLength = 0;
    char* Destination = NULL;
    char* NextHop = NULL;
    while (fgets(Buffer, MAX_TARGET_LENGTH * 2, Fp) != NULL) {
        LineLength = strlen(Buffer);
        Buffer[LineLength - 1] = '\0';

        int i = 0;
        while (i < LineLength && isspace(Buffer[i])) {
            i++;
        }
        if (i >= LineLength) {
            WriteLog("invalid route config\n");
            return 0;
        }

        Destination = Buffer + i;
        while (i < LineLength && !isspace(Buffer[i])) {
            i++;
        }
        if (i >= LineLength) {
            WriteLog("invalid route config\n");
            return 0;
        }
        int DestinationLength = i - (Destination - Buffer);
        Buffer[i] = '\0';
        i++;

        while (i < LineLength && isspace(Buffer[i])) {
            i++;
        }
        if (i >= LineLength) {
            WriteLog("invalid route config\n");
            return 0;
        }
        NextHop = Buffer + i;

        if (DestinationLength == 7 && strncmp(Destination, "default", 7) == 0) {
            if (!SetDefaultRoute(NextHop)) {
                return 0;
            }
        } else {
            if (!AddRoute(Destination, NextHop)) {
                return 0;
            }
        }
        WriteLog("Destination: %s, NextHop:%s\n", Destination, NextHop);
    }

    fclose(Fp);
    return 1;
}
