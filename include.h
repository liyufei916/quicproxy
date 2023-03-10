#define _GNU_SOURCE
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>

#define MAX_TARGET_LENGTH 128
#define MAX_HEADER_LENGTH 4096
#define WriteLog(fmt, args...) InternalWriteLog(fmt, __FILE__, __FUNCTION__, ##args)

typedef struct QUIC_HANDLE* HQUIC;


void RouteLockInit();

int GetDefaultRoute(char * NextHop, int Length);

void RemoveRoute(char* Destination);

int AddRoute(char* Destination, char* NextHop);

int GetRoute(char* Destination, char*NextHop, int Length);

void ShowRoutes();

void DumpRoutes();

int LoadRoutes();


void ConnectionPoolLockInit();

int SetConnection(void* Worker, HQUIC Connection, char* Target);

HQUIC GetConnection(void* Worker, char* Target);

void RemoveConnection(void* Worker, HQUIC Connection);

void ShowConnectionPool();


int LogInit();


void HttpMain();
