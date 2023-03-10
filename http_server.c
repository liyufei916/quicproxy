#include "include.h"

int ProcessRequest(char* Buffer, int Length) {
    char* RequestLineEnd = (char*)memmem(Buffer, Length, "\r\n", 2);
    if (!RequestLineEnd) {
        WriteLog("too long request line\n");
        return 0;
    }
    int RequestLineLength = RequestLineEnd - Buffer;

    int i = 0;
    while (i < RequestLineLength && isspace(Buffer[i])) {
        i++;
    }
    if (i >= RequestLineLength) {
        WriteLog("invalid request line\n");
        return 0;
    }

    const char* MethodStart = Buffer + i;
    while (i < RequestLineLength && !isspace(Buffer[i])) {
        i++;
    }
    if (i >= RequestLineLength) {
        WriteLog("invalid request line\n");
        return 0;
    }
    int MethodLength = i - (MethodStart - Buffer);
    if (MethodLength != 3 || strncmp(MethodStart, "GET", 3)) {
        WriteLog("invalid request method\n");
        return 0;
    }

    while (i < RequestLineLength && isspace(Buffer[i])) {
        i++;
    }
    if (i >= RequestLineLength) {
        WriteLog("invalid request url\n");
        return 0;
    }

    const char* UrlStart = Buffer + i;
    while (i < RequestLineLength && !isspace(Buffer[i])) {
        i++;
    }
    if (i >= RequestLineLength) {
        WriteLog("invalid request url\n");
        return 0;
    }
    int UrlLength = i - (UrlStart - Buffer);

    const char* UriStart = NULL;
    if (UrlLength >= strlen("http://") && !strncmp(UrlStart, "http://", strlen("http://"))) {
        UriStart = memmem(UrlStart + strlen("http://"), UrlLength - strlen("http://"), "/", 1);
    } else {
        UriStart = UrlStart;
    }
    int UriLength = UrlLength - (UriStart - UrlStart);

    char* QueryStart = memmem(UriStart, UriLength, "?", 1);
    if (!QueryStart) {
        WriteLog("invalid request url, no query\n");
        return 0;
    }
    UriLength = QueryStart - UriStart;
    QueryStart += 1;
    int QueryLength = UrlLength - UriLength - 1;
    *(QueryStart + QueryLength) = '\0';

    char* Ptr = NULL;
    char* Str = NULL;
    char* Routes = NULL;
    char* Comma = NULL;
    if (UriLength == 4 && !strncmp(UriStart, "/add", 4)) {
        Ptr = strtok(QueryStart, "&");
        while (Ptr) {
            WriteLog("ptr:%s, len: %d\n", Ptr, strlen(Ptr));
            if (strlen(Ptr) > strlen("routes=") && !strncmp(Ptr, "routes=", strlen("routes="))) {
                Routes = Ptr + strlen("routes=");
                Str = strtok(Routes, ";");

                while(Str) {
                    Comma = memmem(Str, strlen(Str), ",", 1);
                    int DestinationLength = Comma - Str;
                    int NextHopLength = strlen(Str) - (Comma - Str) - 1;
                    if (!Comma || DestinationLength <= 0 || NextHopLength <= 0
                        || DestinationLength >= 256 || NextHopLength >= 64) {
                        Str = strtok(NULL, ";");
                        continue;
                    }

                    char Destination[256] = {0};
                    char NextHop[64] = {0};
                    memcpy(Destination, Str, DestinationLength);
                    memcpy(NextHop, Comma + 1, NextHopLength);
                    WriteLog("Destination:%s\n", Destination);
                    WriteLog("NextHop:%s\n", NextHop);
                    if (!AddRoute(Destination, NextHop)) {
                        WriteLog("add route failed, internal error\n");
                        return 0;
                    }

                    Str = strtok(NULL, ";");
                }

                DumpRoutes();
                break;
            }
            Ptr = strtok(NULL, "&");
        }
    } else if (UriLength == 4 && !strncmp(UriStart, "/del", 4)) {
        Ptr = strtok(QueryStart, "&");
        while (Ptr) {
            WriteLog("ptr:%s, len: %d\n", Ptr, strlen(Ptr));
            if (strlen(Ptr) > strlen("routes=") && !strncmp(Ptr, "routes=", strlen("routes="))) {
                Routes = Ptr + strlen("routes=");
                Str = strtok(Routes, ";");

                while (Str) {
                    RemoveRoute(Str);
                    WriteLog("Destination:%s\n", Str);
                    Str = strtok(NULL, ";");
                };

                DumpRoutes();
                break;
            }
            Ptr = strtok(NULL, "&");
        }
    } else {
        WriteLog("invalid uri\n");
        return 0;
    }
    ShowRoutes();
    return 1;
}

void HttpMain()
{
    int ServerSockfd;
    int ClientSockfd;
    int Pid;
    int Buflen;
    struct sockaddr_in *ServerAddr = (struct sockaddr_in*)calloc(1, sizeof(struct sockaddr_in));   
    struct sockaddr_in *RemoteAddr = (struct sockaddr_in*)calloc(1, sizeof(struct sockaddr_in));; 
    int SinSize = sizeof(struct sockaddr_in);
    char GoodHeader[] = "HTTP/1.0 200 OK\r\n\r\n";
    char BadHeader[]  = "HTTP/1.0 400 Bad Request\r\n\r\n";

    ServerAddr->sin_family = AF_INET; 
    ServerAddr->sin_addr.s_addr = INADDR_ANY; 
    ServerAddr->sin_port = htons(8811); 

    if((ServerSockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        WriteLog("socket failed\n");
        return;
    }
    
    if (bind(ServerSockfd, (struct sockaddr *)ServerAddr, sizeof(struct sockaddr)) < 0)
    {
        WriteLog("bind failed\n");
        return;
    }
 
    if (listen(ServerSockfd, 5) < 0) {
        WriteLog("listen failed");
        return;
    }

    while(1)
    {
        ClientSockfd = accept(ServerSockfd, (struct sockaddr *)RemoteAddr, &SinSize);

        if (ClientSockfd < 0)
        {
            error("failed on accept");
        }

        char RecvBuf[BUFSIZ] = {0};

        Buflen = recv(ClientSockfd, RecvBuf, BUFSIZ, 0);
        if (Buflen > 0) {
            WriteLog("%s\n", RecvBuf);
            int Ret = ProcessRequest(RecvBuf, Buflen);
            if (Ret) {
                send(ClientSockfd, GoodHeader, strlen(GoodHeader), 0);
            } else {
                send(ClientSockfd, BadHeader, strlen(BadHeader), 0);
            }
        } else {
            send(ClientSockfd, BadHeader, strlen(BadHeader), 0);
        }
        close(ClientSockfd);
    } 
    close(ServerSockfd);
    return;
}

