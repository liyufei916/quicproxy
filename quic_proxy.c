#include "quic_proxy.h"

const QUIC_REGISTRATION_CONFIG RegConfig = { "quicproxy", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

const QUIC_BUFFER Alpn = { sizeof("quicproxy") - 1, (uint8_t*)"quicproxy" };

uint16_t UdpPort = 4567;
uint16_t UpsUdpPort = 4568;

const uint64_t IdleTimeoutMs = 10000;
const uint64_t UpsIdleTimeoutMs = 1200;
const uint64_t KeepAliveIntervalMs = 1000;

const QUIC_API_TABLE* MsQuic;

HQUIC Registration;

HQUIC Configuration;

HQUIC UpsConfiguration;

void PrintUsage()
{
    printf(
        "\n"
        "Usage:\n"
        "\n"
        "  quicproxy.exe -cert_hash:<...> or (-cert_file:<...> and -key_file:<...> (and optionally -password:<...>))\n"
        );
}

BOOLEAN
GetFlag(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* Name
    )
{
    int i;
    const int NameLen = strlen(Name);
    for (i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, Name, NameLen) == 0
            && strlen(argv[i]) == NameLen + 1) {
            return TRUE;
        }
    }
    return FALSE;
}

_Ret_maybenull_ _Null_terminated_ const char*
GetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* Name
    )
{
    int i;
    const int NameLen = strlen(Name);
    for (i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, Name, NameLen) == 0
            && strlen(argv[i]) > 1 + NameLen + 1
            && *(argv[i] + 1 + NameLen) == ':') {
            return argv[i] + 1 + NameLen + 1;
        }
    }
    return NULL;
}

uint8_t
DecodeHexChar(
    _In_ char c
    )
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return 0;
}

uint32_t
DecodeHexBuffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
        uint8_t* OutBuffer
    )
{
    uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    uint32_t i;
    for (i = 0; i < HexBufferLen; i++) {
        OutBuffer[i] =
            (DecodeHexChar(HexBuffer[i * 2]) << 4) |
            DecodeHexChar(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}

BOOLEAN SetDefaultTarget(QUIC_PROXY_CONTEXT* Context){
    return GetDefaultRoute(Context->Target, MAX_TARGET_LENGTH);
}

BOOLEAN FindAndSetTarget(const char* Value, int Len, QUIC_PROXY_CONTEXT* Context) {
    WriteLog("host: %s, len:%d\n", Value, Len);
    return GetRoute((char*)Value, Context->Target, MAX_TARGET_LENGTH);
}

BOOLEAN ParseRequestHeader(const char* HeaderStart, int Len, QUIC_PROXY_CONTEXT* Context) {
    BOOLEAN Ret;
    const char* NewLine = HeaderStart;
    const char* HeaderEnd = HeaderStart + Len;

    while (NewLine < HeaderStart + Len) {
        while (NewLine < HeaderEnd && isspace(*NewLine)) {
            NewLine ++;
        }

        const char* Crlf = (const char*)memmem(NewLine, Len - (NewLine - HeaderStart), "\r\n", 2);

        if (!Crlf) {
            Crlf = HeaderStart + Len;
        }

        char* Colon = (char*)memmem(NewLine, Crlf - NewLine, ":", 1);

        if (!Colon) {
            WriteLog("invlaid http headers\n");
            Ret = SetDefaultTarget(Context);
            return Ret;
        }

        const char* NameStart = NewLine;
        int NameLen = Colon - NewLine;

        NewLine = Colon + 1;
        while (NewLine < Crlf && isspace(*NewLine)) {
            NewLine ++;
        }

        int ValueLen = Crlf - NewLine;
        while (ValueLen > 0 && isspace(NewLine[ValueLen - 1])) {
            ValueLen --;
        }

        char* ValueStart = (char*)NewLine;

        if (memcmp(NameStart, "Host", NameLen) == 0) {
            char HostValue[MAX_TARGET_LENGTH] = {0};

            char* PortColon = (char*)memmem(ValueStart, ValueLen, ":", 1);
            if (PortColon) {
                ValueLen = PortColon - ValueStart;
            }
            memcpy(HostValue, ValueStart, ValueLen);

            Ret = FindAndSetTarget(HostValue, ValueLen, Context);
            return Ret;
        }

        NewLine = Crlf + 2;
    }

    Ret = SetDefaultTarget(Context);
    return Ret;
}

BOOLEAN ParseTarget(uint8_t * const Buffer, int size, QUIC_PROXY_CONTEXT* Context)
{
    memcpy(Context->ParsedData + Context->ParsedLength, (char*)Buffer, MAX_HEADER_LENGTH - Context->ParsedLength);
    Context->ParsedLength += size;
    if (Context->ParsedLength > MAX_HEADER_LENGTH) {
        Context->ParsedLength = MAX_HEADER_LENGTH;
    }

    char* FirstLineEnd = (char*)memmem(Context->ParsedData, Context->ParsedLength, "\r\n", 2);

    if (!FirstLineEnd) {
        goto Error;
    }

    char* HeaderStart = FirstLineEnd + 2;

    char* HeaderEnd = (char*)memmem(HeaderStart, Context->ParsedLength - (HeaderStart - Context->ParsedData), "\r\n\r\n", 4);

    if (!HeaderEnd) {
        goto Error;
    }

    BOOLEAN ParseRet = ParseRequestHeader(HeaderStart, HeaderEnd - HeaderStart, Context);

    return ParseRet;

Error:

    if (Context->ParsedLength >= MAX_HEADER_LENGTH) {
        WriteLog("parse failed\n");
        BOOLEAN Ret = SetDefaultTarget(Context);
        return Ret;
    } else {
        WriteLog("still need read request\n");
        return FALSE;
    }
}

BOOLEAN
UpstreamLoadConfiguration(
    BOOLEAN Unsecure
    )
{
    QUIC_SETTINGS Settings = {0};
    Settings.IdleTimeoutMs = UpsIdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    Settings.KeepAliveIntervalMs = KeepAliveIntervalMs;
    Settings.IsSet.KeepAliveIntervalMs = TRUE;

    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (Unsecure) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &UpsConfiguration))) {
        WriteLog("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(UpsConfiguration, &CredConfig))) {
        WriteLog("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
LoadConfiguration(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_SETTINGS Settings = {0};
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    const char* Cert;
    const char* KeyFile;
    if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
        uint32_t CertHashLen =
            DecodeHexBuffer(
                Cert,
                sizeof(Config.CertHash.ShaHash),
                Config.CertHash.ShaHash);
        if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
            return FALSE;
        }
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        Config.CredConfig.CertificateHash = &Config.CertHash;

    } else if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
               (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {
        const char* Password = GetValue(argc, argv, "password");
        if (Password != NULL) {
            Config.CertFileProtected.CertificateFile = (char*)Cert;
            Config.CertFileProtected.PrivateKeyFile = (char*)KeyFile;
            Config.CertFileProtected.PrivateKeyPassword = (char*)Password;
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
            Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
        } else {
            Config.CertFile.CertificateFile = (char*)Cert;
            Config.CertFile.PrivateKeyFile = (char*)KeyFile;
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            Config.CredConfig.CertificateFile = &Config.CertFile;
        }

    } else {
        WriteLog("Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and optionally 'password')]!\n");
        return FALSE;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        WriteLog("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &Config.CredConfig))) {
        WriteLog("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

void
StreamFinish(HQUIC Stream)
{
    MsQuic->StreamSend(Stream, NULL, 0, QUIC_SEND_FLAG_FIN, NULL);
}

void
StreamSend(uint8_t * const Buffer, int SendBufferLength, HQUIC Stream)
{
    QUIC_STATUS Status;
    uint8_t* SendBufferRaw;
    QUIC_BUFFER* SendBuffer;

    SendBufferRaw = (uint8_t*)calloc(1, sizeof(QUIC_BUFFER) + SendBufferLength);
    if (SendBufferRaw == NULL) {
        WriteLog("SendBuffer allocation failed!\n");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        return;
    }
    SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = SendBufferLength;
    memcpy(SendBuffer->Buffer, Buffer, SendBufferLength);

    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, 0, SendBuffer))) {
        WriteLog("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
UpsStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    int i;
    QUIC_PROXY_CONTEXT* Ctx = (QUIC_PROXY_CONTEXT*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        WriteLog("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        WriteLog("[strm][%p] Data received\n", Stream);
        if (!Ctx || !Ctx->DownstreamStream) {
            WriteLog("[strm][%p] no down stream\n", Stream);
            break;
        }
        for (i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            StreamSend(Event->RECEIVE.Buffers[i].Buffer, Event->RECEIVE.Buffers[i].Length, Ctx->DownstreamStream);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        WriteLog("[strm][%p] Peer aborted\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        WriteLog("[strm][%p] Peer shut down\n", Stream);
        StreamFinish(Ctx->DownstreamStream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        WriteLog("[strm][%p] All done\n", Stream);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->StreamClose(Stream);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
UpstreamStreamStart(QUIC_PROXY_CONTEXT* Context)
{
    QUIC_STATUS Status;
    HQUIC UpsStream;

    if (QUIC_FAILED(Status = MsQuic->StreamOpen(Context->UpstreamConnection, QUIC_STREAM_OPEN_FLAG_NONE, UpsStreamCallback, Context, &UpsStream))) {
        WriteLog("StreamOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    WriteLog("[strm][%p] Starting...\n", UpsStream);

    if (QUIC_FAILED(Status = MsQuic->StreamStart(UpsStream, QUIC_STREAM_START_FLAG_NONE))) {
        WriteLog("StreamStart failed, 0x%x!\n", Status);
        MsQuic->StreamClose(UpsStream);
        goto Error;
    }

    Context->UpstreamStream = UpsStream;

Error:

    if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Context->UpstreamConnection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
UpsConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    QUIC_PROXY_CONTEXT* Ctx = (QUIC_PROXY_CONTEXT*)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        WriteLog("[conn][%p] Connected\n", Connection);
        UpstreamStreamStart(Ctx);

        pthread_rwlock_wrlock(&Ctx->DataLock);
        Ctx->UpstreamConnected = TRUE;

        QUIC_CHAINNODE* p = Ctx->Data;
        QUIC_CHAINNODE* q = p;
        while (p) {
            WriteLog("data: %p\n", p);
            StreamSend(p->Buffer, p->Length, Ctx->UpstreamStream);
            p = p->Next;
            free(q->Buffer);
            free(q);
            q = p;
        }
        Ctx->Data = NULL;
        pthread_rwlock_unlock(&Ctx->DataLock);

        if (Ctx->DownstreamFinished) {
            StreamFinish(Ctx->UpstreamStream);
        }
        WriteLog("send finish\n");

        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            WriteLog("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            WriteLog("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        WriteLog("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        WriteLog("[conn][%p] All done\n", Connection);
        QUIC_CONNECTION* QC = (QUIC_CONNECTION*)Connection;
        RemoveConnection(QC->Worker, Connection);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->ConnectionClose(Connection);
            WriteLog("conn: %p closed\n", Connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        WriteLog("[conn][%p] Resumption ticket received (%u bytes):\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        /*uint32_t i;
        for (i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
            WriteLog("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        WriteLog("\n");*/
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
UpstreamConnect(QUIC_PROXY_CONTEXT* Context)
{
    QUIC_STATUS Status;
    HQUIC UpsConnection;

    ShowConnectionPool();

    if (UpsConnection = GetConnection(Context->Worker, Context->Target)) {
        Context->UpstreamConnection = UpsConnection;
        Context->UpstreamConnected = TRUE;
        WriteLog("reuse connection: %p\n", UpsConnection);
        return;
    }

    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, UpsConnectionCallback, (void *)Context, &UpsConnection))) {
        WriteLog("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    const char* Target = Context->Target;
    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(UpsConnection, UpsConfiguration, QUIC_ADDRESS_FAMILY_UNSPEC, Target, UpsUdpPort))) {
        WriteLog("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

    Context->UpstreamConnection = UpsConnection;
    if (!SetConnection(Context->Worker, UpsConnection, Context->Target)) {
        WriteLog("set connection failed\n");
        goto Error;
    }

    ShowConnectionPool();

Error:

    if (QUIC_FAILED(Status) && Context->UpstreamConnection != NULL) {
        MsQuic->ConnectionClose(Context->UpstreamConnection);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
StreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    int i;
    QUIC_PROXY_CONTEXT* Ctx = (QUIC_PROXY_CONTEXT*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //free(Event->SEND_COMPLETE.ClientContext);
        WriteLog("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        WriteLog("[strm][%p] Data received\n", Stream);
        for (i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            if (!Ctx->TargetParsed) {
                if (ParseTarget(Event->RECEIVE.Buffers[i].Buffer, Event->RECEIVE.Buffers[i].Length, Ctx)) {
                    Ctx->TargetParsed = TRUE;
                    WriteLog("parse target: %s\n", Ctx->Target);
                    UpstreamConnect(Ctx);
                } else {
                    WriteLog("[strm][%p] Target parse failed\n", Stream);
                    continue;
                }
            }

            pthread_rwlock_wrlock(&Ctx->DataLock);
            if (Ctx->UpstreamConnected && !Ctx->Data) {
                pthread_rwlock_unlock(&Ctx->DataLock);
                if (!Ctx->UpstreamStream) {
                    UpstreamStreamStart(Ctx);
                }
                StreamSend(Event->RECEIVE.Buffers[i].Buffer, Event->RECEIVE.Buffers[i].Length, Ctx->UpstreamStream);
                continue;
            }

            QUIC_CHAINNODE* Data = (QUIC_CHAINNODE*)calloc(1, sizeof(QUIC_CHAINNODE));
            Data->Buffer = (char*)calloc(1, Event->RECEIVE.Buffers[i].Length);
            memcpy(Data->Buffer, Event->RECEIVE.Buffers[i].Buffer, Event->RECEIVE.Buffers[i].Length);
            Data->Length = Event->RECEIVE.Buffers[i].Length;
            Data->Next = NULL;

            if (!Ctx->Data) {
                Ctx->Data = Data;
            } else {
                QUIC_CHAINNODE* p = Ctx->Data;
                while (p->Next) {
                    p = p->Next;
                }
                p->Next = Data;
            }
            pthread_rwlock_unlock(&Ctx->DataLock);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        WriteLog("[strm][%p] Peer shut down\n", Stream);
        if (Ctx->UpstreamStream) {
            StreamFinish(Ctx->UpstreamStream);
        } else {
            Ctx->DownstreamFinished = TRUE;
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        WriteLog("[strm][%p] Peer aborted\n", Stream);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        if (Ctx && (!Ctx->UpstreamConnected || !Ctx->Data)) {
            free(Ctx);
        }
        WriteLog("[strm][%p] All done\n", Stream);
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        WriteLog("[conn][%p] Connected\n", Connection);
        //MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            WriteLog("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            WriteLog("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        WriteLog("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        WriteLog("[conn][%p] All done\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        WriteLog("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        QUIC_PROXY_CONTEXT* Ctx = (QUIC_PROXY_CONTEXT*)calloc(1, sizeof(QUIC_PROXY_CONTEXT));
        Ctx->DownstreamConnection = Connection;
        Ctx->DownstreamStream = Event->PEER_STREAM_STARTED.Stream;
        QUIC_CONNECTION* QC = (QUIC_CONNECTION*)Connection;
        Ctx->Worker = QC->Worker;
        pthread_rwlock_init(&Ctx->DataLock, NULL);
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)StreamCallback, Ctx);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        WriteLog("[conn][%p] Connection resumed!\n", Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(Context);
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ConnectionCallback, NULL);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
        break;
    default:
        break;
    }
    return Status;
}

BOOLEAN
RunProxy()
{
    QUIC_STATUS Status;
    HQUIC Listener = NULL;

    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);

    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ListenerCallback, NULL, &Listener))) {
        WriteLog("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
        WriteLog("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    return TRUE;

Error:

    if (Listener != NULL) {
        MsQuic->ListenerClose(Listener);
    }
    return FALSE;
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (!LogInit()) {
        printf("init log failed\n");
        goto Error;
    }

    ConnectionPoolLockInit();
    RouteLockInit();

    if (!LoadRoutes()) {
        printf("load routes failed\n");
        goto Error;
    }

    if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
        PrintUsage();
    } else {
        if (!LoadConfiguration(argc, argv)) {
            printf("load configuration failed\n");
            goto Error;
        }

        if (!UpstreamLoadConfiguration(GetFlag(argc, argv, "unsecure"))) {
            printf("upstream load configuration failed\n");
            goto Error;
        }

        if (!RunProxy()) {
            printf("run proxy failed\n");
            goto Error;
        }
    }

    HttpMain();

Error:

    if (MsQuic != NULL) {
        if (Configuration != NULL) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (UpsConfiguration != NULL) {
            MsQuic->ConfigurationClose(UpsConfiguration);
        }
        if (Registration != NULL) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return (int)Status;
}


