#include "include.h"

FILE* LogFp = NULL;
const char* LogFile = "./debug.log";

int LogInit()
{
    if ((LogFp = fopen(LogFile, "a+")) == NULL) {
        printf("open log file failed\n");
        return 0;
    }
    return 1;
}

void InternalWriteLog(const char* Fmt, char *File, const char *Func, ...)
{
    struct tm* SysTime;
    time_t SysDay;
    time(&SysDay);
    SysTime = localtime(&SysDay);

    va_list Args;
    char RealFormat[4096];
    snprintf(RealFormat, 4096, "[%d-%d-%d %d:%d:%d] [%s] [%s] %s",
                    1900 + SysTime->tm_year, SysTime->tm_mon, SysTime->tm_mday, SysTime->tm_hour, SysTime->tm_min, SysTime->tm_sec, File, Func, Fmt);

    va_start(Args, Func);
    vfprintf(LogFp, RealFormat, Args);

    va_end(Args);
    fflush(LogFp);
}
