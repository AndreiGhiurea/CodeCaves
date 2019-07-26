#pragma once
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <stdio.h>

#define STATUS NTSTATUS

#ifndef     CHAR
typedef char CHAR, *PCHAR;
#endif

#ifndef     BOOLEAN
typedef unsigned __int8 BOOLEAN, *PBOOLEAN;
#endif

#ifndef     QWORD
typedef unsigned __int64 QWORD, *PQWORD;
#endif