#pragma once
#include "utils.h"
#include <DbgHelp.h>

typedef STATUS
(*PFUNC_SectionCallback)(
    _In_ VOID *MappedPeFile,
    _In_ IMAGE_SECTION_HEADER *Section, 
    _In_ VOID *SectionVa,
    _In_ QWORD ImageBase
    );

STATUS
MapPeFile(
    _In_ CHAR* FilePath,
    _Out_ VOID** MappedPeFile
    );

STATUS
ValidatePeFile(
    _In_ VOID *MappedPeFile
    );

STATUS IterateSectionsAndCallback(
    _In_ VOID *MappedPeFile,
    _In_ PFUNC_SectionCallback Callback
    );