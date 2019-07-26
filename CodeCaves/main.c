#include "utils.h"
#include "pe.h"

STATUS
SectionsCallback(
    _In_ VOID *MappedPeFile,
    _In_ IMAGE_SECTION_HEADER *Section,
    _In_ VOID *SectionVa,
    _In_ QWORD ImageBase
    )
{
    QWORD caveStart = 0x0;
    QWORD caveEnd = 0x0;
    QWORD caveSize = 0x0;
    QWORD caveOffset = 0x0;
    QWORD sectionVa = (QWORD)SectionVa;

    if (NULL == SectionVa)
    {
        printf("[WARNING] Skipping section: %s\n\n", Section->Name);
        return STATUS_SUCCESS;
    }

    while (sectionVa < (QWORD)SectionVa + Section->Misc.VirtualSize)
    {
        caveStart = sectionVa;
        caveEnd = sectionVa;

        while (*(BYTE*)caveEnd == 0x00)
        {
            caveEnd++;
        }

        caveSize = caveEnd - caveStart;
        caveOffset = caveStart - (QWORD)SectionVa;
        if (caveSize > 0x100)
        {
            printf("New Cave detected\n");
            printf("   Section Name:    %s\n", Section->Name);
            printf("   Cave Start:      0x%p\n", (VOID*)(Section->VirtualAddress + caveOffset));
            printf("   Cave End:        0x%p\n", (VOID*)(Section->VirtualAddress + caveOffset + caveSize));
            printf("   Cave Size:       0x%p\n", (VOID*)caveSize);
            printf("   Virtual Address: 0x%p\n", (VOID*)(ImageBase + Section->VirtualAddress + caveOffset));
            printf("   Infos:");
            if (Section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                printf(" Executable");
            }
            if (Section->Characteristics & IMAGE_SCN_MEM_READ)
            {
                printf(" Readable");
            }
            if (Section->Characteristics & IMAGE_SCN_MEM_WRITE)
            {
                printf(" Writable");
            }
            printf("\n\n");
        }

        sectionVa = caveEnd + 1;
    }

    return STATUS_SUCCESS;
}

STATUS 
main(
    DWORD argc,
    CHAR** argv
    )
{
    STATUS status;
    PVOID pMappedPeFile = NULL;

    if (argc < 2)
    {
        printf("[ERROR] Give a PE file path as a parameter\n");
        return STATUS_INVALID_PARAMETER;
    }

    status = MapPeFile(argv[1], &pMappedPeFile);
    if (!SUCCEEDED(status))
    {
        printf("[ERROR] MapPeFile failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    status = IterateSectionsAndCallback(pMappedPeFile, SectionsCallback);
    if (!SUCCEEDED(status))
    {
        printf("[ERROR] IterateSectionsAndCallback failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    printf("[SUCCESS] Finished finding all the caves\n");

    return STATUS_SUCCESS;
}