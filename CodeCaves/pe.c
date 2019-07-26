#include "pe.h"

STATUS
ValidatePeFile(
    _In_ VOID *MappedPeFile
    )
{
    IMAGE_NT_HEADERS64 *pNth64;
    IMAGE_NT_HEADERS32 *pNth32;
    BYTE *pBase;
    IMAGE_DOS_HEADER *pDosHeader;
    DWORD secOff, sizeOfImage;

    pBase = (BYTE *)MappedPeFile;

    pDosHeader = (IMAGE_DOS_HEADER *)MappedPeFile;

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }

    pNth32 = (IMAGE_NT_HEADERS32 *)(pBase + pDosHeader->e_lfanew);
    pNth64 = (IMAGE_NT_HEADERS64 *)(pBase + pDosHeader->e_lfanew);

    //
    // Validate the PE signature. Doesn't matter what we use here since only the OptionalHeader is different
    //
    if (pNth64->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        if (pNth64->Signature != IMAGE_NT_SIGNATURE)
        {
            return STATUS_INVALID_IMAGE_NOT_MZ;
        }

        // See that section headers don't point out of file
        sizeOfImage = pNth64->OptionalHeader.SizeOfImage;
        secOff = pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + pNth64->FileHeader.SizeOfOptionalHeader;
        if (secOff + sizeof(IMAGE_SECTION_HEADER) * pNth64->FileHeader.NumberOfSections > sizeOfImage)
        {
            printf("[ERROR] Sections headers point out of the mapping!\n");
            return STATUS_INVALID_IMAGE_NOT_MZ;
        }
    }
    else if (pNth32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        if (pNth32->Signature != IMAGE_NT_SIGNATURE)
        {
            return STATUS_INVALID_IMAGE_NOT_MZ;
        }

        // See that section headers don't point out of file
        sizeOfImage = pNth32->OptionalHeader.SizeOfImage;
        secOff = pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + pNth32->FileHeader.SizeOfOptionalHeader;
        if (secOff + sizeof(IMAGE_SECTION_HEADER) * pNth32->FileHeader.NumberOfSections > sizeOfImage)
        {
            printf("[ERROR] Sections headers point out of the mapping!\n");
            return STATUS_INVALID_IMAGE_NOT_MZ;
        }
    }
    else
    {
        printf("[ERROR] Unknown image: 0x%x", pNth32->FileHeader.Machine);
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }

    // Make a final validation (so we know that the NT headers weren't moved outside the image)
    if ((DWORD)pDosHeader->e_lfanew > sizeOfImage)
    {
        printf("[ERROR] e_lfanew points outside of image\n");
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }

    return STATUS_SUCCESS;
}

STATUS IterateSectionsAndCallback(
    _In_ VOID *MappedPeFile,
    _In_ PFUNC_SectionCallback Callback
    )
{
    STATUS status;
    DWORD secOff = 0, numberOfSections = 0;
    IMAGE_DOS_HEADER *pDosHeader;
    IMAGE_NT_HEADERS32 *pNth32;
    IMAGE_NT_HEADERS64 *pNth64;
    IMAGE_SECTION_HEADER* pSectionHeader;
    VOID *pSectionFa = NULL;
    QWORD imageBase = 0;

    // Validate it one more time just for shits and giggles
    status = ValidatePeFile(MappedPeFile);
    if (!SUCCEEDED(status))
    {
        printf("[ERROR] ValidatePeFile failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    pDosHeader = (IMAGE_DOS_HEADER *)MappedPeFile;
    pNth32 = (IMAGE_NT_HEADERS32 *)((BYTE *)MappedPeFile + pDosHeader->e_lfanew);
    
    if (pNth32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        pNth64 = (IMAGE_NT_HEADERS64 *)pNth32;
        secOff = pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + pNth64->FileHeader.SizeOfOptionalHeader;
        numberOfSections = pNth64->FileHeader.NumberOfSections;
        imageBase = pNth64->OptionalHeader.ImageBase;
    }
    else if (pNth32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        secOff = pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + pNth32->FileHeader.SizeOfOptionalHeader;
        numberOfSections = pNth32->FileHeader.NumberOfSections;
        imageBase = pNth32->OptionalHeader.ImageBase;
    }
    else
    {
        printf("[ERROR] Unknown image: 0x%x", pNth32->FileHeader.Machine);
        return STATUS_UNSUCCESSFUL;
    }

    pSectionHeader = (IMAGE_SECTION_HEADER *)((BYTE*)MappedPeFile + secOff);
    for (DWORD i = 0; i < numberOfSections; i++, pSectionHeader++)
    {
        pSectionFa = ImageRvaToVa(pNth32, MappedPeFile, pSectionHeader->VirtualAddress, NULL);
        if (NULL == pSectionFa && GetLastError() != 0)
        {
            printf("[ERROR] ImageRvaToVa failed with status: %d\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

        status = Callback(MappedPeFile, pSectionHeader, pSectionFa, imageBase);
        if (!SUCCEEDED(status))
        {
            printf("[ERROR] Callback failed\n");
            return status;
        }
    }

    return STATUS_SUCCESS;
}

STATUS
MapPeFile(
    _In_ CHAR* FilePath,
    _Out_ VOID** MappedPeFile
    )
{
    STATUS status = STATUS_SUCCESS;
    HANDLE hFile = INVALID_HANDLE_VALUE, hMapping = NULL;
    PVOID pMappedFile = NULL;

    if (NULL == FilePath)
    {
        printf("[ERROR] Invalid FilePath\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == MappedPeFile)
    {
        printf("[ERROR] Invalid MappedPeFile pointer\n");
        return STATUS_INVALID_PARAMETER;
    }

    hFile = CreateFile(
        FilePath,
        GENERIC_READ,
        0x0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf("[ERROR] CreateFile failed with status: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto cleanup_and_leave;
    }

    hMapping = CreateFileMapping(
        hFile,
        NULL,
        PAGE_READONLY,
        0x0,
        0x0,
        NULL);
    if (NULL == hMapping)
    {
        printf("[ERROR] CreateFileMapping failed with status: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto cleanup_and_leave;
    }

    pMappedFile = MapViewOfFile(
        hMapping,
        FILE_MAP_READ,
        0x0,
        0x0,
        0x0);
    if (NULL == pMappedFile)
    {
        printf("[ERROR] MapViewOfFile failed with status: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto cleanup_and_leave;
    }

    status = ValidatePeFile(pMappedFile);
    if (!SUCCEEDED(status))
    {
        printf("[ERROR] Not a valid PE file\n");
        goto cleanup_and_leave;
    }

    *MappedPeFile = pMappedFile;

    return status;

cleanup_and_leave:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }

    if (hMapping != NULL)
    {
        CloseHandle(hMapping);
    }

    if (pMappedFile != NULL)
    {
        UnmapViewOfFile(pMappedFile);
    }

    return status;
}