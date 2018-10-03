#include <stdio.h>
#include <iostream>
#include <conio.h>
#include <stdlib.h>
#include <Windows.h>
#include <fstream>
#include <string>

int main() {

	DWORD FileSize, PeHeaderAddress, Signature, exports, Characteristics_export;
	errno_t err;
	FILE*fp = NULL;
	std::string path;
	printf("duong dam file .exe can tim ");
	std::getline(std::cin, path);
	const char * c = path.c_str();
	err = fopen_s(&fp, c, "rb");

	IMAGE_DOS_HEADER DosHeader = { 0 };
	PIMAGE_DOS_HEADER dosHeader = { 0 };
	PIMAGE_NT_HEADERS PeHeader = { 0 };
	IMAGE_FILE_HEADER FileHeader = { 0 };
	IMAGE_OPTIONAL_HEADER OpHeader = { 0 };
	IMAGE_SECTION_HEADER SectionHeader = { 0 };
	IMAGE_EXPORT_DIRECTORY Export = { 0 };

	fseek(fp, 0, SEEK_END);         //  đưa con trỏ về cuối tập tin 
	FileSize = ftell(fp);           //  ftell(fp) : cho biết vị trí hiện tại của con trỏ chỉ vị (byte thứ mấy trên tập fp)
	if (FileSize < sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_NT_HEADERS))
		printf("NOT PE file ");
	else
		printf("Reading PE FILE\n----------------------\n\n");
		printf("Reading DOS header \n----------------------\n");
		printf("size of DosHeder:\t\t %d \n", sizeof DosHeader);         //sizeofDosHeader
		fseek(fp, 0, SEEK_SET);         // đưa con trỏ về đầu tập tin >
		fread(&DosHeader, sizeof DosHeader, 1, fp);
	if (DosHeader.e_magic != 0x5a4d)
		printf("NOT PE file");
	printf("Magic number:\t\t\t MZ(%#x) \n", DosHeader.e_magic);    // e_magic
	printf("Adress of PE header(e_lfanew):\t %#xh \n", DosHeader.e_lfanew);     // e_lfanew
	printf("-------------------------------------------------\n\n");
	PeHeaderAddress = DosHeader.e_lfanew;
	if (FileSize <= PeHeaderAddress + sizeof (IMAGE_NT_HEADERS))
		printf("NOT PE file");
	else
	{
		printf("Reading PE Header \n----------------------\n");
		printf("\nPE File signature \n----------------------\n");
		fseek(fp, PeHeaderAddress, SEEK_SET);           //  đưa con trỏ về đầu Pe Header Adress
		fread(&Signature, sizeof(DWORD), 1, fp);        //đọc thông tin signature
		printf("Signature:\t\t %#x \n", Signature);     //Signature
		fread(&FileHeader, sizeof FileHeader, 1, fp);       //đọc FileHeader
		printf("number of section:\t %d \n", FileHeader.NumberOfSections);          //NumberOfSection
		printf("Size of optional Header: %d \n", FileHeader.SizeOfOptionalHeader);  //SizeOfOptionalHeader
		printf("Characteristics:\t\t %x", FileHeader.Characteristics);

		printf("\nPE Optional Header \n----------------------\n");
		fread(&OpHeader, 1, sizeof OpHeader, fp);            // đọc optional header
		printf("Address of Entry Point:\t\t %#x\n", OpHeader.AddressOfEntryPoint);
		printf("ImageBase:\t\t\t %#x \n", OpHeader.ImageBase);
		printf("BaseofCode:\t\t\t %#x \n", OpHeader.BaseOfCode);
		printf("FileAlignment:\t\t\t %#x \n", OpHeader.FileAlignment);
		printf("SizeOfImage:\t\t\t %#x \n", OpHeader.SizeOfImage);
		printf("CheckSum:\t\t\t %#x \n", OpHeader.CheckSum);
		printf("-------------------------------------------------\n\n");
		fread(&SectionHeader, PeHeaderAddress + sizeof (IMAGE_NT_HEADERS), sizeof SectionHeader, fp);    //đọc sectionHeader
		int secCount = 1;       //secCount= section Count
		while (secCount <= FileHeader.NumberOfSections)      // lặp lại cho đến khi số section <= NumberofSection
		{

			printf("section header (%d or %d) \n", secCount, FileHeader.NumberOfSections);
			printf("---------------------\n");
			printf("Section Header name \t\t:%s\n", SectionHeader.Name);
			printf("Virtual Size  \t\t\t:%#x\n", SectionHeader.Misc.VirtualSize);
			printf("Virtual Address \t\t:%#x\n", SectionHeader.VirtualAddress);
			printf("Size of raw data  \t\t:%#x\n", SectionHeader.SizeOfRawData);
			printf("Pointer to Raw Data \t\t:%#x\n\n", SectionHeader.PointerToRawData);
			fseek(fp, PeHeaderAddress + sizeof(IMAGE_NT_HEADERS)+secCount*sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
			fread(&SectionHeader, sizeof SectionHeader, 1, fp);
			secCount++;
		}
		printf("Reading ExPort \n----------------------\n");
		exports = SectionHeader.Characteristics;
		fseek(fp, exports, SEEK_SET);                           //đặt con trỏ vào đầu IMAGE_EXPORT 
		fread(&Characteristics_export, sizeof(DWORD), 1, fp);
		printf("characteristics \t: %#x \n", Characteristics_export);

		fread(&Export, sizeof Export, 1, fp);                   //đọc IMAGE_EXPORT
		printf("nName \t\t\t: %x \n", Export.Name);
		printf("nBase \t\t\t: %x \n", Export.Base);
		printf("Number of Function \t: %d \n", Export.NumberOfFunctions);
		printf("Number of Name \t\t: %d \n", Export.NumberOfNames);
		printf("Address of function \t: %x \n", Export.AddressOfFunctions);
		printf("Adress Of Name \t\t: %x \n", Export.AddressOfNames);
		printf("Address of name ordinals: %x \n", Export.AddressOfNameOrdinals);

		fclose(fp);
		_getch();
	}
}