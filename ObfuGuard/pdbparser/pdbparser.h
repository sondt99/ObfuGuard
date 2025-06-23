#pragma once
#include "../pe/pe.h"

#include <string>

class pdbparser {
private:
	// Chứa thông tin về signature, về tên tệp PDB của tệp đầu vào
	struct codeviewInfo_t
	{
		ULONG CvSignature;
		GUID Signature;
		ULONG Age;
		char PdbFileName[ANYSIZE_ARRAY];
	};

	uint8_t* module_base; // Lưu trữ địa chỉ cơ sở của PDB sau khi được tải vào bộ nhớ

public:

	struct sym_func { // Lưu trữ thông tin cơ bản của hàm

		int id;

		uint32_t offset;
		std::string name;
		uint32_t size;
		bool obfuscate = true;
		bool ctfflattening = true;	
	};

	pdbparser(pe64* pe);
	
	~pdbparser();

	std::vector<sym_func>parse_functions();

};