#pragma once
#include "../pe/pe.h"
#include <vector>
#include <cstdint>
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

	uint8_t* module_base = nullptr; // Lưu trữ địa chỉ cơ sở của PDB sau khi được tải vào bộ nhớ

public:

	struct sym_func { // Lưu trữ thông tin cơ bản của hàm

		int id = -1;

		uint32_t offset = 0;
		std::string name;
		uint32_t size = 0;
		bool obfuscate = true;
		bool ctfflattening = true;	
	};

	pdbparser(pe64* pe);
	~pdbparser();

	std::vector<sym_func>parse_functions();

};