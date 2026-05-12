#pragma once
#include "../pe/pe.h"
#include <vector>
#include <cstdint>
#include <string>

class pdbparser {
private:
	// Contains signature and PDB file name information of the input file
	struct codeviewInfo_t
	{
		ULONG CvSignature;
		GUID Signature;
		ULONG Age;
		char PdbFileName[ANYSIZE_ARRAY];
	};

	uint8_t* module_base = nullptr; // Store base address of PDB after loading into memory

public:

	struct sym_func { // Store basic function information

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