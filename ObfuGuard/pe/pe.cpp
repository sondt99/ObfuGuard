#include "pe.h"
#include "../constants.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <cstring>
#include <algorithm>


pe64::pe64(std::string binary_path) {

	this->path = binary_path;

	if (!std::filesystem::exists(binary_path))
		throw std::runtime_error("binary path doesn't exist!");

	std::ifstream file_stream(binary_path, std::ios::binary);
	if(!file_stream)
		throw std::runtime_error("couldn't open input binary!");

	this->buffer.assign((std::istreambuf_iterator<char>(file_stream)),
		std::istreambuf_iterator<char>());

	std::vector<uint8_t>temp_buffer = buffer;

	if (temp_buffer.size() < sizeof(IMAGE_DOS_HEADER))
		throw std::runtime_error("file too small to contain a valid PE header!");

	PIMAGE_DOS_HEADER dos =
		reinterpret_cast<PIMAGE_DOS_HEADER>(temp_buffer.data());

	if(dos->e_magic != IMAGE_DOS_SIGNATURE)
		throw std::runtime_error("input binary isn't a valid pe file!");

	if (dos->e_lfanew < 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > temp_buffer.size())
		throw std::runtime_error("invalid PE header offset (e_lfanew out of bounds)!");

	PIMAGE_NT_HEADERS nt =
		reinterpret_cast<PIMAGE_NT_HEADERS>(temp_buffer.data() + dos->e_lfanew);

	if (nt->Signature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("input binary isn't a valid pe file (missing PE signature)!");

	if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		throw std::runtime_error("ObfuGuard requires a 64-bit PE optional header!");

	if(nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		throw std::runtime_error("ObfuGuard doesn't support 32bit binaries!");

	if (nt->OptionalHeader.SizeOfImage > ObfuGuard::MAX_PE_IMAGE_SIZE)
		throw std::runtime_error("PE SizeOfImage exceeds maximum allowed size!");

	this->buffer.resize(nt->OptionalHeader.SizeOfImage);

	memset(this->buffer.data(), 0, nt->OptionalHeader.SizeOfImage);

	auto first_section = IMAGE_FIRST_SECTION(nt);

	uint32_t headers_size = (std::min)(static_cast<uint32_t>(temp_buffer.size()), nt->OptionalHeader.SizeOfHeaders);
	memcpy(this->buffer.data(), temp_buffer.data(), headers_size);

	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {

		auto curr_section = &first_section[i];

		if (curr_section->PointerToRawData + curr_section->SizeOfRawData > temp_buffer.size())
			continue;
		if (curr_section->VirtualAddress + curr_section->SizeOfRawData > this->buffer.size())
			continue;

		memcpy(this->buffer.data() + curr_section->VirtualAddress, temp_buffer.data() + curr_section->PointerToRawData, curr_section->SizeOfRawData);

	}
	this->buffer_not_relocated = temp_buffer;
}

std::vector<uint8_t>* pe64::get_buffer() {
	return &this->buffer;
}

std::vector<uint8_t>* pe64::get_buffer_not_relocated() {
	return &this->buffer_not_relocated;
}

PIMAGE_NT_HEADERS pe64::get_nt() {
	return reinterpret_cast<PIMAGE_NT_HEADERS>(this->buffer.data() + reinterpret_cast<PIMAGE_DOS_HEADER>(this->buffer.data())->e_lfanew);
}

PIMAGE_SECTION_HEADER pe64::get_section(std::string sectionname) {

	auto first_section = IMAGE_FIRST_SECTION(this->get_nt());

	for (int i = 0; i < this->get_nt()->FileHeader.NumberOfSections; i++) {

		auto curr_section = &first_section[i];
		if (!_strnicmp(reinterpret_cast<const char*>(curr_section->Name), sectionname.c_str(), IMAGE_SIZEOF_SHORT_NAME))
			return curr_section;
	}

	return nullptr;
}

uint32_t pe64::align(uint32_t address, uint32_t alignment) const {
	if (alignment == 0)
		return address;
	uint32_t remainder = address % alignment;
	if (remainder == 0)
		return address;
	return address + (alignment - remainder);
}

PIMAGE_SECTION_HEADER pe64::create_section(std::string name, uint32_t size, uint32_t characteristic) {

	if (name.length() > IMAGE_SIZEOF_SHORT_NAME)
		throw std::runtime_error("section name can't be longer than 8 characters!");

	PIMAGE_NT_HEADERS nt = this->get_nt();
	PIMAGE_FILE_HEADER file_header = &nt->FileHeader;
	PIMAGE_OPTIONAL_HEADER optional_header = &nt->OptionalHeader;

	if (file_header->NumberOfSections == 0)
		throw std::runtime_error("PE has no sections; cannot append a new section!");

	if (file_header->NumberOfSections >= ObfuGuard::PE_MAX_SECTIONS)
		throw std::runtime_error("PE section count would exceed PE_MAX_SECTIONS limit!");

	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt);
	PIMAGE_SECTION_HEADER last_section = &section_header[file_header->NumberOfSections - 1];
	PIMAGE_SECTION_HEADER new_section_header =
		reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PUCHAR>(&last_section->Characteristics) + 4);

	// Ensure the new section header does not collide with the first section's raw data.
	const uint32_t file_alignment = optional_header->FileAlignment
		? optional_header->FileAlignment
		: ObfuGuard::PE_FILE_ALIGNMENT;
	const auto header_start = reinterpret_cast<uintptr_t>(this->buffer.data());
	const auto new_header_end = reinterpret_cast<uintptr_t>(new_section_header) + sizeof(IMAGE_SECTION_HEADER);
	const uint32_t needed_headers = this->align(
		static_cast<uint32_t>(new_header_end - header_start), file_alignment);
	if (section_header[0].PointerToRawData != 0 && needed_headers > section_header[0].PointerToRawData)
		throw std::runtime_error("insufficient PE header space for a new section header!");

	memset(new_section_header->Name, 0, IMAGE_SIZEOF_SHORT_NAME);
	memcpy(new_section_header->Name, name.c_str(), name.length());
	new_section_header->Misc.VirtualSize = align(size + sizeof(uint32_t) + 1, optional_header->SectionAlignment);
	new_section_header->VirtualAddress = align(last_section->VirtualAddress + last_section->Misc.VirtualSize, optional_header->SectionAlignment);
	new_section_header->SizeOfRawData = align(size + sizeof(uint32_t) + 1, optional_header->FileAlignment);
	new_section_header->PointerToRawData = align(last_section->PointerToRawData + last_section->SizeOfRawData, optional_header->FileAlignment);
	new_section_header->Characteristics = characteristic;
	new_section_header->PointerToRelocations = 0x0;
	new_section_header->PointerToLinenumbers = 0x0;
	new_section_header->NumberOfRelocations = 0x0;
	new_section_header->NumberOfLinenumbers = 0x0;

	file_header->NumberOfSections += 1;
	uint32_t old_size = optional_header->SizeOfImage;
	optional_header->SizeOfImage = align(optional_header->SizeOfImage + size + sizeof(uint32_t) + 1 + sizeof(IMAGE_SECTION_HEADER), optional_header->SectionAlignment);
	// Grow headers only if the new section table entry needs more room
	if (needed_headers > optional_header->SizeOfHeaders)
		optional_header->SizeOfHeaders = needed_headers;

	if (optional_header->SizeOfImage > ObfuGuard::MAX_PE_IMAGE_SIZE)
		throw std::runtime_error("PE SizeOfImage would exceed maximum allowed size after adding section!");

	std::vector<uint8_t> new_buffer;
	new_buffer.resize(optional_header->SizeOfImage);
	memset(new_buffer.data(), 0, optional_header->SizeOfImage);
	memcpy(new_buffer.data(), this->buffer.data(), old_size);
	this->buffer = new_buffer;

	return this->get_section(name);
}

void pe64::save_to_disk(std::string path, PIMAGE_SECTION_HEADER new_section, uint32_t total_size) {


	uint32_t size = this->align(total_size, this->get_nt()->OptionalHeader.SectionAlignment);

	uint32_t original_size = new_section->Misc.VirtualSize;
	new_section->SizeOfRawData = size;
	new_section->Misc.VirtualSize = size;

	if (size < original_size) {
		this->get_nt()->OptionalHeader.SizeOfImage -= (original_size - size);
	}

	uint32_t write_size = (std::min)(static_cast<uint32_t>(this->buffer.size()), this->get_nt()->OptionalHeader.SizeOfImage);

	std::ofstream file_stream(path.c_str(), std::ios_base::out | std::ios_base::binary);
	if (!file_stream)
		throw std::runtime_error("couldn't open output binary!");

	if (!file_stream.write(reinterpret_cast<const char*>(this->buffer.data()), write_size)) {
		throw std::runtime_error("couldn't write output binary!");
	}
}

std::string pe64::get_path() const {
	return this->path;
}
