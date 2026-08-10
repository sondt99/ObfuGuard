#include "function_filter.h"
#include "../constants.h"

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <sstream>
#include <limits>
#include <filesystem>
#include <fstream>
#include <mutex>

namespace ObfuGuard {

// Built-in defaults used when no external blacklist file is available
static const std::set<std::string> BUILTIN_DANGEROUS_FUNCTION_NAMES = {
    "mainCRTStartup","atexit",
    "__scrt_initialize_onexit_tables",
    "__scrt_dllmain_before_initialize",
    "_initterm",
    "_initterm_e",
    "__C_specific_handler",
    "_chkstk",
    "__security_check_cookie",
    "__GSHandlerCheck",
    "__isa_available_init",
    "pre_c_initialization","DebuggerRuntime",
    "pre_cpp_initialization","operator new","operator delete","failwithmessage",
    "exit", "fget", "fwrite", "memcpy", "memmove", "memset", "malloc", "free",
    "fread", "fclose", "fopen", "fprintf", "printf", "sprintf", "snprintf",
    "strcpy", "strncpy", "strcat", "strncat", "strlen", "strcmp", "strncmp",
    "fgetc", "fgets", "fputc", "fputs", "vfprintf", "vprintf", "vsprintf", "fgetpos", "fsetpos", "fegetenv",
    "srand", "rand", "time", "localtime", "gmtime", "asctime", "ctime",
    "clock", "ceil", "wcsnlen", "strpbrk", "GetLocaleNameFromLanguage", "strcspn", "memcmp", "qsort",
};

static const std::set<std::string> BUILTIN_DANGEROUS_FUNCTION_NAMES_BIG_BINARY = {
    "detect_pe_architecture", "main", "pe64::pe64", "pdbparser::pdbparser",
    "obfuscatecff::obfuscatecff", "obfuscatecff::run", "obfuscatecff::compile", "obfuscatecff::~obfuscatecff",
    "TrampolineInjector::TrampolineInjector", "TrampolineInjector::~TrampolineInjector",
    "FuncToRVA::RVAResolver::initialize", "FuncToRVA::RVAResolver::RVAResolver", "FuncToRVA::RVAResolver::~RVAResolver",
    "terminate", "raise", "raise$fin$0", "std::setw", "ceilf", "InternalCompareStringA", "InternalGetLocaleInfoA",
    "std::filesystem::exists", "std::filesystem::path::path", "std::filesystem::path::operator/=",
    "std::filesystem::path::string", "std::filesystem::operator/",
    "std::vector<unsigned char,std::allocator<unsigned char> >::vector<unsigned char,std::allocator<unsigned char> >",
    "std::vector<unsigned char,std::allocator<unsigned char> >::resize",
    "std::vector<unsigned int,std::allocator<unsigned int> >::operator=",
    "std::exception::exception", "std::exception::what",
    "strrchr", "srand", "CountryEnumProc","LangCountryEnumProc", "LangCountryEnumProcEx",
    "strnlen", "strtol","strtoul","wcschr","wcscmp","wcsncmp","wcspbrk","isdigit","islower","isupper",
    "GetLcidFromLanguage","GetLcidFromLangCountry","TranslateName","TestDefaultLanguage","setSBCS",
    "setSBUpLow","setvbuf","getSystemCP","ExFilterRethrow","ExFilterRethrowFH4",
    "fallbackMethod","FH4::HandlerMap4::HandlerMap4","FH4::HandlerMap4::DecompHandler",
    "FH4::TryBlockMap4::TryBlockMap4","FH4::TryBlockMap4::setBuffer",
    "FH4::UWMap4::ReadEntry","FH4::UWMap4::getStateFromIterators","FH4::UWMap4::getStartStop","IsInExceptionSpec",
};

static const std::vector<std::string> DANGEROUS_PREFIXES = {
    "??_",
};

// Runtime-loaded names (merged from file + defaults)
static std::set<std::string> g_dangerous_names;
static std::set<std::string> g_dangerous_names_big_binary;
static std::once_flag g_blacklist_init_flag;
static bool g_file_loaded = false;

static void init_defaults() {
    g_dangerous_names = BUILTIN_DANGEROUS_FUNCTION_NAMES;
    g_dangerous_names_big_binary = BUILTIN_DANGEROUS_FUNCTION_NAMES_BIG_BINARY;
}

bool load_blacklist_file(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) {
        return false;
    }

    // Ensure defaults exist before merging file entries
    std::call_once(g_blacklist_init_flag, init_defaults);

    std::string line;
    size_t loaded = 0;
    while (std::getline(in, line)) {
        // Trim whitespace
        auto start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        auto end = line.find_last_not_of(" \t\r\n");
        line = line.substr(start, end - start + 1);

        if (line.empty() || line[0] == '#') continue;

        // Optional section markers: [big] for large-binary-only names
        if (line == "[big]" || line == "[big_binary]") {
            // Subsequent names go to big-binary set until next section
            // Simple mode: treat all non-section lines as standard blacklist;
            // big-binary names can be prefixed with "big:"
            continue;
        }
        if (line.rfind("big:", 0) == 0) {
            g_dangerous_names_big_binary.insert(line.substr(4));
            ++loaded;
            continue;
        }

        g_dangerous_names.insert(line);
        ++loaded;
    }

    if (loaded > 0) {
        g_file_loaded = true;
        std::cout << "Loaded " << loaded << " blacklist entries from: " << path << std::endl;
    }
    return loaded > 0 || in.eof();
}

void ensure_blacklist_loaded(const std::string& binary_path) {
    std::call_once(g_blacklist_init_flag, init_defaults);

    if (g_file_loaded) return;

    // Candidate paths: CWD, next to target binary, and common relative locations
    std::vector<std::filesystem::path> candidates = {
        "blacklist_default.txt",
        "ObfuGuard/blacklist_default.txt",
        std::filesystem::path("..") / "ObfuGuard" / "blacklist_default.txt",
    };

    if (!binary_path.empty()) {
        std::filesystem::path bp(binary_path);
        candidates.push_back(bp.parent_path() / "blacklist_default.txt");
        candidates.push_back(bp.parent_path() / "ObfuGuard" / "blacklist_default.txt");
    }

    for (const auto& cand : candidates) {
        std::error_code ec;
        if (std::filesystem::exists(cand, ec) && std::filesystem::is_regular_file(cand, ec)) {
            if (load_blacklist_file(cand.string())) {
                return;
            }
        }
    }
    // No file found: built-in defaults already initialized
}

static bool is_binary_large(const std::string& binary_path) {
    try {
        std::filesystem::path fp(binary_path);
        if (!std::filesystem::exists(fp)) return false;
        return std::filesystem::file_size(fp) > LARGE_BINARY_SIZE_THRESHOLD;
    } catch (const std::filesystem::filesystem_error&) {
        return false;
    }
}

bool is_function_blacklisted(const std::string& func_name) {
    ensure_blacklist_loaded();
    // MSVC special/RTTI names contain backticks; CRT internals usually lead with '_'
    // Do NOT ban mid-name underscores (would exclude user functions like sum_to_n).
    if (func_name.find('`') != std::string::npos) return true;
    if (func_name.rfind('_', 0) == 0) return true;
    if (g_dangerous_names.count(func_name)) return true;
    for (const auto& prefix : DANGEROUS_PREFIXES) {
        if (func_name.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

bool is_function_blacklisted_by_binary_size(const std::string& func_name, const std::string& binary_path) {
    ensure_blacklist_loaded(binary_path);
    if (is_function_blacklisted(func_name)) return true;
    if (is_binary_large(binary_path) && g_dangerous_names_big_binary.count(func_name) > 0) return true;
    return false;
}

std::vector<FunctionInfo> filter_functions(
    const std::vector<FunctionInfo>& all_functions,
    const std::string& binary_path,
    uint32_t min_size)
{
    ensure_blacklist_loaded(binary_path);
    std::vector<FunctionInfo> result;
    for (const auto& f : all_functions) {
        if (f.size < min_size) continue;
        if (is_function_blacklisted_by_binary_size(f.name, binary_path)) continue;
        result.push_back(f);
    }
    return result;
}

void sort_functions_by_size_desc(std::vector<FunctionInfo>& functions) {
    std::sort(functions.begin(), functions.end(),
        [](const FunctionInfo& a, const FunctionInfo& b) { return a.size > b.size; });
}

static void display_function_table(const std::vector<FunctionInfo>& functions) {
    std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;
    std::cout << std::setw(7) << "No." << " | "
        << std::setw(12) << "RVA (Hex)" << " | "
        << std::setw(12) << "Offset (Hex)" << " | "
        << std::setw(10) << "Size" << " | "
        << "Function Name" << std::endl;
    std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;

    for (size_t i = 0; i < functions.size(); ++i) {
        const auto& f = functions[i];
        std::cout << std::setw(7) << std::left << i + 1 << " | "
            << "0x" << std::hex << std::setw(10) << std::left << f.rva << " | "
            << "0x" << std::hex << std::setw(10) << std::left << f.pdb_offset << " | "
            << std::dec << std::setw(10) << std::left << f.size << " | "
            << f.name << std::endl;
    }
    std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;
}

bool select_functions_interactive(
    const std::vector<FunctionInfo>& all_functions,
    std::vector<uint32_t>& out_rvas,
    std::vector<std::string>& out_names)
{
    if (all_functions.empty()) {
        std::cout << "No functions available to select." << std::endl;
        return false;
    }

    std::cout << "\nAvailable functions:" << std::endl;
    display_function_table(all_functions);

    std::string input_str;
    while (true) {
        std::cout << "Select functions by No. (comma-separated, e.g., '1,3,5' or enter 0 to cancel): ";
        if (!std::getline(std::cin, input_str) || input_str.empty()) {
            std::cout << "Invalid input." << std::endl;
            continue;
        }

        if (input_str == "0") {
            std::cout << "Selection cancelled." << std::endl;
            return false;
        }

        std::vector<int> choices;
        std::stringstream ss(input_str);
        std::string token;
        bool valid = true;

        while (std::getline(ss, token, ',')) {
            token.erase(0, token.find_first_not_of(" \t"));
            token.erase(token.find_last_not_of(" \t") + 1);
            try {
                int choice = std::stoi(token);
                if (choice <= 0 || static_cast<size_t>(choice) > all_functions.size()) {
                    std::cout << "Invalid No. " << choice << std::endl;
                    valid = false;
                    break;
                }
                choices.push_back(choice);
            } catch (const std::exception&) {
                std::cout << "Invalid input: '" << token << "'" << std::endl;
                valid = false;
                break;
            }
        }

        if (!valid || choices.empty()) continue;

        std::sort(choices.begin(), choices.end());
        choices.erase(std::unique(choices.begin(), choices.end()), choices.end());

        out_rvas.clear();
        out_names.clear();
        std::cout << "\nSelected functions:" << std::endl;
        for (int choice : choices) {
            const auto& f = all_functions[choice - 1];
            out_rvas.push_back(f.rva);
            out_names.push_back(f.name);
            std::cout << "  " << choice << ". " << f.name
                << " (RVA: 0x" << std::hex << f.rva << std::dec << ")" << std::endl;
        }
        std::cout << "Total selected: " << choices.size() << " function(s)" << std::endl;
        return true;
    }
}

} // namespace ObfuGuard
