#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libsdb/elf.hpp>
#include <libsdb/error.hpp>
#include <libsdb/bit.hpp>
#include <algorithm>
#include <cxxabi.h>
#include <libsdb/dwarf.hpp>

sdb::elf::elf(const std::filesystem::path& path) {
	path_ = path;

	if ((fd_ = open(path.c_str(), O_LARGEFILE, O_RDONLY)) < 0) {
		error::send_errno("Could not open ELF file");
	}

	struct stat stats;
	if (fstat(fd_, &stats) < 0) {
		error::send_errno("Could not retrieve ELF file stats");
	}
	file_size_ = stats.st_size;

	void* ret;
	if ((ret = mmap(0, file_size_, PROT_READ, MAP_SHARED, fd_, 0)) == MAP_FAILED) {
		close(fd_);
		error::send_errno("Could not mmap ELF file");
	}
	data_ = reinterpret_cast<std::byte*>(ret);

	std::copy(data_, data_ + sizeof(header_), as_bytes(header_));

	parse_section_headers();
	build_section_map();
	parse_symbol_table();
	build_symbol_maps();
	dwarf_ = std::make_unique<dwarf>(*this);
}

void sdb::elf::build_symbol_maps() {
	for (auto& symbol : symbol_table_) {
		auto mangled_name = get_string(symbol.st_name);
		int demangle_status;
		auto demangled_name = abi::__cxa_demangle(
			mangled_name.data(), nullptr, nullptr, &demangle_status);
		if (demangle_status == 0) {
			symbol_name_map_.insert({ demangled_name, &symbol });
			free(demangled_name);
		}
		symbol_name_map_.insert({ mangled_name, &symbol });


		if (symbol.st_value != 0 and 
			symbol.st_name != 0 and 
			symbol.st_info != STT_TLS) {
			auto addr_range = std::pair(
				file_addr{ *this, symbol.st_value },
				file_addr{ *this, symbol.st_value + symbol.st_size });
			symbol_addr_map_.insert({ addr_range, &symbol });
		}
	}
}

void sdb::elf::parse_symbol_table() {
	auto opt_symtab = get_section(".symtab");
	if (!opt_symtab) {
		opt_symtab = get_section(".dynsym");
		if (!opt_symtab) return;
	}

	auto symtab = *opt_symtab;
	symbol_table_.resize(symtab->sh_size / symtab->sh_entsize);
	std::copy(data_ + symtab->sh_offset,
		data_ + symtab->sh_offset + symtab->sh_size,
		reinterpret_cast<std::byte*>(symbol_table_.data()));
}

void sdb::elf::build_section_map() {
	for (auto& section : section_headers_) {
		section_map_[get_section_name(section.sh_name)] = &section;
	}
}

void sdb::elf::parse_section_headers() {
	auto n_headers = header_.e_shnum;
	if (n_headers == 0 and header_.e_shentsize != 0) {
		n_headers = from_bytes<Elf64_Shdr>(data_ + header_.e_shoff).sh_size;
	}

	section_headers_.resize(n_headers);
	std::copy(data_ + header_.e_shoff,
		data_ + header_.e_shoff + sizeof(Elf64_Shdr) * n_headers,
		reinterpret_cast<std::byte*>(section_headers_.data()));
}
sdb::elf::~elf() {
	munmap(data_, file_size_);
	close(fd_);
}

std::string_view sdb::elf::get_section_name(std::size_t index) const {
	auto& section = section_headers_[header_.e_shstrndx];
	return { reinterpret_cast<char*>(data_) + section.sh_offset + index };
}

std::optional<const Elf64_Shdr*>
sdb::elf::get_section(std::string_view name) const {
	if (section_map_.count(name) == 0) {
		return std::nullopt;
	}
	return section_map_.at(name);
}

sdb::span<const std::byte>
sdb::elf::get_section_contents(std::string_view name) const {
	if (auto sect = get_section(name); sect) {
		return { data_ + sect.value()->sh_offset, sect.value()->sh_size };
	}
	return { nullptr, std::size_t(0) };
}

std::string_view sdb::elf::get_string(std::size_t index) const {
	auto opt_strtab = get_section(".strtab");
	if (!opt_strtab) {
		opt_strtab = get_section(".dynstr");
		if (!opt_strtab) return "";
	}
	return {
		reinterpret_cast<char*>(data_) + opt_strtab.value()->sh_offset + index
	};
}

const Elf64_Shdr* sdb::elf::get_section_containing_address(
	file_addr addr) const {
	if (addr.elf_file() != this) return nullptr;
	for (auto& section : section_headers_) {
		if (section.sh_addr <= addr.addr() and
			section.sh_addr + section.sh_size > addr.addr()) {
			return &section;
		}
	}
	return nullptr;
}

const Elf64_Shdr* sdb::elf::get_section_containing_address(virt_addr addr) const {
	for (auto& section : section_headers_) {
		if (load_bias_ + section.sh_addr <= addr and
			load_bias_ + section.sh_addr + section.sh_size > addr) {
			return &section;
		}
	}
	return nullptr;
}

std::optional<sdb::file_addr> sdb::elf::get_section_start_address(
	std::string_view name) const {
	if (auto sect = get_section(name); sect) {
		return file_addr{ *this, sect.value()->sh_addr };
	}
	return std::nullopt;
}

std::vector<const Elf64_Sym*>
sdb::elf::get_symbols_by_name(std::string_view name) const {
	auto [begin, end] = symbol_name_map_.equal_range(name);

	std::vector<const Elf64_Sym*> ret;
	std::transform(begin, end, std::back_inserter(ret),
		[](auto& pair) { return pair.second; });
	return ret;
}

std::optional<const Elf64_Sym*>
sdb::elf::get_symbol_at_address(file_addr address) const {
	if (address.elf_file() != this) return std::nullopt;
	file_addr null_addr;
	auto it = symbol_addr_map_.find({ address, null_addr });
	if (it == end(symbol_addr_map_)) return std::nullopt;

	return it->second;
}

std::optional<const Elf64_Sym*>
sdb::elf::get_symbol_at_address(virt_addr address) const {
	return get_symbol_at_address(address.to_file_addr(*this));
}

std::optional<const Elf64_Sym*>
sdb::elf::get_symbol_containing_address(file_addr address) const {
	if (address.elf_file() != this or symbol_addr_map_.empty())
		return std::nullopt;

	file_addr null_addr;
	auto it = symbol_addr_map_.lower_bound({ address, null_addr });

	if (it != end(symbol_addr_map_)) {
		if (auto [key, value] = *it; key.first == address) {
			return value;
		}
	}

	if (it == begin(symbol_addr_map_)) return std::nullopt;

	--it;
	if (auto [key, value] = *it;
		key.first < address and key.second > address) {
		return value;
	}

	return std::nullopt;
}

std::optional<const Elf64_Sym*>
sdb::elf::get_symbol_containing_address(virt_addr address) const {
	return get_symbol_containing_address(address.to_file_addr(*this));
}