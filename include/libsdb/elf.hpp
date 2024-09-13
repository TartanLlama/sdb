#ifndef SDB_ELF_HPP
#define SDB_ELF_HPP

#include <filesystem>
#include <elf.h>
#include <vector>
#include <string_view>
#include <unordered_map>
#include <optional>
#include <libsdb/types.hpp>
#include <map>

namespace sdb {
    class dwarf;
    class elf {
    public:
        elf(const std::filesystem::path& path);
        ~elf();

        elf(const elf&) = delete;
        elf& operator=(const elf&) = delete;

        std::filesystem::path path() const { return path_; }
        const Elf64_Ehdr& get_header() const { return header_; }

        void parse_section_headers();
        std::string_view get_section_name(std::size_t index) const;

        std::optional<const Elf64_Shdr*>
            get_section(std::string_view name) const;
        span<const std::byte> get_section_contents(std::string_view name) const;

        std::string_view get_string(std::size_t index) const;

        virt_addr load_bias() const {
            return load_bias_;
        }
        void notify_loaded(virt_addr address) {
            load_bias_ = address;
        }

        const Elf64_Shdr* get_section_containing_address(
            file_addr addr) const;
        const Elf64_Shdr* get_section_containing_address(
            virt_addr addr) const;

        std::optional<file_addr> get_section_start_address(
            std::string_view name) const;

        std::vector<const Elf64_Sym*> get_symbols_by_name(
            std::string_view name) const;

        std::optional<const Elf64_Sym*> get_symbol_at_address(
            file_addr addr) const;
        std::optional<const Elf64_Sym*> get_symbol_at_address(
            virt_addr addr) const;

        std::optional<const Elf64_Sym*> get_symbol_containing_address(
            file_addr addr) const;
        std::optional<const Elf64_Sym*> get_symbol_containing_address(
            virt_addr addr) const;

        dwarf& get_dwarf() { return *dwarf_; }
        const dwarf& get_dwarf() const { return *dwarf_; }

        file_offset data_pointer_as_file_offset(const std::byte* ptr) const {
            return { *this, ptr - data_ };
        }
        const std::byte* file_offset_as_data_pointer(file_offset offset) const {
            return data_ + offset.off();
        }

    private:
        void build_section_map();
        void parse_symbol_table();
        void build_symbol_maps();

        int fd_;
        std::filesystem::path path_;
        std::size_t file_size_;
        std::byte* data_;
        Elf64_Ehdr header_;
        std::vector<Elf64_Shdr> section_headers_;
        std::unordered_map<std::string_view, Elf64_Shdr*> section_map_;
        virt_addr load_bias_;
        std::vector<Elf64_Sym> symbol_table_;
        std::unordered_multimap<std::string_view, Elf64_Sym*>
            symbol_name_map_;

        struct range_comparator {
            bool operator()(
                std::pair<file_addr, file_addr> lhs,
                std::pair<file_addr, file_addr> rhs) const {
                return lhs.first < rhs.first;
            }
        };
        std::map<std::pair<file_addr, file_addr>, Elf64_Sym*, range_comparator>
            symbol_addr_map_;
        std::unique_ptr<dwarf> dwarf_;
    };
}

#endif