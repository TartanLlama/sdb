#ifndef SDB_DWARF_HPP
#define SDB_DWARF_HPP

#include <libsdb/detail/dwarf.h>
#include <libsdb/types.hpp>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <memory>
#include <string_view>
#include <optional>
#include <string>
#include <filesystem>

namespace sdb {
	class compile_unit;
	class die;

	class range_list {
	public:
		range_list(
			const compile_unit* cu, span<const std::byte> data,
			file_addr base_address)
			: cu_(cu), data_(data), base_address_(base_address) {}

		struct entry {
			file_addr low;
			file_addr high;

			bool contains(file_addr addr) const {
				return low <= addr and addr < high;
			}
		};

		class iterator;
		iterator begin() const;
		iterator end() const;

		bool contains(file_addr address) const;

	private:
		const compile_unit* cu_;
		span<const std::byte> data_;
		file_addr base_address_;
	};

	class range_list::iterator {
	public:
		using value_type = entry;
		using reference = const entry&;
		using pointer = const entry*;
		using difference_type = std::ptrdiff_t;
		using iterator_category = std::forward_iterator_tag;

		iterator(
			const compile_unit* cu,
			span<const std::byte> data,
			file_addr base_address);

		iterator() = default;
		iterator(const iterator&) = default;
		iterator& operator=(const iterator&) = default;

		const entry& operator*() const { return current_; }
		const entry* operator->() const { return &current_; }

		bool operator==(iterator rhs) const { return pos_ == rhs.pos_; }
		bool operator!=(iterator rhs) const { return pos_ != rhs.pos_; }

		iterator& operator++();
		iterator operator++(int);

	private:
		const compile_unit* cu_ = nullptr;
		span<const std::byte> data_{ nullptr,nullptr };
		file_addr base_address_;
		const std::byte* pos_ = nullptr;
		entry current_;
	};

	class attr {
	public:
		attr(const compile_unit* cu, std::uint64_t type,
			std::uint64_t form, const std::byte* location) :
			cu_(cu), type_(type), form_(form), location_(location) {}

		std::uint64_t name() const { return type_; }
		std::uint64_t form() const { return form_; }

		file_addr as_address() const;
		std::uint32_t as_section_offset() const;
		span<const std::byte> as_block() const;
		std::uint64_t as_int() const;
		std::string_view as_string() const;
		die as_reference() const;
		range_list as_range_list() const;

	private:
		const compile_unit* cu_;
		std::uint64_t type_;
		std::uint64_t form_;
		const std::byte* location_;
	};

	class elf;
	struct attr_spec {
		std::uint64_t attr;
		std::uint64_t form;
	};
	struct abbrev {
		std::uint64_t code;
		std::uint64_t tag;
		bool has_children;
		std::vector<attr_spec> attr_specs;
	};

	class dwarf;

	class line_table {
	public:
		struct file {
			std::filesystem::path path;
			std::uint64_t modification_time;
			std::uint64_t file_length;
		};

		line_table(sdb::span<const std::byte> data,
			const compile_unit* cu,
			bool default_is_stmt, std::int8_t line_base,
			std::uint8_t line_range, std::uint8_t opcode_base,
			std::vector<std::filesystem::path> include_directories,
			std::vector<file> file_names)
			: data_(data), cu_(cu)
			, default_is_stmt_(default_is_stmt)
			, line_base_(line_base)
			, line_range_(line_range)
			, opcode_base_(opcode_base)
			, include_directories_(std::move(include_directories))
			, file_names_(std::move(file_names))
		{}

		const compile_unit& cu() const { return *cu_; }
		const std::vector<file>& file_names() const { return file_names_; }

		line_table(const line_table&) = delete;
		line_table& operator=(const line_table&) = delete;

		struct entry;

		class iterator;

		iterator begin() const;
		iterator end() const;

		iterator get_entry_by_address(file_addr address) const;
		std::vector<iterator> get_entries_by_line(
			std::filesystem::path path, std::size_t line) const;

	private:
		sdb::span<const std::byte> data_;
		const compile_unit* cu_;
		bool default_is_stmt_;
		std::int8_t line_base_;
		std::uint8_t line_range_;
		std::uint8_t opcode_base_;
		std::vector<std::filesystem::path> include_directories_;
		mutable std::vector<file> file_names_;
	};

	struct line_table::entry {
		bool operator==(const entry& rhs) const {
			return address == rhs.address and
				file_index == rhs.file_index and
				line == rhs.line and
				column == rhs.column and
				discriminator == rhs.discriminator;
		}

		file_addr address;
		std::uint64_t file_index = 1;
		std::uint64_t line = 1;
		std::uint64_t column = 0;
		bool is_stmt;
		bool basic_block_start = false;
		bool end_sequence = false;
		bool prologue_end = false;
		bool epilogue_begin = false;
		std::uint64_t discriminator = 0;
		file* file_entry = nullptr;
	};

	class line_table::iterator {
	public:
		using value_type = entry;
		using pointer = const entry*;
		using reference = const entry&;
		using difference_type = std::ptrdiff_t;
		using iterator_category = std::forward_iterator_tag;

		iterator(const line_table* table_);

		iterator() = default;
		iterator(const iterator&) = default;
		iterator& operator=(const iterator&) = default;

		const line_table::entry& operator*() const { return current_; }
		const line_table::entry* operator->() const { return &current_; }

		bool operator==(const iterator& rhs) const { return pos_ == rhs.pos_; }
		bool operator!=(const iterator& rhs) const { return pos_ != rhs.pos_; }

		iterator& operator++();
		iterator operator++(int);

	private:
		bool execute_instruction();

		const line_table* table_;
		line_table::entry current_;
		line_table::entry registers_;
		const std::byte* pos_;
	};



	class die;
	class compile_unit {
	public:
		compile_unit(dwarf& parent,
			span<const std::byte> data,
			std::size_t abbrev);

		const dwarf* dwarf_info() const { return parent_; }
		span<const std::byte> data() const { return data_; }

		const std::unordered_map<std::uint64_t, sdb::abbrev>&
			abbrev_table() const;

		die root() const;
		const line_table& lines() const { return *line_table_; }
	private:
		dwarf* parent_;
		span<const std::byte> data_;
		std::size_t abbrev_offset_;
		std::unique_ptr<line_table> line_table_;
	};

	struct source_location {
		const line_table::file* file;
		std::uint64_t line;
	};
	class die {
	public:
		explicit die(const std::byte* next) : next_(next) {}
		die(const std::byte* pos, const compile_unit* cu, const abbrev* abbrev,
			std::vector<const std::byte*> attr_locs, const std::byte* next) :
			pos_(pos), cu_(cu), abbrev_(abbrev),
			attr_locs_(std::move(attr_locs)), next_(next) {}

		const compile_unit* cu() const { return cu_; }
		const abbrev* abbrev_entry() const { return abbrev_; }
		const std::byte* position() const { return pos_; }
		const std::byte* next() const { return next_; }

		class children_range;
		children_range children() const;

		bool contains(std::uint64_t attribute) const;
		attr operator[](std::uint64_t attribute) const;

		file_addr low_pc() const;
		file_addr high_pc() const;

		bool contains_address(file_addr address) const;

		std::optional<std::string_view> name() const;

		source_location location() const;
		const line_table::file& file() const;
		std::uint64_t line() const;

	private:
		const std::byte* pos_ = nullptr;
		const compile_unit* cu_ = nullptr;
		const abbrev* abbrev_ = nullptr;
		const std::byte* next_ = nullptr;
		std::vector<const std::byte*> attr_locs_;
	};

	class die::children_range {
	public:
		children_range(const die die) : die_(std::move(die)) {}
		class iterator {
		public:
			using value_type = die;
			using reference = const die&;
			using pointer = const die*;
			using difference_type = std::ptrdiff_t;
			using iterator_category = std::forward_iterator_tag;

			iterator() = default;
			iterator(const iterator&) = default;
			iterator& operator=(const iterator&) = default;

			explicit iterator(const die& die);

			const die& operator*() const { return *die_; }
			const die* operator->() const { return &die_.value(); }

			iterator& operator++();
			iterator operator++(int);

			bool operator==(const iterator& rhs) const;
			bool operator!=(const iterator& rhs) const {
				return !(*this == rhs);
			}
		private:
			std::optional<die> die_;
		};

		iterator begin() const {
			if (die_.abbrev_->has_children) {
				return iterator{ die_ };
			}
			return end();
		}
		iterator end() const { return iterator{}; }
	private:
		die die_;
	};

	class dwarf {
	public:
		dwarf(const elf& parent);
		const elf* elf_file() const { return elf_; }
		const std::unordered_map<std::uint64_t, abbrev>& get_abbrev_table(
			std::size_t offset);
		const std::vector<std::unique_ptr<compile_unit>>&
			compile_units() const { return compile_units_; }

		const compile_unit* compile_unit_containing_address(
			file_addr address) const;
		std::optional<die> function_containing_address(
			file_addr address) const;

		std::vector<die> find_functions(std::string name) const;

		line_table::iterator line_entry_at_address(file_addr address) const {
			auto cu = compile_unit_containing_address(address);
			if (!cu) return {};
			return cu->lines().get_entry_by_address(address);
		}

		std::vector<die> inline_stack_at_address(file_addr address) const;

	private:
		void index() const;
		void index_die(const die& current) const;

		const elf* elf_;
		std::unordered_map<std::size_t,
			std::unordered_map<std::uint64_t, abbrev>> abbrev_tables_;
		std::vector<std::unique_ptr<compile_unit>> compile_units_;

		struct index_entry {
			const compile_unit* cu;
			const std::byte* pos;
		};
		mutable std::unordered_multimap<std::string, index_entry>
			function_index_;
	};
}

#endif