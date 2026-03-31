#pragma once

/// Lazy PE import table views.
///
///   import_symbol_ref<Traits>  — proxy to one imported function (thunk entry)
///   import_module_ref<Traits>  — proxy to one imported DLL (IMAGE_IMPORT_DESCRIPTOR)
///   import_range<Traits>       — iterable range over all imported modules
///
/// All RVA resolution is done through rva_resolver, which performs bounds
/// checking to prevent malicious PE files from causing overflows (1ee0be8).

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <coffi/core/byte_view.hpp>
#include <coffi/platform/schema.hpp>
#include <coffi/views/rva_resolver.hpp>

namespace coffi {

// ================================================================
//  import_symbol_ref — one imported function
// ================================================================

template <typename Traits>
class import_symbol_ref {
    const rva_resolver* resolver_;
    uint32_t            thunk_rva_;

    [[nodiscard]] typename Traits::address_type thunk_value() const noexcept {
        auto v = resolver_->to_view(thunk_rva_, Traits::thunk_size);
        if (!v) return 0;
        typename Traits::address_type val{};
        std::memcpy(&val, v->data(), Traits::thunk_size);
        return val;
    }

public:
    import_symbol_ref(const rva_resolver* res, uint32_t rva) noexcept
        : resolver_(res), thunk_rva_(rva) {}

    [[nodiscard]] bool is_ordinal() const noexcept {
        return (thunk_value() & Traits::ordinal_flag) != 0;
    }

    [[nodiscard]] uint16_t ordinal() const noexcept {
        return static_cast<uint16_t>(thunk_value() & 0xFFFF);
    }

    [[nodiscard]] std::string_view name() const noexcept {
        if (is_ordinal()) return {};
        auto rva = static_cast<uint32_t>(thunk_value());
        // Points to IMAGE_IMPORT_BY_NAME: skip 2-byte hint, then name
        auto res = resolver_->read_string(rva + sizeof(uint16_t));
        return res ? *res : std::string_view{};
    }

    [[nodiscard]] uint16_t hint() const noexcept {
        if (is_ordinal()) return 0;
        auto rva = static_cast<uint32_t>(thunk_value());
        auto v = resolver_->to_view(rva, sizeof(uint16_t));
        if (!v) return 0;
        uint16_t h;
        std::memcpy(&h, v->data(), sizeof(h));
        return h;
    }
};

// ================================================================
//  import_symbol_range — thunk chain for one DLL
// ================================================================

template <typename Traits>
class import_symbol_range {
    const rva_resolver* resolver_;
    uint32_t            first_thunk_;

public:
    class iterator {
        const rva_resolver* resolver_;
        uint32_t            current_;
        bool                done_ = false;

        void check() {
            if (!resolver_) { done_ = true; return; }
            auto v = resolver_->to_view(current_, Traits::thunk_size);
            if (!v) { done_ = true; return; }
            typename Traits::address_type val{};
            std::memcpy(&val, v->data(), Traits::thunk_size);
            if (val == 0) done_ = true;
        }

    public:
        using difference_type   = std::ptrdiff_t;
        using value_type        = import_symbol_ref<Traits>;
        using pointer           = void;
        using reference         = value_type;
        using iterator_category = std::input_iterator_tag;

        iterator() : resolver_(nullptr), current_(0), done_(true) {}
        iterator(const rva_resolver* r, uint32_t rva) noexcept
            : resolver_(r), current_(rva) { check(); }

        value_type operator*() const { return {resolver_, current_}; }
        iterator& operator++() {
            current_ += static_cast<uint32_t>(Traits::thunk_size);
            check();
            return *this;
        }
        iterator operator++(int) { auto t = *this; ++(*this); return t; }
        bool operator==(const iterator& o) const noexcept {
            if (done_ && o.done_) return true;
            if (done_ != o.done_) return false;
            return current_ == o.current_;
        }
        bool operator!=(const iterator& o) const noexcept { return !(*this == o); }
    };

    import_symbol_range(const rva_resolver* r, uint32_t first) noexcept
        : resolver_(r), first_thunk_(first) {}

    [[nodiscard]] iterator begin() const { return {resolver_, first_thunk_}; }
    [[nodiscard]] iterator end()   const { return {}; }
};

// ================================================================
//  import_module_ref — one imported DLL
// ================================================================

template <typename Traits>
class import_module_ref {
    const rva_resolver*       resolver_;
    image_import_descriptor   desc_;

public:
    import_module_ref(const rva_resolver* r, image_import_descriptor d) noexcept
        : resolver_(r), desc_(d) {}

    [[nodiscard]] std::string_view dll_name() const noexcept {
        auto s = resolver_->read_string(desc_.name);
        return s ? *s : std::string_view{};
    }

    [[nodiscard]] import_symbol_range<Traits> symbols() const noexcept {
        uint32_t rva = desc_.original_first_thunk;
        if (rva == 0) rva = desc_.first_thunk;
        return {resolver_, rva};
    }

    [[nodiscard]] uint32_t time_date_stamp() const noexcept { return desc_.time_date_stamp; }
    [[nodiscard]] uint32_t forwarder_chain() const noexcept { return desc_.forwarder_chain; }
};

// ================================================================
//  import_range — all imported modules
// ================================================================

template <typename Traits>
class import_range {
    const rva_resolver* resolver_;
    uint32_t            idt_rva_;
    uint32_t            idt_size_;

public:
    class iterator {
        const rva_resolver*       resolver_;
        uint32_t                  current_;
        uint32_t                  remaining_;
        bool                      done_ = false;
        image_import_descriptor   desc_{};

        void fetch() {
            if (!resolver_ || remaining_ < sizeof(image_import_descriptor)) {
                done_ = true; return;
            }
            auto v = resolver_->to_view(current_, sizeof(image_import_descriptor));
            if (!v) { done_ = true; return; }
            std::memcpy(&desc_, v->data(), sizeof(desc_));
            // Null terminator: all fields zero
            if (desc_.original_first_thunk == 0 && desc_.time_date_stamp == 0 &&
                desc_.forwarder_chain == 0 && desc_.name == 0 && desc_.first_thunk == 0)
                done_ = true;
        }

    public:
        using difference_type   = std::ptrdiff_t;
        using value_type        = import_module_ref<Traits>;
        using pointer           = void;
        using reference         = value_type;
        using iterator_category = std::input_iterator_tag;

        iterator() : resolver_(nullptr), current_(0), remaining_(0), done_(true) {}
        iterator(const rva_resolver* r, uint32_t rva, uint32_t size) noexcept
            : resolver_(r), current_(rva), remaining_(size) { fetch(); }

        value_type operator*() const { return {resolver_, desc_}; }
        iterator& operator++() {
            current_ += static_cast<uint32_t>(sizeof(image_import_descriptor));
            remaining_ = (remaining_ >= sizeof(image_import_descriptor))
                       ? (remaining_ - static_cast<uint32_t>(sizeof(image_import_descriptor)))
                       : 0;
            fetch();
            return *this;
        }
        iterator operator++(int) { auto t = *this; ++(*this); return t; }
        bool operator==(const iterator& o) const noexcept { return done_ == o.done_; }
        bool operator!=(const iterator& o) const noexcept { return done_ != o.done_; }
    };

    import_range(const rva_resolver* r, uint32_t rva, uint32_t size) noexcept
        : resolver_(r), idt_rva_(rva), idt_size_(size) {}

    [[nodiscard]] iterator begin() const { return {resolver_, idt_rva_, idt_size_}; }
    [[nodiscard]] iterator end()   const { return {}; }
    [[nodiscard]] bool     empty() const noexcept { return idt_rva_ == 0 || idt_size_ == 0; }
};

} // namespace coffi
