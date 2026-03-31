#pragma once

/// Composable lazy range adaptors for C++17.
/// Provides filter, transform, take_while via pipe (|) syntax,
/// enabling expression-template-like lazy evaluation:
///
///   file.sections() | coffi::filter([](auto s){ return s.is_code(); })
///                   | coffi::transform([](auto s){ return s.name(); });

#include <optional>
#include <type_traits>
#include <utility>

namespace coffi {

// ============================================================
//  Pipe infrastructure
// ============================================================

namespace detail {

template <typename F>
struct pipeable {
    F func;
    explicit constexpr pipeable(F f) : func(std::move(f)) {}
};

template <typename F>
pipeable(F) -> pipeable<F>;

template <typename Range, typename F>
constexpr auto operator|(Range&& range, const pipeable<F>& p) {
    return p.func(std::forward<Range>(range));
}

} // namespace detail

// ============================================================
//  filter_view
// ============================================================

template <typename Range, typename Pred>
class filter_view {
    Range range_;
    Pred  pred_;

public:
    class iterator {
        using base_t = decltype(std::declval<const Range&>().begin());
        base_t      cur_;
        base_t      end_;
        const Pred* pred_;

        void skip() { while (cur_ != end_ && !(*pred_)(*cur_)) ++cur_; }

    public:
        using difference_type   = std::ptrdiff_t;
        using value_type        = std::decay_t<decltype(*std::declval<base_t>())>;
        using pointer           = const value_type*;
        using reference         = decltype(*std::declval<base_t>());
        using iterator_category = std::input_iterator_tag;

        iterator() = default;
        iterator(base_t cur, base_t end, const Pred* p)
            : cur_(cur), end_(end), pred_(p) { skip(); }

        reference operator*()  const { return *cur_; }
        iterator& operator++()       { ++cur_; skip(); return *this; }
        iterator  operator++(int)    { auto t = *this; ++(*this); return t; }
        bool operator==(const iterator& o) const { return cur_ == o.cur_; }
        bool operator!=(const iterator& o) const { return cur_ != o.cur_; }
    };

    filter_view(Range r, Pred p) : range_(std::move(r)), pred_(std::move(p)) {}

    [[nodiscard]] iterator begin() const { return {range_.begin(), range_.end(), &pred_}; }
    [[nodiscard]] iterator end()   const { return {range_.end(),   range_.end(), &pred_}; }
};

template <typename Range, typename Pred>
filter_view(Range, Pred) -> filter_view<Range, Pred>;

template <typename Pred>
[[nodiscard]] constexpr auto filter(Pred pred) {
    return detail::pipeable{[p = std::move(pred)](auto&& r) {
        return filter_view{std::forward<decltype(r)>(r), p};
    }};
}

// ============================================================
//  transform_view
// ============================================================

template <typename Range, typename Func>
class transform_view {
    Range range_;
    Func  func_;

public:
    class iterator {
        using base_t = decltype(std::declval<const Range&>().begin());
        base_t      cur_;
        const Func* func_;

    public:
        using difference_type   = std::ptrdiff_t;
        using value_type        = std::decay_t<std::invoke_result_t<Func, decltype(*std::declval<base_t>())>>;
        using pointer           = const value_type*;
        using reference         = value_type;
        using iterator_category = std::input_iterator_tag;

        iterator() = default;
        iterator(base_t cur, const Func* f) : cur_(cur), func_(f) {}

        value_type operator*()  const { return (*func_)(*cur_); }
        iterator&  operator++()       { ++cur_; return *this; }
        iterator   operator++(int)    { auto t = *this; ++(*this); return t; }
        bool operator==(const iterator& o) const { return cur_ == o.cur_; }
        bool operator!=(const iterator& o) const { return cur_ != o.cur_; }
    };

    transform_view(Range r, Func f) : range_(std::move(r)), func_(std::move(f)) {}

    [[nodiscard]] iterator begin() const { return {range_.begin(), &func_}; }
    [[nodiscard]] iterator end()   const { return {range_.end(),   &func_}; }
};

template <typename Range, typename Func>
transform_view(Range, Func) -> transform_view<Range, Func>;

template <typename Func>
[[nodiscard]] constexpr auto transform(Func func) {
    return detail::pipeable{[f = std::move(func)](auto&& r) {
        return transform_view{std::forward<decltype(r)>(r), f};
    }};
}

// ============================================================
//  take_while_view
// ============================================================

template <typename Range, typename Pred>
class take_while_view {
    Range range_;
    Pred  pred_;

public:
    class sentinel {};

    class iterator {
        using base_t = decltype(std::declval<const Range&>().begin());
        base_t      cur_;
        base_t      end_;
        const Pred* pred_;
        bool        done_ = false;

        void check() { if (cur_ == end_ || !(*pred_)(*cur_)) done_ = true; }

    public:
        using difference_type   = std::ptrdiff_t;
        using value_type        = std::decay_t<decltype(*std::declval<base_t>())>;
        using pointer           = const value_type*;
        using reference         = decltype(*std::declval<base_t>());
        using iterator_category = std::input_iterator_tag;

        iterator() : done_(true) {}
        iterator(base_t cur, base_t end, const Pred* p)
            : cur_(cur), end_(end), pred_(p) { check(); }

        reference operator*()  const { return *cur_; }
        iterator& operator++()       { ++cur_; check(); return *this; }
        bool operator==(const sentinel&) const { return done_; }
        bool operator!=(const sentinel&) const { return !done_; }
        // Symmetric
        friend bool operator==(const sentinel& s, const iterator& i) { return i == s; }
        friend bool operator!=(const sentinel& s, const iterator& i) { return i != s; }
    };

    take_while_view(Range r, Pred p) : range_(std::move(r)), pred_(std::move(p)) {}

    [[nodiscard]] iterator begin() const { return {range_.begin(), range_.end(), &pred_}; }
    [[nodiscard]] sentinel end()   const { return {}; }
};

template <typename Range, typename Pred>
take_while_view(Range, Pred) -> take_while_view<Range, Pred>;

template <typename Pred>
[[nodiscard]] constexpr auto take_while(Pred pred) {
    return detail::pipeable{[p = std::move(pred)](auto&& r) {
        return take_while_view{std::forward<decltype(r)>(r), p};
    }};
}

// ============================================================
//  Convenience: find_first
// ============================================================

template <typename Range, typename Pred>
[[nodiscard]] auto find_first(Range&& range, Pred pred)
    -> std::optional<std::decay_t<decltype(*range.begin())>>
{
    for (auto&& item : range) {
        if (pred(item)) return item;
    }
    return std::nullopt;
}

} // namespace coffi
