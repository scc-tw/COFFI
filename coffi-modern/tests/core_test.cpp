#include <gtest/gtest.h>
#include <coffi/core/error.hpp>
#include <coffi/core/result.hpp>
#include <coffi/core/safe_math.hpp>
#include <coffi/core/endian.hpp>
#include <coffi/core/byte_view.hpp>

using namespace coffi;

// ================================================================
//  error_code tests
// ================================================================

TEST(ErrorTest, ToStringCoversAllCodes) {
    EXPECT_EQ(to_string(error_code::success), "success");
    EXPECT_EQ(to_string(error_code::out_of_bounds), "access out of bounds");
    EXPECT_EQ(to_string(error_code::overflow), "integer overflow");
    EXPECT_EQ(to_string(error_code::division_by_zero), "division by zero");
}

// ================================================================
//  result<T, E> tests
// ================================================================

TEST(ResultTest, ValueConstruction) {
    result<int> r(42);
    EXPECT_TRUE(r.has_value());
    EXPECT_TRUE(static_cast<bool>(r));
    EXPECT_EQ(r.value(), 42);
    EXPECT_EQ(*r, 42);
}

TEST(ResultTest, ErrorConstruction) {
    result<int> r(error_code::overflow);
    EXPECT_FALSE(r.has_value());
    EXPECT_FALSE(static_cast<bool>(r));
    EXPECT_EQ(r.error(), error_code::overflow);
}

TEST(ResultTest, UnexpectedConstruction) {
    result<int> r(unexpected{error_code::out_of_bounds});
    EXPECT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), error_code::out_of_bounds);
}

TEST(ResultTest, ValueOr) {
    result<int> ok(10);
    result<int> err(error_code::overflow);
    EXPECT_EQ(ok.value_or(99), 10);
    EXPECT_EQ(err.value_or(99), 99);
}

TEST(ResultTest, ArrowOperator) {
    struct S { int x; };
    result<S> r(S{7});
    EXPECT_EQ(r->x, 7);
}

TEST(ResultTest, Map) {
    result<int> r(5);
    auto doubled = r.map([](int v) { return v * 2; });
    EXPECT_TRUE(doubled.has_value());
    EXPECT_EQ(*doubled, 10);

    result<int> err(error_code::overflow);
    auto mapped = err.map([](int v) { return v * 2; });
    EXPECT_FALSE(mapped.has_value());
    EXPECT_EQ(mapped.error(), error_code::overflow);
}

TEST(ResultTest, AndThen) {
    auto half = [](int v) -> result<int> {
        if (v % 2 != 0) return error_code::invalid_alignment;
        return v / 2;
    };
    result<int> r(10);
    auto h = r.and_then(half);
    EXPECT_TRUE(h.has_value());
    EXPECT_EQ(*h, 5);

    result<int> odd(7);
    auto h2 = odd.and_then(half);
    EXPECT_FALSE(h2.has_value());
}

TEST(ResultTest, VoidSpecialisation) {
    result<void> ok;
    EXPECT_TRUE(ok.has_value());

    result<void> err(error_code::file_too_small);
    EXPECT_FALSE(err.has_value());
    EXPECT_EQ(err.error(), error_code::file_too_small);
}

// ================================================================
//  safe_math tests
// ================================================================

TEST(SafeMathTest, CheckedAddNormal) {
    auto r = checked_add<uint32_t>(10, 20);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 30u);
}

TEST(SafeMathTest, CheckedAddOverflow) {
    auto r = checked_add<uint32_t>(UINT32_MAX, 1);
    EXPECT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), error_code::overflow);
}

TEST(SafeMathTest, CheckedMulNormal) {
    auto r = checked_mul<uint32_t>(1000, 1000);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 1000000u);
}

TEST(SafeMathTest, CheckedMulOverflow) {
    auto r = checked_mul<uint32_t>(UINT32_MAX, 2);
    EXPECT_FALSE(r.has_value());
}

TEST(SafeMathTest, CheckedMulZero) {
    auto r = checked_mul<uint32_t>(0, UINT32_MAX);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0u);
}

TEST(SafeMathTest, AlignToBasic) {
    EXPECT_EQ(align_to<uint32_t>(0, 4), 0u);
    EXPECT_EQ(align_to<uint32_t>(1, 4), 4u);
    EXPECT_EQ(align_to<uint32_t>(4, 4), 4u);
    EXPECT_EQ(align_to<uint32_t>(5, 4), 8u);
    EXPECT_EQ(align_to<uint32_t>(512, 512), 512u);
}

TEST(SafeMathTest, AlignToZeroAlignment) {
    // 1ee0be8 fix: alignment==0 must not divide by zero
    EXPECT_EQ(align_to<uint32_t>(42, 0), 42u);
}

TEST(SafeMathTest, NarrowCast) {
    auto r = narrow_cast<uint8_t>(255u);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 255);

    auto r2 = narrow_cast<uint8_t>(256u);
    EXPECT_FALSE(r2.has_value());
}

// ================================================================
//  endian tests
// ================================================================

TEST(EndianTest, ByteSwap16) {
    EXPECT_EQ(byte_swap(uint16_t(0x0102)), uint16_t(0x0201));
}

TEST(EndianTest, ByteSwap32) {
    EXPECT_EQ(byte_swap(uint32_t(0x01020304)), uint32_t(0x04030201));
}

TEST(EndianTest, ByteSwap64) {
    EXPECT_EQ(byte_swap(uint64_t(0x0102030405060708ULL)),
              uint64_t(0x0807060504030201ULL));
}

TEST(EndianTest, ToNativeSameOrder) {
    uint32_t val = 0xDEADBEEF;
    EXPECT_EQ(to_native(val, native_byte_order), val);
}

TEST(EndianTest, EndianValueWrapper) {
    le<uint16_t> v;
    v.set(0x1234);
    EXPECT_EQ(v.get(), 0x1234);
}

// ================================================================
//  byte_view tests
// ================================================================

TEST(ByteViewTest, DefaultConstruction) {
    byte_view v;
    EXPECT_TRUE(v.empty());
    EXPECT_EQ(v.size(), 0u);
}

TEST(ByteViewTest, ReadPod) {
    const uint8_t data[] = {0xEF, 0xBE, 0xAD, 0xDE};
    byte_view v(data, sizeof(data));

    auto r = v.read<uint32_t>(0);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 0xDEADBEEF);
}

TEST(ByteViewTest, ReadOutOfBounds) {
    const uint8_t data[] = {0x01};
    byte_view v(data, 1);
    auto r = v.read<uint32_t>(0);
    EXPECT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), error_code::out_of_bounds);
}

TEST(ByteViewTest, Subview) {
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    byte_view v(data, sizeof(data));

    auto sub = v.subview(1, 2);
    ASSERT_TRUE(sub.has_value());
    EXPECT_EQ(sub->size(), 2u);
    EXPECT_EQ(static_cast<uint8_t>((*sub)[0]), 0x02);
}

TEST(ByteViewTest, SubviewOverflow) {
    const uint8_t data[] = {0x01};
    byte_view v(data, 1);
    auto sub = v.subview(0, SIZE_MAX);  // triggers overflow in checked_add
    EXPECT_FALSE(sub.has_value());
}

TEST(ByteViewTest, ReadCstring) {
    const char data[] = "hello\0world";
    byte_view v(data, sizeof(data));
    EXPECT_EQ(v.read_cstring(0), "hello");
    EXPECT_EQ(v.read_cstring(6), "world");
}

TEST(ByteViewTest, ReadFixedString) {
    const char name[8] = {'.', 't', 'e', 'x', 't', '\0', '\0', '\0'};
    byte_view v(name, 8);
    EXPECT_EQ(v.read_fixed_string(0, 8), ".text");
}

TEST(ByteViewTest, ReadArray) {
    const uint32_t data[] = {1, 2, 3, 4};
    byte_view v(data, sizeof(data));
    auto arr = v.read_array<uint32_t>(0, 4);
    ASSERT_TRUE(arr.has_value());
    EXPECT_EQ(arr->size(), 16u);

    // Overflow: huge count
    auto bad = v.read_array<uint32_t>(0, SIZE_MAX);
    EXPECT_FALSE(bad.has_value());
}

TEST(ByteViewTest, SliceUnchecked) {
    const uint8_t data[] = {0xAA, 0xBB, 0xCC};
    byte_view v(data, 3);
    auto s = v.slice(1, 1);
    EXPECT_EQ(s.size(), 1u);
    EXPECT_EQ(static_cast<uint8_t>(s[0]), 0xBB);
}
