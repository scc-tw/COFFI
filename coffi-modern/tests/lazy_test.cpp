#include <gtest/gtest.h>
#include <coffi/core/lazy.hpp>
#include <vector>
#include <string>

using namespace coffi;

TEST(FilterViewTest, BasicFilter) {
    std::vector<int> v = {1, 2, 3, 4, 5, 6};
    auto evens = v | filter([](int x) { return x % 2 == 0; });

    std::vector<int> result;
    for (auto x : evens) result.push_back(x);
    EXPECT_EQ(result, (std::vector<int>{2, 4, 6}));
}

TEST(FilterViewTest, EmptyResult) {
    std::vector<int> v = {1, 3, 5};
    auto evens = v | filter([](int x) { return x % 2 == 0; });

    int count = 0;
    for ([[maybe_unused]] auto x : evens) ++count;
    EXPECT_EQ(count, 0);
}

TEST(TransformViewTest, BasicTransform) {
    std::vector<int> v = {1, 2, 3};
    auto doubled = v | transform([](int x) { return x * 2; });

    std::vector<int> result;
    for (auto x : doubled) result.push_back(x);
    EXPECT_EQ(result, (std::vector<int>{2, 4, 6}));
}

TEST(TransformViewTest, TypeChanging) {
    std::vector<int> v = {1, 2, 3};
    auto strs = v | transform([](int x) { return std::to_string(x); });

    std::vector<std::string> result;
    for (auto s : strs) result.push_back(s);
    EXPECT_EQ(result, (std::vector<std::string>{"1", "2", "3"}));
}

TEST(PipeTest, FilterThenTransform) {
    std::vector<int> v = {1, 2, 3, 4, 5, 6};
    auto pipe = v | filter([](int x) { return x > 3; })
                  | transform([](int x) { return x * 10; });

    std::vector<int> result;
    for (auto x : pipe) result.push_back(x);
    EXPECT_EQ(result, (std::vector<int>{40, 50, 60}));
}

TEST(TakeWhileTest, Basic) {
    std::vector<int> v = {1, 2, 3, 10, 4, 5};
    auto taken = v | take_while([](int x) { return x < 10; });

    std::vector<int> result;
    for (auto x : taken) result.push_back(x);
    EXPECT_EQ(result, (std::vector<int>{1, 2, 3}));
}

TEST(TakeWhileTest, AllMatch) {
    std::vector<int> v = {1, 2, 3};
    auto taken = v | take_while([](int x) { return x < 10; });

    std::vector<int> result;
    for (auto x : taken) result.push_back(x);
    EXPECT_EQ(result, (std::vector<int>{1, 2, 3}));
}

TEST(TakeWhileTest, NoneMatch) {
    std::vector<int> v = {10, 20, 30};
    auto taken = v | take_while([](int x) { return x < 5; });

    int count = 0;
    for ([[maybe_unused]] auto x : taken) ++count;
    EXPECT_EQ(count, 0);
}

TEST(FindFirstTest, Found) {
    std::vector<int> v = {1, 2, 3, 4};
    auto r = find_first(v, [](int x) { return x > 2; });
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 3);
}

TEST(FindFirstTest, NotFound) {
    std::vector<int> v = {1, 2, 3};
    auto r = find_first(v, [](int x) { return x > 10; });
    EXPECT_FALSE(r.has_value());
}
