#pragma once

// The one small runner every test executable shares: named checks, counts and an expected-failure helper.
#include <concepts>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace craft::testing
{
inline int passed = 0, failed = 0;

// Run one named check. Integration harnesses stop at the first failure, since later checks build on its
// state.
inline void test(std::string_view name, std::invocable auto &&check, bool stop_on_failure = false)
{
    try
    {
        check();
        ++passed;
        std::cout << "PASS " << name << std::endl;
    }
    catch (const std::exception &error)
    {
        ++failed;
        std::cout << "FAIL " << name << ": " << error.what() << std::endl;
        if (stop_on_failure) throw;
    }
}

inline void rejects(std::invocable auto &&operation)
{
    bool rejected = false;
    try
    {
        operation();
    }
    catch (const std::exception &)
    {
        rejected = true;
    }
    if (!rejected) throw std::runtime_error("operation unexpectedly accepted invalid input");
}

inline int finish(std::string_view note)
{
    std::cout << passed << " passed; " << failed << " failed. " << note << std::endl;
    return failed ? 1 : 0;
}

} // namespace craft::testing
