// A tiny test registry. The kernel takes no test-framework dependency: a
// checked-in framework would be a supply-chain surface for a library that is
// meant to be auditable on its own.

#ifndef ZEROCOIN_KERNEL_TEST_FRAMEWORK_H
#define ZEROCOIN_KERNEL_TEST_FRAMEWORK_H

#include <string>
#include <vector>

namespace zk::test {

struct TestCase {
  const char* name;
  void (*fn)();
};

struct Failure {
  std::string message;
};

std::vector<TestCase>& registry();
bool add(const char* name, void (*fn)());

/// Records a failure by throwing, so the rest of a broken test does not run.
void check(bool condition, const char* expression, const char* file, int line);

/// Runs every registered test; returns the number of tests that failed.
int run_all();

}  // namespace zk::test

#define ZK_TEST(unique_name)                                                          \
  static void unique_name();                                                          \
  [[maybe_unused]] static const bool unique_name##_registered =                       \
      ::zk::test::add(#unique_name, &unique_name);                                    \
  static void unique_name()

#define ZK_CHECK(expression) \
  ::zk::test::check(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

#endif  // ZEROCOIN_KERNEL_TEST_FRAMEWORK_H
