#include "test_framework.h"

#include <exception>
#include <iostream>

namespace zk::test {

std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

bool add(const char* name, void (*fn)()) {
  registry().push_back(TestCase{name, fn});
  return true;
}

void check(bool condition, const char* expression, const char* file, int line) {
  if (!condition) {
    throw Failure{std::string(file) + ":" + std::to_string(line) +
                  ": check failed: " + expression};
  }
}

int run_all() {
  int failures = 0;
  for (const TestCase& test : registry()) {
    try {
      test.fn();
      std::cout << "[ ok ] " << test.name << '\n';
    } catch (const Failure& failure) {
      ++failures;
      std::cout << "[fail] " << test.name << ": " << failure.message << '\n';
    } catch (const std::exception& error) {
      ++failures;
      std::cout << "[fail] " << test.name << ": unexpected exception: " << error.what() << '\n';
    }
  }
  std::cout << "kernel unit tests: " << registry().size() << " run, " << failures
            << " failed\n";
  return failures;
}

}  // namespace zk::test
