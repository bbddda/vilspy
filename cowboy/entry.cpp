#include <Windows.h>
#include <iostream>
#include <intrin.h>
#include <string>
#include <thread>

class MyClass {
 public:
  MyClass(int num) { number = num; }

  void printInfo() {
    std::cout << "Number: " << number << std::endl;
    std::cout << "Message: " << message << std::endl;
  }

  void setMessage(const std::string& msg) { message = msg; }

  int multiply(int factor) { return number * factor; }

 private:
  int number;
  std::string message;
};

void thread() {
  while (true) {
    MyClass myObject(42);
    myObject.setMessage("Hello, World!");

    std::cout << "Result: " << myObject.multiply(5) << std::endl;
    myObject.printInfo();

    for (int i = 0; i < 10; ++i) {
      if (i % 2 == 0) {
        std::cout << i << " is even." << std::endl;
      } else {
        std::cout << i << " is odd." << std::endl;
      }
    }

    std::cout << "Result: " << myObject.multiply(5) << std::endl;
    myObject.printInfo();

    for (int i = 0; i < 10; ++i) {
      if (i % 2 == 0) {
        std::cout << i << " is even." << std::endl;
      } else {
        std::cout << i << " is odd." << std::endl;
      }
    }

    std::cout << "Result: " << myObject.multiply(5) << std::endl;
    myObject.printInfo();

    for (int i = 0; i < 10; ++i) {
      if (i % 2 == 0) {
        std::cout << i << " is even." << std::endl;
      } else {
        std::cout << i << " is odd." << std::endl;
      }
    }

    std::cout << "Result: " << myObject.multiply(5) << std::endl;
    myObject.printInfo();

    for (int i = 0; i < 10; ++i) {
      if (i % 2 == 0) {
        std::cout << i << " is even." << std::endl;
      } else {
        std::cout << i << " is odd." << std::endl;
      }
    }

    std::cout << "Result: " << myObject.multiply(5) << std::endl;
    myObject.printInfo();

    for (int i = 0; i < 10; ++i) {
      if (i % 2 == 0) {
        std::cout << i << " is even." << std::endl;
      } else {
        std::cout << i << " is odd." << std::endl;
      }
    }
  }
}


void thread3() {
  while (true) {
    MyClass myObject(5315);
    myObject.setMessage("Hello, World!");

    MyClass myObject1(5315);
    myObject.setMessage("Hello, World!");

    std::cout << "Result: " << myObject.multiply(5) << std::endl;
    myObject.printInfo();

    std::cout << "Result: " << myObject.multiply(5) << std::endl;
    myObject.printInfo();

    for (int i = 0; i < 10; ++i) {
      if (i % 2 == 0) {
        std::cout << i << " is even." << std::endl;
      } else {
        std::cout << i << " is odd." << std::endl;
      }
    }

    std::cout << "Result: " << myObject.multiply(5) << std::endl;
    myObject1.printInfo();

    for (int i = 0; i < 10; ++i) {
      if (i % 2 == 0) {
        std::cout << i << " is even." << std::endl;
      } else {
        std::cout << i << " is odd." << std::endl;
      }
    }
  }
}

s32 main(s32 argc, char* argv[]) {
  for (u8 i = 0; i < 50; ++i) {
    if (i % 2 == 0) {
      std::thread([&]() { thread3(); }).detach();
    } else {
      std::thread([&]() { thread(); }).detach();
    
    }

    Sleep(100 + i);
  }

  printf("works! [%i, %s]\n", argc, argv[0]);
  thread3();
  return 0;
}