#include <Windows.h>
#include <iostream>
#include <intrin.h>
#include <string>
#include <thread>

#pragma code_seg(".text")
__declspec(allocate(".text")) u8 test[0x10000];
#pragma code_seg(pop)

s32 main(s32 argc, char* argv[]) {
  while (!GetAsyncKeyState(VK_END)) {
    system("cls");
    printf("enter password big boy: ");

    std::string pass;
    std::cin >> pass;

    Sleep(1000);

    if (atoll(pass.data()) == 341498349348394) {
    //  printf("1\n");
    //  Sleep(2000);
    //  break;
    }

    Sleep(100);
  }

  printf("works! [%i, %s]\n", argc, argv[0]);
  return 0;
}