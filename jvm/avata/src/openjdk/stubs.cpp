#include "avata/machine.h"

using namespace vm;

extern "C" AVATA_EXPORT jint JNICALL net_JNI_OnLoad(JavaVM*, void*)
{
  return 0;
}

extern "C" AVATA_EXPORT jint JNICALL management_JNI_OnLoad(JavaVM*, void*)
{
  return 0;
}

extern "C" char* findJavaTZ_md(const char*, const char*)
{
  return 0;
}
