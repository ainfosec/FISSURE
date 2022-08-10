// https://github.com/1337ninja/UUIDGenerator
#include "uuidgen.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstring>


UUIDGenerator::UUIDGenerator() 
{
}

UUIDGenerator::~UUIDGenerator()
{
}


void UUIDGenerator::SetTimeEpoch()
{
  //Get the current epoch in nanoseconds from January 1 1970
  std::chrono::nanoseconds ns = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch());
  uuid.TimeEpoch = ns.count() & 0xFFFFFFFFFFFFF;
}


void UUIDGenerator::SetRandomNumber(std::mt19937& PRNG)
{
  std::uniform_int_distribution<uint32_t> uint_dist_long(0, UINT32_MAX);
  uuid.RandomNumber =  uint_dist_long(PRNG);
  uuid.RandomNumber <<= 32;
  uuid.RandomNumber |= uint_dist_long(PRNG);
  uuid.RandomNumber &= 0xFFFFFFFFFFFFFFF ;
}


void UUIDGenerator::SetNodeNumber(std::mt19937& PRNG)
{
  /*This number is currently being randomly generated. In a distributed environment this would be known before-hand */
  std::uniform_int_distribution<unsigned> uint_dist_long(0,UINT16_MAX);
  uuid.Node = uint_dist_long(PRNG) & 0xFFFF;
}


std::string UUIDGenerator::GenerateUUID(bool bPrettyPrint)
{
     
  static std::random_device seed;
  static std::mt19937 PRNG(seed());
    
  //Initialize various fields of UUID structure
  SetRandomNumber(PRNG);
  SetTimeEpoch();
  SetNodeNumber(PRNG);

  std::stringstream ssUUID;
  ssUUID << std::hex << std::setfill('0');
    
  ssUUID << std::setw(15) << uuid.RandomNumber; // 15 hex digits = 60 bit binary number
  ssUUID << std::setw(13) << uuid.TimeEpoch;
  ssUUID << std::setw(4) << uuid.Node;

  return bPrettyPrint ? (ssUUID.str().insert(8, 1, '-').insert(13, 1, '-').insert(18, 1, '-').insert(23, 1, '-')) : ssUUID.str();
}

  

int main(int argc, char *argv[])
{

  UUIDGenerator uuid;
  argv[1] == NULL ? std::cout<< uuid.GenerateUUID() : strcmp(argv[1], "0") ? std::cout<< uuid.GenerateUUID() : std::cout<< uuid.GenerateUUID(false);

  return 0;
}
