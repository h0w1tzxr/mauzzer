#ifndef MAUZZER_FUZZER_H
#define MAUZZER_FUZZER_H

#include "types.h"

const int kBugCount = 4;

// these 2 need a bugId from 1 to kBugCount
BugInfo catalogBug(int bugId);
CrashRelInfo catalogHit(int bugId);

// each bug has its own rule, so one packet can trigger several bugs
bool runTargetParser(const PacketInfo& packet, int bugId);

// starts from a valid seed packet and applies 1 or 2 random mutations. call srand first if you want the same packets again
PacketInfo mutatePacket(int packetId);

#endif  // MAUZZER_FUZZER_H
