#ifndef MAUZZER_PACKET_H
#define MAUZZER_PACKET_H

#include "types.h"

// returns InvalidValue for a bad ID, a bad type, or a negative length or size, and DuplicateId if the ID exists. length and size may disagree on purpose because fuzzed packets are broken
Status insertChild(PacketList& L, const PacketInfo& info);

// adds a packet to the end with no checks and returns it. the ID must be valid and new
PacketNode* appendChild(PacketList& L, const PacketInfo& info);

PacketNode* findChild(const PacketList& L, int packetId);

void showAllChild(const PacketList& L);

string packetText(const PacketInfo& info);

#endif  // MAUZZER_PACKET_H
