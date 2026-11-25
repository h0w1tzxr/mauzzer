#include "fuzzer.h"

#include <cstdlib>

namespace {

struct Rule {
    const char* name;
    int severity;
    int hitOffset;
    const char* note;
};

const Rule kRules[kBugCount] = {
    {"Buffer Over-Read",      5, 1, "declaredLength > actualSize"},
    {"Magic Byte NullPtr",    4, 2, "rawHex has DE AD or DEADBEEF"},
    {"Zero-Length Underflow", 3, 1, "type 2 with declaredLength 0"},
    {"Truncated Header",      2, 0, "actualSize < 2"},
};

}  // namespace

BugInfo catalogBug(int bugId) {
    const Rule& rule = kRules[bugId - 1];
    return {bugId, rule.name, rule.severity};
}

CrashRelInfo catalogHit(int bugId) {
    const Rule& rule = kRules[bugId - 1];
    return {rule.hitOffset, rule.note};
}

bool runTargetParser(const PacketInfo& packet, int bugId) {
    switch (bugId) {
        case 1:
            return packet.declaredLength > packet.actualSize;
        case 2:
            return packet.rawHex.find("DE AD") != string::npos ||
                   packet.rawHex.find("DEADBEEF") != string::npos;
        case 3:
            return packet.type == 2 && packet.declaredLength == 0;
        case 4:
            return packet.actualSize < 2;
        default:
            return false;
    }
}

PacketInfo mutatePacket(int packetId) {
    PacketInfo packet = {packetId, 1, 4, 4, "41 42 43 44"};

    int mutationCount = 1 + rand() % 2;
    for (int i = 0; i < mutationCount; i++) {
        switch (rand() % 5) {
            case 0: packet.declaredLength = 255; break;
            case 1: packet.declaredLength = 0; break;
            case 2: packet.rawHex += " DE AD BE EF"; break;
            case 3: packet.type = 2; break;
            default: packet.actualSize = 1; break;
        }
    }
    return packet;
}
