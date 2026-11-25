#include "campaign.h"

#include <cstdlib>

#include "bug.h"
#include "fuzzer.h"
#include "packet.h"
#include "relation.h"

namespace {

int nextPacketId(const PacketList& packets) {
    int largest = 0;
    for (const PacketNode* packet = packets.first; packet != nullptr; packet = packet->next) {
        if (packet->info.packetId > largest) {
            largest = packet->info.packetId;
        }
    }
    return largest + 1;
}

}  // namespace

CampaignResult runCampaign(BugList& bugs, PacketList& packets, CrashRelList& relations,
                           int count, int seed) {
    srand(static_cast<unsigned>(seed));

    CampaignResult result = {0, 0, 0, 0};
    int packetId = nextPacketId(packets);
    while (result.made < count && packetId <= kMaxId) {
        PacketInfo info = mutatePacket(packetId);
        PacketNode* packet = appendChild(packets, info);

        bool triggeredAnyBug = false;
        for (int bugId = 1; bugId <= kBugCount; bugId++) {
            if (!runTargetParser(info, bugId)) {
                continue;
            }
            triggeredAnyBug = true;
            result.bugHits++;

            BugNode* bug = findParent(bugs, bugId);
            if (bug == nullptr) {
                result.skipped++;
            } else {
                appendRelation(relations, bug, packet, catalogHit(bugId));
            }
        }
        if (triggeredAnyBug) {
            result.crashed++;
        }
        result.made++;
        packetId++;
    }
    return result;
}
