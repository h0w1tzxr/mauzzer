#ifndef MAUZZER_CAMPAIGN_H
#define MAUZZER_CAMPAIGN_H

#include "types.h"

const int kMaxPacketsPerRun = 1000;

struct CampaignResult {
    int made;     // packets created
    int crashed;  // packets that triggered at least one bug
    int bugHits;  // bug triggers in total
    int skipped;  // bug hits that got no link, because the bug isn't in the bug list
};

// creates packets after the largest existing ID, runs each one through the parser,
// and links it to every bug it triggers. the same seed gives the same packets.
// it stops early if the packet IDs run out, so check result.made against count
CampaignResult runCampaign(BugList& bugs, PacketList& packets, CrashRelList& relations,
                           int count, int seed);

#endif  // MAUZZER_CAMPAIGN_H
