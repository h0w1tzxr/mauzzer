#ifndef MAUZZER_RELATION_H
#define MAUZZER_RELATION_H

#include "bug.h"
#include "packet.h"

// returns InvalidValue for a negative offset, BugNotFound or PacketNotFound for an ID that doesn't exist, and DuplicateRelation if the pair is already linked.
Status insertRelation(CrashRelList& relations, const BugList& bugs, const PacketList& packets, int bugId, int packetId, const CrashRelInfo& info);

// links with no checks. both nodes must exist and the pair must not be linked yet
void appendRelation(CrashRelList& relations, BugNode* bug, PacketNode* packet, const CrashRelInfo& info);

// delete the bug's links first then the bug
Status deleteParent(BugList& bugs, CrashRelList& relations, int bugId);

// delete the packet's links first then the packet
Status deleteChild(PacketList& packets, CrashRelList& relations, int packetId);

Status deleteRelation(CrashRelList& relations, int bugId, int packetId);

CrashRelNode* findRelation(const CrashRelList& relations, int bugId, int packetId);

string linkText(const CrashRelInfo& info);

void showChildOfParent(const CrashRelList& relations, int bugId);
void showParentOfChild(const CrashRelList& relations, int packetId);
void showParentWithChild(const BugList& bugs, const CrashRelList& relations);
void showChildWithParent(const PacketList& packets, const CrashRelList& relations);

int countChildOfParent(const CrashRelList& relations, int bugId);
int countParentOfChild(const CrashRelList& relations, int packetId);
int countChildWithoutParent(const PacketList& packets, const CrashRelList& relations);
int countParentWithoutChild(const BugList& bugs, const CrashRelList& relations);

// moves a link to a new bug and packet. to change one side only, repeat the other side's ID. the offset and note stay, failed move changes nothing
Status editRelation(CrashRelList& relations, const BugList& bugs, const PacketList& packets, int bugId, int packetId, int newBugId, int newPacketId);

#endif  // MAUZZER_RELATION_H
