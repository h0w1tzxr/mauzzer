#include "relation.h"

#include <iostream>

namespace {

CrashRelNode* removeLinkAndGetNext(CrashRelList& relations, CrashRelNode* previous, CrashRelNode* link) {
    CrashRelNode* next = link->next;
    if (previous == nullptr) {
        relations.first = next;
    } else {
        previous->next = next;
    }
    if (relations.last == link) {
        relations.last = previous;
    }
    delete link;
    return next;
}

void removeBug(BugList& bugs, BugNode* bug) {
    BugNode* previous = nullptr;
    BugNode* current = bugs.first;
    while (current != bug) {
        previous = current;
        current = current->next;
    }

    if (previous == nullptr) {
        bugs.first = bug->next;
    } else {
        previous->next = bug->next;
    }
    if (bugs.last == bug) {
        bugs.last = previous;
    }
    delete bug;
}

void removePacket(PacketList& packets, PacketNode* packet) {
    PacketNode* previous = nullptr;
    PacketNode* current = packets.first;
    while (current != packet) {
        previous = current;
        current = current->next;
    }

    if (previous == nullptr) {
        packets.first = packet->next;
    } else {
        previous->next = packet->next;
    }
    if (packets.last == packet) {
        packets.last = previous;
    }
    delete packet;
}

bool isPair(const CrashRelNode* link, int bugId, int packetId) {
    return link->parent->info.bugId == bugId && link->child->info.packetId == packetId;
}

}  // namespace

Status insertRelation(CrashRelList& relations, const BugList& bugs, const PacketList& packets,
                      int bugId, int packetId, const CrashRelInfo& info) {
    if (info.hitOffset < 0) {
        return Status::InvalidValue;
    }
    BugNode* bug = findParent(bugs, bugId);
    if (bug == nullptr) {
        return Status::BugNotFound;
    }
    PacketNode* packet = findChild(packets, packetId);
    if (packet == nullptr) {
        return Status::PacketNotFound;
    }
    if (findRelation(relations, bugId, packetId) != nullptr) {
        return Status::DuplicateRelation;
    }
    appendRelation(relations, bug, packet, info);
    return Status::Ok;
}

void appendRelation(CrashRelList& relations, BugNode* bug, PacketNode* packet,
                    const CrashRelInfo& info) {
    CrashRelNode* link = new CrashRelNode{info, bug, packet, nullptr};
    if (relations.last == nullptr) {
        relations.first = link;
    } else {
        relations.last->next = link;
    }
    relations.last = link;
}

Status deleteParent(BugList& bugs, CrashRelList& relations, int bugId) {
    BugNode* bug = findParent(bugs, bugId);
    if (bug == nullptr) {
        return Status::BugNotFound;
    }

    CrashRelNode* previous = nullptr;
    CrashRelNode* link = relations.first;
    while (link != nullptr) {
        if (link->parent == bug) {
            link = removeLinkAndGetNext(relations, previous, link);
        } else {
            previous = link;
            link = link->next;
        }
    }

    removeBug(bugs, bug);
    return Status::Ok;
}

Status deleteChild(PacketList& packets, CrashRelList& relations, int packetId) {
    PacketNode* packet = findChild(packets, packetId);
    if (packet == nullptr) {
        return Status::PacketNotFound;
    }

    CrashRelNode* previous = nullptr;
    CrashRelNode* link = relations.first;
    while (link != nullptr) {
        if (link->child == packet) {
            link = removeLinkAndGetNext(relations, previous, link);
        } else {
            previous = link;
            link = link->next;
        }
    }

    removePacket(packets, packet);
    return Status::Ok;
}

Status deleteRelation(CrashRelList& relations, int bugId, int packetId) {
    CrashRelNode* previous = nullptr;
    for (CrashRelNode* link = relations.first; link != nullptr; link = link->next) {
        if (isPair(link, bugId, packetId)) {
            removeLinkAndGetNext(relations, previous, link);
            return Status::Ok;
        }
        previous = link;
    }
    return Status::RelationNotFound;
}

CrashRelNode* findRelation(const CrashRelList& relations, int bugId, int packetId) {
    for (CrashRelNode* link = relations.first; link != nullptr; link = link->next) {
        if (isPair(link, bugId, packetId)) {
            return link;
        }
    }
    return nullptr;
}

string linkText(const CrashRelInfo& info) {
    return "hit at byte " + to_string(info.hitOffset) + " (" + info.note + ")";
}

void showChildOfParent(const CrashRelList& relations, int bugId) {
    bool anyLink = false;
    for (const CrashRelNode* link = relations.first; link != nullptr; link = link->next) {
        if (link->parent->info.bugId == bugId) {
            cout << "    -> " << packetText(link->child->info) << " | " << linkText(link->info) << '\n';
            anyLink = true;
        }
    }
    if (!anyLink) {
        cout << "    (no links)\n";
    }
}

void showParentOfChild(const CrashRelList& relations, int packetId) {
    bool anyLink = false;
    for (const CrashRelNode* link = relations.first; link != nullptr; link = link->next) {
        if (link->child->info.packetId == packetId) {
            cout << "    -> " << bugText(link->parent->info) << " | " << linkText(link->info) << '\n';
            anyLink = true;
        }
    }
    if (!anyLink) {
        cout << "    (no links)\n";
    }
}

void showParentWithChild(const BugList& bugs, const CrashRelList& relations) {
    if (bugs.first == nullptr) {
        cout << "No bugs yet.\n";
        return;
    }
    for (const BugNode* bug = bugs.first; bug != nullptr; bug = bug->next) {
        cout << bugText(bug->info) << '\n';
        showChildOfParent(relations, bug->info.bugId);
    }
}

void showChildWithParent(const PacketList& packets, const CrashRelList& relations) {
    if (packets.first == nullptr) {
        cout << "No packets yet.\n";
        return;
    }
    for (const PacketNode* packet = packets.first; packet != nullptr; packet = packet->next) {
        cout << packetText(packet->info) << '\n';
        showParentOfChild(relations, packet->info.packetId);
    }
}

int countChildOfParent(const CrashRelList& relations, int bugId) {
    int total = 0;
    for (const CrashRelNode* link = relations.first; link != nullptr; link = link->next) {
        if (link->parent->info.bugId == bugId) {
            total++;
        }
    }
    return total;
}

int countParentOfChild(const CrashRelList& relations, int packetId) {
    int total = 0;
    for (const CrashRelNode* link = relations.first; link != nullptr; link = link->next) {
        if (link->child->info.packetId == packetId) {
            total++;
        }
    }
    return total;
}

int countChildWithoutParent(const PacketList& packets, const CrashRelList& relations) {
    int total = 0;
    for (const PacketNode* packet = packets.first; packet != nullptr; packet = packet->next) {
        if (countParentOfChild(relations, packet->info.packetId) == 0) {
            total++;
        }
    }
    return total;
}

int countParentWithoutChild(const BugList& bugs, const CrashRelList& relations) {
    int total = 0;
    for (const BugNode* bug = bugs.first; bug != nullptr; bug = bug->next) {
        if (countChildOfParent(relations, bug->info.bugId) == 0) {
            total++;
        }
    }
    return total;
}

Status editRelation(CrashRelList& relations, const BugList& bugs, const PacketList& packets,
                    int bugId, int packetId, int newBugId, int newPacketId) {
    CrashRelNode* link = findRelation(relations, bugId, packetId);
    if (link == nullptr) {
        return Status::RelationNotFound;
    }
    BugNode* newBug = findParent(bugs, newBugId);
    if (newBug == nullptr) {
        return Status::BugNotFound;
    }
    PacketNode* newPacket = findChild(packets, newPacketId);
    if (newPacket == nullptr) {
        return Status::PacketNotFound;
    }
    if (findRelation(relations, newBugId, newPacketId) != nullptr) {
        return Status::DuplicateRelation;
    }

    link->parent = newBug;
    link->child = newPacket;
    return Status::Ok;
}
