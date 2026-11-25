// the data model is a MLL and a list of links between them
// a bug can have many packets and a packet can have many bugs
#ifndef MAUZZER_TYPES_H
#define MAUZZER_TYPES_H

#include <string>

using namespace std;

const int kMaxId = 999999;
const int kMaxSeverity = 5;
const int kMaxTlvType = 255;

struct BugInfo {
    int bugId;
    string bugName;
    int severity;
};

// declaredLength is what the packet claims, actualSize is what it really has
struct PacketInfo {
    int packetId;
    int type;
    int declaredLength;
    int actualSize;
    string rawHex;
};

struct CrashRelInfo {
    int hitOffset;  // the byte that triggers the bug
    string note;
};

struct BugNode {
    BugInfo info;
    BugNode* next;
};

struct PacketNode {
    PacketInfo info;
    PacketNode* next;
};

// a link doesn't own its bug or packet, so delete a link before you delete either one
struct CrashRelNode {
    CrashRelInfo info;
    BugNode* parent;
    PacketNode* child;
    CrashRelNode* next;
};

enum class Status {
    Ok,
    DuplicateId,
    DuplicateRelation,
    BugNotFound,
    PacketNotFound,
    RelationNotFound,
    InvalidValue
};

struct BugList {
    BugNode* first = nullptr;
    BugNode* last = nullptr;

    ~BugList() {
        while (first != nullptr) {
            BugNode* next = first->next;
            delete first;
            first = next;
        }
    }
};

struct PacketList {
    PacketNode* first = nullptr;
    PacketNode* last = nullptr;

    ~PacketList() {
        while (first != nullptr) {
            PacketNode* next = first->next;
            delete first;
            first = next;
        }
    }
};

struct CrashRelList {
    CrashRelNode* first = nullptr;
    CrashRelNode* last = nullptr;

    ~CrashRelList() {
        while (first != nullptr) {
            CrashRelNode* next = first->next;
            delete first;
            first = next;
        }
    }
};

#endif  // MAUZZER_TYPES_H
