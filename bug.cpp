#include "bug.h"

#include <iostream>

Status insertParent(BugList& L, const BugInfo& info) {
    bool nameIsBlank = info.bugName.find_first_not_of(" \t") == string::npos;
    if (info.bugId < 1 || info.bugId > kMaxId || nameIsBlank ||
        info.severity < 1 || info.severity > kMaxSeverity) {
        return Status::InvalidValue;
    }
    if (findParent(L, info.bugId) != nullptr) {
        return Status::DuplicateId;
    }

    BugNode* node = new BugNode{info, nullptr};
    if (L.last == nullptr) {
        L.first = node;
    } else {
        L.last->next = node;
    }
    L.last = node;
    return Status::Ok;
}

BugNode* findParent(const BugList& L, int bugId) {
    for (BugNode* bug = L.first; bug != nullptr; bug = bug->next) {
        if (bug->info.bugId == bugId) {
            return bug;
        }
    }
    return nullptr;
}

void showAllParent(const BugList& L) {
    if (L.first == nullptr) {
        cout << "No bugs yet.\n";
        return;
    }
    for (const BugNode* bug = L.first; bug != nullptr; bug = bug->next) {
        cout << bugText(bug->info) << '\n';
    }
}

string bugText(const BugInfo& info) {
    return "Bug " + to_string(info.bugId) + ": " + info.bugName +
           " (severity " + to_string(info.severity) + ")";
}
