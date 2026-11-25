#ifndef MAUZZER_BUG_H
#define MAUZZER_BUG_H

#include "types.h"

// returns InvalidValue for a bad ID, a bad severity, or a blank name, and DuplicateId if the ID exists
Status insertParent(BugList& L, const BugInfo& info);

BugNode* findParent(const BugList& L, int bugId);

void showAllParent(const BugList& L);

string bugText(const BugInfo& info);

#endif  // MAUZZER_BUG_H
