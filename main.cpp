#include <iostream>

#include "cli.h"
#include "types.h"

int main() {
    BugList bugs;
    PacketList packets;
    CrashRelList relations;

    try {
        runMenu(bugs, packets, relations);
    } catch (...) {
        // new throws when memory runs out. leaving this block frees all three lists
        cout << "Out of memory. Stopping.\n";
        return 1;
    }
    return 0;
}
