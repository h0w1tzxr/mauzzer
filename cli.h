#ifndef MAUZZER_CLI_H
#define MAUZZER_CLI_H

#include "types.h"

// shows the menu and runs the chosen items until the user quits or the input ends
void runMenu(BugList& bugs, PacketList& packets, CrashRelList& relations);

#endif  // MAUZZER_CLI_H
