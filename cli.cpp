#include "cli.h"

#include <ctime>
#include <iostream>

#include "bug.h"
#include "campaign.h"
#include "fuzzer.h"
#include "input.h"
#include "packet.h"
#include "relation.h"

namespace {

void report(Status status, const string& successMessage) {
    switch (status) {
        case Status::Ok:
            cout << successMessage << '\n';
            break;
        case Status::DuplicateId:
            cout << "That ID already exists.\n";
            break;
        case Status::DuplicateRelation:
            cout << "Those two are already linked.\n";
            break;
        case Status::BugNotFound:
            cout << "No bug has that ID.\n";
            break;
        case Status::PacketNotFound:
            cout << "No packet has that ID.\n";
            break;
        case Status::RelationNotFound:
            cout << "Those two aren't linked.\n";
            break;
        case Status::InvalidValue:
            cout << "That value didn't work. IDs go from 1 to " << kMaxId
                 << ", severity from 1 to " << kMaxSeverity << ", and type from 0 to " << kMaxTlvType
                 << ". Length, size, and offset can't be negative. A bug name can't be blank.\n";
            break;
    }
}

bool askExistingBugId(const BugList& bugs, int& bugId) {
    if (!askNumber("Bug ID: ", bugId)) {
        return false;
    }
    if (findParent(bugs, bugId) == nullptr) {
        report(Status::BugNotFound, "");
        return false;
    }
    return true;
}

bool askExistingPacketId(const PacketList& packets, int& packetId) {
    if (!askNumber("Packet ID: ", packetId)) {
        return false;
    }
    if (findChild(packets, packetId) == nullptr) {
        report(Status::PacketNotFound, "");
        return false;
    }
    return true;
}

void addBug(BugList& bugs) {
    BugInfo bug = {0, "", 0};
    if (askNumber("Bug ID: ", bug.bugId) && askText("Bug name: ", bug.bugName) &&
        askNumber("Severity (1-5): ", bug.severity)) {
        report(insertParent(bugs, bug), "Added the bug.");
    }
}

void addPacket(PacketList& packets) {
    PacketInfo packet = {0, 0, 0, 0, ""};
    if (askNumber("Packet ID: ", packet.packetId) && askNumber("Type (0-255): ", packet.type) &&
        askNumber("Declared length: ", packet.declaredLength) &&
        askNumber("Actual size: ", packet.actualSize) &&
        askText("Hex bytes (like 41 42 43): ", packet.rawHex)) {
        report(insertChild(packets, packet), "Added the packet.");
    }
}

void addLink(BugList& bugs, PacketList& packets, CrashRelList& relations) {
    int bugId = 0;
    int packetId = 0;
    CrashRelInfo info = {0, ""};
    if (askNumber("Bug ID: ", bugId) && askNumber("Packet ID: ", packetId) &&
        askNumber("Hit offset: ", info.hitOffset) && askText("Note: ", info.note)) {
        report(insertRelation(relations, bugs, packets, bugId, packetId, info), "Linked them.");
    }
}

void deleteBug(BugList& bugs, CrashRelList& relations) {
    int bugId = 0;
    if (askNumber("Bug ID: ", bugId)) {
        report(deleteParent(bugs, relations, bugId), "Deleted the bug and its links.");
    }
}

void deletePacket(PacketList& packets, CrashRelList& relations) {
    int packetId = 0;
    if (askNumber("Packet ID: ", packetId)) {
        report(deleteChild(packets, relations, packetId), "Deleted the packet and its links.");
    }
}

void deleteLink(CrashRelList& relations) {
    int bugId = 0;
    int packetId = 0;
    if (askNumber("Bug ID: ", bugId) && askNumber("Packet ID: ", packetId)) {
        report(deleteRelation(relations, bugId, packetId), "Deleted the link.");
    }
}

void findBug(const BugList& bugs) {
    int bugId = 0;
    if (askExistingBugId(bugs, bugId)) {
        cout << bugText(findParent(bugs, bugId)->info) << '\n';
    }
}

void findPacket(const PacketList& packets) {
    int packetId = 0;
    if (askExistingPacketId(packets, packetId)) {
        cout << packetText(findChild(packets, packetId)->info) << '\n';
    }
}

void findLink(const CrashRelList& relations) {
    int bugId = 0;
    int packetId = 0;
    if (!askNumber("Bug ID: ", bugId) || !askNumber("Packet ID: ", packetId)) {
        return;
    }
    CrashRelNode* link = findRelation(relations, bugId, packetId);
    if (link == nullptr) {
        cout << "Not linked.\n";
    } else {
        cout << "Linked: " << linkText(link->info) << '\n';
    }
}

void showPacketsOfBug(const BugList& bugs, const CrashRelList& relations) {
    int bugId = 0;
    if (askExistingBugId(bugs, bugId)) {
        showChildOfParent(relations, bugId);
    }
}

void showBugsOfPacket(const PacketList& packets, const CrashRelList& relations) {
    int packetId = 0;
    if (askExistingPacketId(packets, packetId)) {
        showParentOfChild(relations, packetId);
    }
}

void countPacketsOfBug(const BugList& bugs, const CrashRelList& relations) {
    int bugId = 0;
    if (askExistingBugId(bugs, bugId)) {
        cout << "Packets linked to this bug: " << countChildOfParent(relations, bugId) << '\n';
    }
}

void countBugsOfPacket(const PacketList& packets, const CrashRelList& relations) {
    int packetId = 0;
    if (askExistingPacketId(packets, packetId)) {
        cout << "Bugs linked to this packet: " << countParentOfChild(relations, packetId) << '\n';
    }
}

void moveLink(BugList& bugs, PacketList& packets, CrashRelList& relations) {
    int bugId = 0;
    int packetId = 0;
    int newBugId = 0;
    int newPacketId = 0;
    cout << "To change one side only, repeat the other side's ID.\n";
    if (askNumber("Old bug ID: ", bugId) && askNumber("Old packet ID: ", packetId) &&
        askNumber("New bug ID: ", newBugId) && askNumber("New packet ID: ", newPacketId)) {
        report(editRelation(relations, bugs, packets, bugId, packetId, newBugId, newPacketId),
               "Moved the link.");
    }
}

void addKnownBugs(BugList& bugs) {
    int added = 0;
    for (int bugId = 1; bugId <= kBugCount; bugId++) {
        if (insertParent(bugs, catalogBug(bugId)) == Status::Ok) {
            added++;
        }
    }
    cout << "Added " << added << " of the " << kBugCount << " known bugs.\n";
}

void fuzz(BugList& bugs, PacketList& packets, CrashRelList& relations) {
    int count = 0;
    int seed = 0;
    if (!askNumber("How many packets (1-" + to_string(kMaxPacketsPerRun) + ")? ", count) ||
        !askNumber("Seed (0 = random): ", seed)) {
        return;
    }
    if (count < 1 || count > kMaxPacketsPerRun || seed < 0) {
        cout << "Pick 1 to " << kMaxPacketsPerRun << " packets and a seed of 0 or more.\n";
        return;
    }

    if (seed == 0) {
        seed = static_cast<int>(time(nullptr) % 1000000000);
    }
    cout << "Seed: " << seed << '\n';

    CampaignResult result = runCampaign(bugs, packets, relations, count, seed);
    cout << "Fuzzed packets: " << result.made << ". Crashed: " << result.crashed
         << ". Safe: " << result.made - result.crashed << ". Bug hits: " << result.bugHits << ".\n";
    if (result.skipped > 0) {
        cout << "Skipped bug hits: " << result.skipped
             << ". Those bugs aren't loaded yet. Load them with menu 21.\n";
    }
    if (result.made < count) {
        cout << "Stopped early: packet IDs reached the limit of " << kMaxId << ".\n";
    }
}

void printMenu() {
    cout << "\nMAUZZER (type ? to show this menu, 0 to quit)\n\n"
            " Add     1 bug            2 packet            3 link\n"
            " Delete  4 bug            5 packet            6 link\n"
            " Find    7 bug            8 packet            9 link\n"
            " List   10 all bugs      11 all packets\n"
            " Links  12 packets of a bug                  13 bugs of a packet\n"
            "        14 every bug with its packets        15 every packet with its bugs\n"
            " Count  16 packets of a bug                  17 bugs of a packet\n"
            "        18 packets with no bug               19 bugs with no packet\n"
            " Edit   20 move a link\n"
            " Fuzz   21 add the known bugs                22 fuzz\n";
}

void runMenuItem(int choice, BugList& bugs, PacketList& packets, CrashRelList& relations) {
    switch (choice) {
        case 1:  addBug(bugs); break;
        case 2:  addPacket(packets); break;
        case 3:  addLink(bugs, packets, relations); break;
        case 4:  deleteBug(bugs, relations); break;
        case 5:  deletePacket(packets, relations); break;
        case 6:  deleteLink(relations); break;
        case 7:  findBug(bugs); break;
        case 8:  findPacket(packets); break;
        case 9:  findLink(relations); break;
        case 10: showAllParent(bugs); break;
        case 11: showAllChild(packets); break;
        case 12: showPacketsOfBug(bugs, relations); break;
        case 13: showBugsOfPacket(packets, relations); break;
        case 14: showParentWithChild(bugs, relations); break;
        case 15: showChildWithParent(packets, relations); break;
        case 16: countPacketsOfBug(bugs, relations); break;
        case 17: countBugsOfPacket(packets, relations); break;
        case 18: cout << "Packets with no bug: " << countChildWithoutParent(packets, relations) << '\n'; break;
        case 19: cout << "Bugs with no packet: " << countParentWithoutChild(bugs, relations) << '\n'; break;
        case 20: moveLink(bugs, packets, relations); break;
        case 21: addKnownBugs(bugs); break;
        case 22: fuzz(bugs, packets, relations); break;
        default:
            cout << "There's no menu item " << choice << ". Type ? to see the menu.\n";
    }
}

}  // namespace

void runMenu(BugList& bugs, PacketList& packets, CrashRelList& relations) {
    printMenu();

    string line;
    while (askText("> ", line)) {
        if (trim(line) == "?") {
            printMenu();
            continue;
        }

        int choice = 0;
        if (!parseNumber(line, choice)) {
            cout << "Type a menu number, or ? to see the menu.\n";
            continue;
        }
        if (choice == 0) {
            break;
        }
        runMenuItem(choice, bugs, packets, relations);
    }
    cout << "Bye.\n";
}
