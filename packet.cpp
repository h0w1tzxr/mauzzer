#include "packet.h"

#include <iostream>

Status insertChild(PacketList& L, const PacketInfo& info) {
    if (info.packetId < 1 || info.packetId > kMaxId ||
        info.type < 0 || info.type > kMaxTlvType ||
        info.declaredLength < 0 || info.actualSize < 0) {
        return Status::InvalidValue;
    }
    if (findChild(L, info.packetId) != nullptr) {
        return Status::DuplicateId;
    }
    appendChild(L, info);
    return Status::Ok;
}

PacketNode* appendChild(PacketList& L, const PacketInfo& info) {
    PacketNode* node = new PacketNode{info, nullptr};
    if (L.last == nullptr) {
        L.first = node;
    } else {
        L.last->next = node;
    }
    L.last = node;
    return node;
}

PacketNode* findChild(const PacketList& L, int packetId) {
    for (PacketNode* packet = L.first; packet != nullptr; packet = packet->next) {
        if (packet->info.packetId == packetId) {
            return packet;
        }
    }
    return nullptr;
}

void showAllChild(const PacketList& L) {
    if (L.first == nullptr) {
        cout << "No packets yet.\n";
        return;
    }
    for (const PacketNode* packet = L.first; packet != nullptr; packet = packet->next) {
        cout << packetText(packet->info) << '\n';
    }
}

string packetText(const PacketInfo& info) {
    return "Packet " + to_string(info.packetId) + ": type " + to_string(info.type) +
           ", length " + to_string(info.declaredLength) + ", size " + to_string(info.actualSize) +
           ", hex \"" + info.rawHex + "\"";
}
