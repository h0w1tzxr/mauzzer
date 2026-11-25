// the menu only feeds the parser packets from the mutator, so a value like actualSize = 2
// can only be tested here
#include <cstdlib>
#include <iostream>
#include <string>

#include "../fuzzer.h"

static int failures = 0;

static void expect(bool ok, int line, const char* what)
{
    if (!ok) {
        cout << "  FAIL line " << line << ": " << what << '\n';
        ++failures;
    }
}
#define EXPECT(cond) expect((cond), __LINE__, #cond)

// the bugs a packet triggers as digits: "13" means bugs 1 and 3, "" means safe
static string hits(int type, int len, int size, const char* hex)
{
    const PacketInfo packet{1, type, len, size, hex};
    string result;
    for (int id = 1; id <= kBugCount; ++id) {
        if (runTargetParser(packet, id)) {
            result += static_cast<char>('0' + id);
        }
    }
    return result;
}

static void testRules()
{
    EXPECT(hits(1, 4, 4, "41 42 43 44") == "");  

    EXPECT(hits(1, 5, 4, "41") == "1");        
    EXPECT(hits(1, 4, 4, "41") == "");         
    EXPECT(hits(1, 3, 4, "41") == "");

    EXPECT(hits(1, 4, 4, "DE AD") == "2");
    EXPECT(hits(1, 4, 4, "DEADBEEF") == "2");
    EXPECT(hits(1, 4, 4, "41 DE AD BE EF") == "2");
    EXPECT(hits(1, 4, 4, "DE  AD") == "");     
    EXPECT(hits(1, 4, 4, "DEAD") == "");
    EXPECT(hits(1, 4, 4, "DE AB") == "");

    EXPECT(hits(2, 0, 4, "41") == "3");
    EXPECT(hits(2, 1, 4, "41") == "");         
    EXPECT(hits(1, 0, 4, "41") == "");         

    EXPECT(hits(1, 1, 1, "41") == "4");        
    EXPECT(hits(1, 2, 2, "41") == "");         
    EXPECT(hits(1, 0, 0, "") == "4");

    EXPECT(hits(1, 4, 1, "41") == "14");
    EXPECT(hits(2, 0, 0, "") == "34");
    EXPECT(hits(2, 255, 1, "DE AD") == "124");

    const PacketInfo any{1, 2, 0, 0, ""};
    EXPECT(!runTargetParser(any, 0) && !runTargetParser(any, kBugCount + 1) && !runTargetParser(any, -1));
}

static void testCatalog()
{
    EXPECT(catalogBug(1).bugName == "Buffer Over-Read");
    EXPECT(catalogBug(2).bugName == "Magic Byte NullPtr");
    EXPECT(catalogBug(3).bugName == "Zero-Length Underflow");
    EXPECT(catalogBug(4).bugName == "Truncated Header");
    EXPECT(catalogHit(1).hitOffset == 1 && catalogHit(2).hitOffset == 2);
    EXPECT(catalogHit(3).hitOffset == 1 && catalogHit(4).hitOffset == 0);
    for (int id = 1; id <= kBugCount; ++id) {
        const BugInfo bug = catalogBug(id);
        EXPECT(bug.bugId == id && bug.severity >= 1 && bug.severity <= kMaxSeverity);
        EXPECT(!catalogHit(id).note.empty());
    }
}

static void testMutator()
{
    bool seen[5] = {false, false, false, false, false};
    int safe = 0;
    int multi = 0;
    srand(12345);
    for (int i = 1; i <= 20000; ++i) {
        const PacketInfo p = mutatePacket(i);
        const bool known = p.packetId == i && (p.type == 1 || p.type == 2) &&
                           (p.declaredLength == 4 || p.declaredLength == 255 || p.declaredLength == 0) &&
                           (p.actualSize == 4 || p.actualSize == 1) &&
                           p.rawHex.compare(0, 11, "41 42 43 44") == 0;
        const bool changed = p.type != 1 || p.declaredLength != 4 || p.actualSize != 4 ||
                             p.rawHex != "41 42 43 44";
        if (!known || !changed) {
            EXPECT(known && changed);
            return;
        }
        seen[0] = seen[0] || p.declaredLength == 255;
        seen[1] = seen[1] || p.declaredLength == 0;
        seen[2] = seen[2] || p.rawHex.size() > 11;
        seen[3] = seen[3] || p.type == 2;
        seen[4] = seen[4] || p.actualSize == 1;
        const string result = hits(p.type, p.declaredLength, p.actualSize, p.rawHex.c_str());
        safe += result.empty();
        multi += result.size() > 1;
    }
    for (bool kind : seen) {
        EXPECT(kind);
    }
    EXPECT(safe > 0 && multi > 0);
}

static string batch(unsigned seed)
{
    srand(seed);
    string all;
    for (int i = 1; i <= 50; ++i) {
        const PacketInfo p = mutatePacket(i);
        all += to_string(p.type) + "/" + to_string(p.declaredLength) + "/" +
               to_string(p.actualSize) + "/" + p.rawHex + ";";
    }
    return all;
}

int main()
{
    testRules();
    testCatalog();
    testMutator();
    EXPECT(batch(42) == batch(42));
    EXPECT(batch(42) != batch(43));
    return failures != 0;
}
