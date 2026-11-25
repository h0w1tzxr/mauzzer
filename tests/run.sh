#!/usr/bin/env bash
# tests/run.sh            AddressSanitizer and UBSan
# tests/run.sh valgrind   valgrind (skips the memory limit and speed scenarios)
set -u

mode=${1:-asan}
src=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ "$mode" = valgrind ]; then
    flags="-g -O1"; runner="valgrind -q --leak-check=full --error-exitcode=9"; limit=300
else
    flags="-g -fsanitize=address,undefined -fno-sanitize-recover=all"; runner=""; limit=20
fi
g++ -std=c++11 -Wall -Wextra $flags "$src"/*.cpp -o "$work/mauzzer" || exit 1
g++ -std=c++11 -Wall -Wextra $flags "$src/fuzzer.cpp" "$src/tests/parser.cpp" -o "$work/parser" || exit 1
g++ -std=c++11 -Wall -Wextra -O2 "$src"/*.cpp -o "$work/plain" || exit 1

failures=0
bad() { echo "  FAIL: $*"; failures=$((failures + 1)); }

run() {
    timeout "$limit" $runner "$work/mauzzer" >"$work/$1" 2>&1
    [ $? -eq 0 ] || bad "$1: exit code is not 0 (crash, hang, sanitizer, or valgrind)"
    grep -qE 'Sanitizer|runtime error|^==[0-9]+==' "$work/$1" && bad "$1: sanitizer or valgrind reported an error"
}

count()        { grep -cF -- "$2" "$work/$1"; }
has()          { grep -qF -- "$2" "$work/$1" || bad "$1 must contain: $2"; }
hasnt()        { grep -qF -- "$2" "$work/$1" && bad "$1 must not contain: $2"; }
expect_count() { [ "$(count "$1" "$2")" -eq "$3" ] || bad "$1: '$2' must appear $3 times, found $(count "$1" "$2")"; }
number_at()    { grep -F -- "$2" "$work/$1" | sed -n "${3}p" | awk '{ print $NF }'; }
before() {
    local a b
    a=$(grep -nF -- "$2" "$work/$1" | head -1 | cut -d: -f1)
    b=$(grep -nF -- "$3" "$work/$1" | head -1 | cut -d: -f1)
    { [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; } || bad "$1: '$2' must come before '$3'"
}
after() { awk -v m="$2" 'index($0, m) { buf = "" } { buf = buf $0 "\n" } END { printf "%s", buf }' "$work/$1"; }

# recomputes the expected links from the spec, without any Mauzzer code
check_packet_report() {
    awk '
    function finish() {
        if (id == "") return
        want = ""
        if (len + 0 > size + 0)                            want = want " bug1"
        if (index(hex, "DE AD") || index(hex, "DEADBEEF")) want = want " bug2"
        if (type + 0 == 2 && len + 0 == 0)                 want = want " bug3"
        if (size + 0 < 2)                                  want = want " bug4"
        if (got != want) { print "  FAIL: packet " id " has [" got " ] but the spec says [" want " ]"; bad++ }
        total++
    }
    /^Packet [0-9]+:/ {
        finish()
        id = $2; sub(":", "", id)
        type = $4; sub(",", "", type)
        len = $6;  sub(",", "", len)
        size = $8; sub(",", "", size)
        hex = substr($0, index($0, "hex \""))
        got = ""
        next
    }
    /^    -> Bug [0-9]+:/ { n = $3; sub(":", "", n); got = got " bug" n }
    END {
        finish()
        if (total == 0) { print "  FAIL: no packets in the report"; exit 1 }
        exit bad > 0
    }' "$work/$1" || failures=$((failures + 1))
}

add_bug()       { printf '1\n%s\n%s\n%s\n' "$@"; }            # id name severity
add_packet()    { printf '2\n%s\n%s\n%s\n%s\n%s\n' "$@"; }    # id type length size hex
link()          { printf '3\n%s\n%s\n%s\n%s\n' "$@"; }        # bug packet offset note
del_bug()       { printf '4\n%s\n' "$1"; }
del_packet()    { printf '5\n%s\n' "$1"; }
unlink_pair()   { printf '6\n%s\n%s\n' "$1" "$2"; }
find_bug()      { printf '7\n%s\n' "$1"; }
find_packet()   { printf '8\n%s\n' "$1"; }
find_link()     { printf '9\n%s\n%s\n' "$1" "$2"; }
list_bugs()     { printf '10\n'; }
list_packets()  { printf '11\n'; }
packets_of()    { printf '12\n%s\n' "$1"; }
bugs_of()       { printf '13\n%s\n' "$1"; }
every_bug()     { printf '14\n'; }
every_packet()  { printf '15\n'; }
count_packets() { printf '16\n%s\n' "$1"; }
count_bugs()    { printf '17\n%s\n' "$1"; }
count_no_bug()  { printf '18\n'; }
count_no_pkt()  { printf '19\n'; }
move_link()     { printf '20\n%s\n%s\n%s\n%s\n' "$@"; }       # bug packet newBug newPacket
known_bugs()    { printf '21\n'; }
fuzz()          { printf '22\n%s\n%s\n' "$1" "$2"; }          # count seed
marker()        { printf '99\n'; }                            # not a menu item, so it marks the output

echo "P. Parser and mutator"
$runner "$work/parser" || bad "parser: see the messages above"

echo "A. Fuzz campaign"
triage() { every_bug; every_packet; for id in 1 2 3 4; do count_packets $id; done; count_no_bug; count_no_pkt; }

run a1  < <(known_bugs; fuzz 60 20241; triage)
run a1b < <(known_bugs; fuzz 60 20241; triage)
run a2  < <(known_bugs; fuzz 60 20242; triage)

has a1 "Added 4 of the 4 known bugs."
has a1 "Seed: 20241"
has a1 "Fuzzed packets: 60."
cmp -s "$work/a1" "$work/a1b" || bad "the same seed must give identical output"
cmp -s <(grep '^Packet ' "$work/a1") <(grep '^Packet ' "$work/a2") && bad "a different seed must give different packets"
check_packet_report a1
check_packet_report a2

hits=$(sed -n 's/^Fuzzed packets: .* Bug hits: \([0-9]*\)\.$/\1/p' "$work/a1")
crashed=$(sed -n 's/^Fuzzed packets: [0-9]*\. Crashed: \([0-9]*\)\..*/\1/p' "$work/a1")
safe=$(sed -n 's/^Fuzzed packets: .* Safe: \([0-9]*\)\. Bug hits.*/\1/p' "$work/a1")
from_bugs=$(count a1 '    -> Packet ')
from_packets=$(count a1 '    -> Bug ')
from_counts=$(grep -F 'Packets linked to this bug:' "$work/a1" | awk '{ s += $NF } END { print s + 0 }')
[ "${hits:-0}" -gt 0 ] || bad "a1: the fuzzer must find at least one bug"
[ "$hits" -eq "$from_bugs" ]    || bad "a1: summary says $hits hits, the bug report shows $from_bugs"
[ "$hits" -eq "$from_packets" ] || bad "a1: summary says $hits hits, the packet report shows $from_packets"
[ "$hits" -eq "$from_counts" ]  || bad "a1: summary says $hits hits, the counts add up to $from_counts"
[ "$((crashed + safe))" -eq 60 ] || bad "a1: crashed ($crashed) + safe ($safe) must be 60"
[ "$(number_at a1 'Packets with no bug:' 1)" -eq "$safe" ] || bad "a1: 'Packets with no bug' must equal the safe count ($safe)"
idle=$(count a1 'Packets linked to this bug: 0')
[ "$(number_at a1 'Bugs with no packet:' 1)" -eq "$idle" ] || bad "a1: 'Bugs with no packet' must be $idle"

run a0 < <(known_bugs; fuzz 3 0)
grep -qE 'Seed: [1-9][0-9]*' "$work/a0" || bad "a0: seed 0 must print a real, non-zero seed"

run a3a < <(known_bugs; fuzz 60 20241; fuzz 40 777; marker; list_packets)
has a3a "Fuzzed packets: 40."
after a3a "no menu item" >"$work/a3a.final"
has a3a.final "Packet 1: "
has a3a.final "Packet 100: "
hasnt a3a.final "Packet 101: "
expect_count a3a.final "Packet " 100

run a3 < <(known_bugs; fuzz 60 20241; count_no_bug; fuzz 40 777; count_no_bug; del_bug 1; count_packets 1; count_no_bug; fuzz 30 5)
safe_1=$(number_at a3 'Packets with no bug:' 1)
safe_2=$(number_at a3 'Packets with no bug:' 2)
safe_3=$(number_at a3 'Packets with no bug:' 3)
[ "$safe_2" -ge "$safe_1" ] || bad "a3: the second batch must not reduce the safe packets ($safe_1 -> $safe_2)"
[ "$safe_3" -gt "$safe_2" ] || bad "a3: deleting bug 1 must add safe packets ($safe_2 -> $safe_3)"
has a3 "Deleted the bug and its links."
has a3 "No bug has that ID."
grep -qE "Skipped bug hits: [1-9]" "$work/a3" || bad "a3: fuzzing after bug 1 is gone must report skipped bug hits"

echo "B. Bug reports from a tester"
run b < <(
    known_bugs
    known_bugs                              # loading twice must not add duplicates
    add_packet 7001 2 0 4 "02 00 41 42";   link 3 7001 1 "len=0 on type 2"
    add_packet 7002 1 255 4 "01 FF 41 42"; link 1 7002 1 "len 255, 4 data bytes"
    add_packet 7002 1 4 4 "00"
    link 9 7002 0 "wrong bug ID"
    link 1 7022 0 "wrong packet ID"
    link 1 7002 -1 "negative offset"
    link 1 7002 1 "duplicate ticket"
    add_bug 6 "Bad severity" 9
    add_bug 6 "   " 3
    add_bug 5 "Integer Overflow in len*4" 5
    add_bug 5 "Duplicate bug" 3
    add_packet 7003 1 5 5 "de ad be ef 01"
    link 1 7003 2 "wrong: thought it was an over-read"
    move_link 1 7003 2 7003
    link 5 7003 0 "overflow on len*4"
    add_packet 7004 1 4 4 "41 42 43 44"
    add_packet 7005 2 0 2 "02 00"
    link 3 7004 1 "wrong packet"
    move_link 3 7004 3 7005
    move_link 3 7005 3 7999                 # the new packet doesn't exist
    move_link 3 7005 3 7001                 # the new pair is already linked
    move_link 9 9 1 1                       # the old pair isn't linked
    link 3 7002 0 "wrong bug"
    unlink_pair 3 7002                      # the other links of bug 3 must stay
    find_bug 5; find_packet 7003; find_link 2 7003; find_link 1 7003; find_link 3 7002; find_link 3 7001
    packets_of 3; bugs_of 7003
    count_packets 3; count_bugs 7003; count_no_bug; count_no_pkt
    del_packet 7003      # middle, 2 links
    del_bug 3            # middle, 2 links
    del_packet 7001      # head
    del_packet 7005      # tail
    del_bug 5            # tail
    del_bug 1            # head, 1 link
    marker
    list_bugs; list_packets; every_bug; every_packet; count_no_bug; count_no_pkt; find_bug 5; count_bugs 7003
)

has b "Added 4 of the 4 known bugs."
has b "Added 0 of the 4 known bugs."
expect_count b "Added the bug." 1
expect_count b "Added the packet." 5
expect_count b "Linked them." 6
expect_count b "Moved the link." 2
expect_count b "Deleted the link." 1
expect_count b "That ID already exists." 2
expect_count b "Those two are already linked." 2
expect_count b "No bug has that ID." 2
expect_count b "No packet has that ID." 3
expect_count b "Those two aren't linked." 1
expect_count b "That value didn't work." 3
has b "Linked: hit at byte 1 (len=0 on type 2)"
has b "hit at byte 2 (wrong: thought it was an over-read)"
has b "Not linked."
has b "Bug 5: Integer Overflow in len*4 (severity 5)"
has b "Packets linked to this bug: 2"
has b "Bugs linked to this packet: 2"
has b "Packets with no bug: 1"
has b "Bugs with no packet: 1"
expect_count b "Deleted the packet and its links." 3
expect_count b "Deleted the bug and its links." 3

after b "no menu item" >"$work/b.final"
has b.final "Bug 2: "
has b.final "Bug 4: "
has b.final "Packet 7002: "
has b.final "Packet 7004: "
for gone in "Bug 1: " "Bug 3: " "Bug 5: " "Packet 7001: " "Packet 7003: " "Packet 7005: "; do
    hasnt b.final "$gone"
done
expect_count b.final "(no links)" 4
has b.final "Packets with no bug: 2"
has b.final "Bugs with no packet: 2"
has b.final "No bug has that ID."
has b.final "No packet has that ID."

echo "B2. Deleting the last node, then adding again"
run b2 < <(
    known_bugs; add_bug 5 "Five" 1; add_bug 6 "Six" 1; del_bug 6; add_bug 7 "Seven" 1
    add_packet 1 1 4 4 "41"; add_packet 2 1 4 4 "41"; add_packet 3 1 4 4 "41"
    link 1 3 0 "x"; del_packet 3
    add_packet 4 1 4 4 "41"; link 2 4 0 "y"
    del_packet 1; del_packet 2; del_packet 4              # the list is empty now
    add_packet 9 1 4 4 "41"; fuzz 5 3                     # fuzzing continues from ID 10
    marker; list_packets; list_bugs
)
after b2 "no menu item" >"$work/b2.final"
expect_count b2.final "Packet " 6
before b2.final "Packet 9: " "Packet 10: "
before b2.final "Packet 10: " "Packet 14: "
for gone in "Packet 1: " "Packet 2: " "Packet 3: " "Packet 4: "; do hasnt b2.final "$gone"; done
expect_count b2.final "Bug " 6
before b2.final "Bug 5: " "Bug 7: "
hasnt b2.final "Bug 6: "

echo "C. Careless operator and hostile input"
long=$(head -c 100000 /dev/zero | tr '\0' 'A')
run c1 < <(
    printf 'abc\n\n99999999999999\n1e3\n0x10\n5\0junk\n-1\n'   # 6 non-numbers (one has a NUL byte), then -1
    add_bug 0 "x" 3; add_bug -5 "x" 3; add_bug 1000000 "x" 3
    add_bug 1 "" 3; printf '1\n1\n   \n3\n'; add_bug 1 "x" 6; add_bug 1 "x" 0
    add_bug 999999 "upper limit" 5
    add_packet 999999 255 0 0 ""
    add_packet 5 256 1 1 "x"; add_packet 5 -1 1 1 "x"; add_packet 5 1 -1 1 "x"
    add_packet 5 1 1 -1 "x"; add_packet 0 1 1 1 "x"
    link 999999 999999 -1 "x"; link 999999 999999 0 "limit"
    add_packet 1 1 4 4 "$long"; link 999999 1 0 "$long"
    fuzz 5 3
    fuzz 0 1; fuzz 1001 1; fuzz 5 -1
    list_packets
)
expect_count c1 "Type a menu number, or ? to see the menu." 6
expect_count c1 "There's no menu item -1." 1
expect_count c1 "That value didn't work." 13
expect_count c1 "Added the bug." 1
expect_count c1 "Added the packet." 2
expect_count c1 "Linked them." 2
has c1 "Stopped early: packet IDs reached the limit of 999999."
has c1 "Fuzzed packets: 0."
expect_count c1 "Pick 1 to 1000 packets and a seed of 0 or more." 3
has c1 "Bye."

run c1b < <(printf '?\n7\nx\n\n5 \n  \n-\n')                     # ? shows the menu; bad numbers ask again
has c1b "Enter a whole number, up to 9 digits."
has c1b "No bug has that ID."                                    # "5 " counts as 5
expect_count c1b "Add     1 bug" 2

run c1c < <(printf '0\n10\n')                                    # 0 quits, so nothing after it runs
has c1c "Bye."
hasnt c1c "No bugs yet."

run c2 < <(
    list_bugs; list_packets; every_bug; every_packet
    packets_of 1; bugs_of 1; find_bug 1; find_packet 1; find_link 1 1
    del_bug 1; del_packet 1; unlink_pair 1 1; count_packets 1; count_bugs 1
    count_no_bug; count_no_pkt; move_link 1 1 1 1
)
expect_count c2 "No bugs yet." 2
expect_count c2 "No packets yet." 2
expect_count c2 "No bug has that ID." 4
expect_count c2 "No packet has that ID." 4
expect_count c2 "Those two aren't linked." 2
has c2 "Not linked."
has c2 "Packets with no bug: 0"
has c2 "Bugs with no packet: 0"

# no known bugs loaded: fuzzing still works and reports what it skipped
run c2b < <(fuzz 20 9)
has c2b "Fuzzed packets: 20."
grep -qE "Skipped bug hits: [1-9]" "$work/c2b" || bad "c2b: fuzzing without the known bugs must report skipped bug hits"

# a link to freed memory must never show up
churn() { for _ in $(seq 100); do add_bug 7 "Temporary bug" 3; add_packet 7 1 4 4 "41"; link 7 7 0 "x"; del_bug 7; del_packet 7; done; }
run c3 < <(churn; add_bug 7 "New bug" 3; add_packet 7 1 4 4 "41"; count_packets 7; count_bugs 7; every_bug)
for failure in "already exists" "No bug has" "No packet has" "aren't linked" "didn't work"; do hasnt c3 "$failure"; done
expect_count c3 "Deleted the bug and its links." 100
has c3 "Packets linked to this bug: 0"
has c3 "Bugs linked to this packet: 0"
has c3 "(no links)"

run c4 < <(printf '1\n5\n')
has c4 "Bye."
run c5 < <(printf '')
has c5 "Bye."

echo "D. Chaos"
# repeatable random lines, never 0 because 0 quits
chaos_input() {
    awk -v seed="$1" 'BEGIN {
        srand(seed)
        for (i = 0; i < 20000; i++) {
            r = rand()
            if (r < 0.40)      print int(rand() * 22) + 1
            else if (r < 0.70) { v = int(rand() * 14) - 2; print (v == 0 ? 7 : v) }
            else if (r < 0.78) print int(rand() * 300) + 1
            else if (r < 0.84) print "abc" int(rand() * 9)
            else if (r < 0.88) print ""
            else if (r < 0.92) print "41 42 DE AD BE EF"
            else if (r < 0.95) print "99999999999"
            else               print "random note " i
        }
    }'
}
for seed in 1 2 3 4 5 6; do run d$seed < <(chaos_input $seed); done
cat "$work"/d[1-6] >"$work/d_all"
for text in "Added the bug." "Added the packet." "Linked them." "Deleted the bug and its links." \
            "Deleted the packet and its links." "That ID already exists." "Those two are already linked." \
            "No bug has that ID." "Fuzzed"; do
    has d_all "$text"       # chaos must reach the deep operations
done

run d_closed <&-            # closed stdin
has d_closed "Bye."

huge=$(head -c 5000000 /dev/zero | tr '\0' 'B')
run d_big < <(add_bug 1 "$huge" 3; add_packet 1 1 4 4 "$huge"; link 1 1 0 "$huge"; every_bug; every_packet)
has d_big "Added the bug."
has d_big "Added the packet."
has d_big "Linked them."

if [ "$mode" = asan ]; then
    # 40 MB limit: must exit 1 with a message, not abort (134)
    oom_input() { known_bugs; for _ in $(seq 400); do fuzz 1000 1; done; }
    oom_input >"$work/oom.in"
    if ( ulimit -v 40000 ) 2>/dev/null; then
        ( ulimit -v 40000; timeout 60 "$work/plain" <"$work/oom.in" >"$work/d_oom" 2>&1; echo $? >"$work/d_oom.exit" )
        [ "$(cat "$work/d_oom.exit")" -eq 1 ] || bad "d_oom: exit code must be 1, found $(cat "$work/d_oom.exit") (134 = abort, 124 = too slow)"
        has d_oom "Out of memory. Stopping."
        hasnt d_oom "terminate called"
    else
        echo "  (skipped: ulimit -v is not supported)"
    fi
fi

if [ "$mode" = asan ]; then
    echo "E. Speed"
    perf_input() { known_bugs; for _ in $(seq 60); do fuzz 1000 5; done; }
    perf_input >"$work/perf.in"
    started=$(date +%s%N)
    timeout 30 "$work/plain" <"$work/perf.in" >"$work/e" 2>&1
    code=$?
    elapsed=$(( ($(date +%s%N) - started) / 1000000 ))
    [ "$code" -eq 0 ] || bad "e: exit code $code (124 = more than 30 seconds)"
    [ "$elapsed" -lt 5000 ] || bad "e: 60,000 packets took $elapsed ms, the limit is 5000 ms"
    expect_count e "Fuzzed packets: 1000." 60
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "All scenarios passed."
else
    echo "$failures checks failed."
    exit 1
fi
