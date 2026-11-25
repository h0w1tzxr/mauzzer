#ifndef MAUZZER_INPUT_H
#define MAUZZER_INPUT_H

#include <string>

using namespace std;

string trim(const string& text);

// accepts an optional minus sign and up to 9 digits, so the number always fits in an int
bool parseNumber(const string& input, int& number);

// both ask functions return false when the input ends
bool askText(const string& prompt, string& text);
bool askNumber(const string& prompt, int& number);

#endif  // MAUZZER_INPUT_H
