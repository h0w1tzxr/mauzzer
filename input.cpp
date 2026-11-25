#include "input.h"

#include <cstdlib>
#include <iostream>

string trim(const string& text) {
    size_t start = text.find_first_not_of(" \t\r");
    if (start == string::npos) {
        return "";
    }
    size_t end = text.find_last_not_of(" \t\r");
    return text.substr(start, end - start + 1);
}

bool parseNumber(const string& input, int& number) {
    string text = trim(input);
    bool isNegative = !text.empty() && text[0] == '-';
    string digits = isNegative ? text.substr(1) : text;
    if (digits.empty() || digits.size() > 9) {
        return false;
    }
    for (size_t i = 0; i < digits.size(); i++) {
        if (digits[i] < '0' || digits[i] > '9') {
            return false;
        }
    }

    number = atoi(digits.c_str());
    if (isNegative) {
        number = -number;
    }
    return true;
}

bool askText(const string& prompt, string& text) {
    cout << prompt;
    getline(cin, text);
    return !cin.fail();
}

bool askNumber(const string& prompt, int& number) {
    string text;
    while (askText(prompt, text)) {
        if (parseNumber(text, number)) {
            return true;
        }
        cout << "Enter a whole number, up to 9 digits.\n";
    }
    return false;
}
