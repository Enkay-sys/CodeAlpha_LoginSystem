// FileManager.cpp
#include "FileManager.h"
#include <fstream>
#include <sstream>

FileManager::FileManager(const std::string& filename) : filename(filename) {}

bool FileManager::fileExists() const {
    std::ifstream file(filename);
    return file.good();
}

bool FileManager::loadUsers(std::vector<User>& outUsers, int& malformedLinesSkipped) const {
    outUsers.clear();
    malformedLinesSkipped = 0;

    std::ifstream file(filename);

    // If the file simply doesn't exist yet (first run), that's not an
    // error — it just means there are zero registered users so far.
    if (!file.is_open()) {
        return true;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        // A valid line has exactly 3 fields separated by '|'.
        std::stringstream ss(line);
        std::string username, salt, hashedPassword;

        if (!std::getline(ss, username, '|')) { ++malformedLinesSkipped; continue; }
        if (!std::getline(ss, salt, '|'))      { ++malformedLinesSkipped; continue; }
        if (!std::getline(ss, hashedPassword)) { ++malformedLinesSkipped; continue; }

        if (username.empty() || salt.empty() || hashedPassword.empty()) {
            ++malformedLinesSkipped;
            continue;
        }

        outUsers.emplace_back(username, salt, hashedPassword);
    }

    // file goes out of scope here -> destructor closes it automatically
    // (RAII). We don't need to call file.close() manually, though doing so
    // explicitly is also acceptable style.
    return true;
}

bool FileManager::appendUser(const User& user) const {
    // std::ios::app opens the file in "append" mode: writes go to the end
    // of the file instead of overwriting it. If the file does not exist
    // yet, ofstream creates it.
    std::ofstream file(filename, std::ios::app);

    if (!file.is_open()) {
        return false;
    }

    file << user.getUsername() << '|' << user.getSalt() << '|' << user.getHashedPassword() << '\n';

    // Explicitly check the stream's fail bit after writing, in case the
    // disk is full or another I/O error occurred mid-write.
    return !file.fail();
}
