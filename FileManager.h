// FileManager.h
// ---------------------------------------------------------------------------
// Responsible for ALL interaction with the persistent storage file
// (users.txt). Nothing else in the program opens that file directly.
//
// Storage format (one line per user, pipe-delimited):
//     username|salt|hashedPassword
//
// Example line:
//     Julian|9f3a7b2c|5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d
//
// We store the salt in plain text alongside the hash. This is standard
// practice: the salt is not a secret, its purpose is only to make every
// user's hash unique (defeating precomputed "rainbow table" attacks) and to
// ensure two users with the same password don't get the same hash.
// ---------------------------------------------------------------------------
#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <string>
#include <vector>
#include "User.h"

class FileManager {
public:
    explicit FileManager(const std::string& filename);

    // Returns true if the file exists and could be opened for reading.
    // (A missing file is not treated as an error at startup — it just
    // means there are no registered users yet.)
    bool fileExists() const;

    // Reads every record from disk into memory. Returns false only if the
    // file exists but could not be opened/read (e.g. permissions problem).
    // Malformed lines are skipped (and counted) rather than crashing the
    // program; see loadUsers()'s implementation comments.
    bool loadUsers(std::vector<User>& outUsers, int& malformedLinesSkipped) const;

    // Appends a single new user record to the end of the file.
    // Returns false if the file could not be opened for writing.
    bool appendUser(const User& user) const;

private:
    std::string filename;
};

#endif // FILE_MANAGER_H
