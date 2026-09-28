// Authentication.h
// ---------------------------------------------------------------------------
// Responsible for the actual business logic of the system:
//   - username / password validation rules
//   - duplicate-username checking
//   - hashing + salting passwords
//   - registering new users
//   - verifying login credentials
//
// This class owns an in-memory std::vector<User> cache (loaded from disk at
// startup) so we don't re-read the whole file on every single check. It
// stays in sync with the file by appending immediately on every successful
// registration.
// ---------------------------------------------------------------------------
#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <string>
#include <vector>
#include "User.h"
#include "FileManager.h"

// Result codes make it possible for main.cpp to display an appropriate,
// specific message without Authentication having to know anything about
// the console UI itself (separation of logic from presentation).
enum class RegisterResult {
    Success,
    InvalidUsername,
    InvalidPassword,
    UsernameTaken,
    StorageError
};

enum class LoginResult {
    Success,
    InvalidCredentials,   // deliberately covers BOTH "no such user" and
                           // "wrong password" -- see README Security section
    StorageError
};

class Authentication {
public:
    explicit Authentication(FileManager& fileManager);

    // Loads existing users from disk into memory. Returns false only on a
    // genuine I/O error (not on "file doesn't exist yet").
    bool initialize();

    // --- Validation (pure functions: no side effects, easy to unit test) ---
    // On failure, `reason` is filled with a human-readable explanation of
    // exactly which rule was violated.
    static bool isValidUsername(const std::string& username, std::string& reason);
    static bool isValidPassword(const std::string& password, std::string& reason);

    bool usernameExists(const std::string& username) const;

    // --- Core operations ---
    RegisterResult registerUser(const std::string& username, const std::string& password);
    LoginResult login(const std::string& username, const std::string& password);

    int getUserCount() const;

private:
    FileManager& fileManager;
    std::vector<User> users; // in-memory cache, kept in sync with the file

    static std::string generateSalt();
    static std::string hashPassword(const std::string& password, const std::string& salt);
};

#endif // AUTHENTICATION_H
