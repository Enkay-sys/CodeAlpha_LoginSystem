// User.h
// ---------------------------------------------------------------------------
// Represents a single user account in memory. This class only knows how to
// HOLD user data (username, salt, hashed password) — it does not know how
// to validate rules, hash things, or talk to files. That separation of
// concerns is intentional (see README -> Architecture).
// ---------------------------------------------------------------------------
#ifndef USER_H
#define USER_H

#include <string>

class User {
public:
    User() = default;
    User(const std::string& username, const std::string& salt, const std::string& hashedPassword);

    // --- Accessors (read-only views into the object's private state) ---
    const std::string& getUsername() const;
    const std::string& getSalt() const;
    const std::string& getHashedPassword() const;

private:
    std::string username;        // The account's unique identifier
    std::string salt;            // Random per-user salt, stored alongside the hash
    std::string hashedPassword;  // SHA-256(salt + password), never the raw password
};

#endif // USER_H
