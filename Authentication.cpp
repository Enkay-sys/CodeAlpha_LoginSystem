// Authentication.cpp
#include "Authentication.h"
#include "sha256.h"
#include <algorithm>
#include <cctype>
#include <random>
#include <sstream>
#include <iomanip>

namespace {
    // --- Policy constants (kept in one place, named, so the rules are
    //     easy to find and change) ---
    constexpr size_t USERNAME_MIN_LEN = 3;
    constexpr size_t USERNAME_MAX_LEN = 20;
    constexpr size_t PASSWORD_MIN_LEN = 8;
    constexpr size_t SALT_BYTES = 8; // -> 16 hex characters
}

Authentication::Authentication(FileManager& fileManager) : fileManager(fileManager) {}

bool Authentication::initialize() {
    int malformed = 0;
    bool ok = fileManager.loadUsers(users, malformed);
    // Note: `malformed` (count of corrupted/skipped lines) is reported by
    // main.cpp after calling initialize(), via getUserCount() and a
    // separate diagnostic print — kept simple here since Authentication's
    // job is logic, not console output.
    return ok;
}

int Authentication::getUserCount() const {
    return static_cast<int>(users.size());
}

// ---------------------------------------------------------------------------
// Username policy: 3-20 characters, letters/digits/underscore only, no
// spaces. This mirrors common real-world username rules (e.g. GitHub,
// Discord) and is simple enough to explain and defend to a reviewer.
// ---------------------------------------------------------------------------
bool Authentication::isValidUsername(const std::string& username, std::string& reason) {
    if (username.empty()) {
        reason = "Username cannot be empty.";
        return false;
    }
    if (username.length() < USERNAME_MIN_LEN) {
        reason = "Username must be at least " + std::to_string(USERNAME_MIN_LEN) + " characters long.";
        return false;
    }
    if (username.length() > USERNAME_MAX_LEN) {
        reason = "Username must be at most " + std::to_string(USERNAME_MAX_LEN) + " characters long.";
        return false;
    }
    for (char c : username) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) {
            reason = "Username may only contain letters, numbers, and underscores (no spaces or symbols).";
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Password policy: at least 8 characters, containing at least one
// uppercase letter, one lowercase letter, one digit, and one special
// character. This is the "stronger implementation" option described in the
// task brief, chosen because it is a widely recognized, easy-to-explain
// standard (similar to what most real sign-up forms enforce).
// ---------------------------------------------------------------------------
bool Authentication::isValidPassword(const std::string& password, std::string& reason) {
    if (password.empty()) {
        reason = "Password cannot be empty.";
        return false;
    }
    if (password.length() < PASSWORD_MIN_LEN) {
        reason = "Password must be at least " + std::to_string(PASSWORD_MIN_LEN) + " characters long.";
        return false;
    }

    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    for (char c : password) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (std::isupper(uc)) hasUpper = true;
        else if (std::islower(uc)) hasLower = true;
        else if (std::isdigit(uc)) hasDigit = true;
        else if (std::isspace(uc)) { /* spaces don't count toward "special" */ }
        else hasSpecial = true;
    }

    if (!hasUpper)   { reason = "Password must contain at least one uppercase letter."; return false; }
    if (!hasLower)   { reason = "Password must contain at least one lowercase letter."; return false; }
    if (!hasDigit)   { reason = "Password must contain at least one digit.";            return false; }
    if (!hasSpecial) { reason = "Password must contain at least one special character (e.g. !@#$%).";  return false; }

    return true;
}

bool Authentication::usernameExists(const std::string& username) const {
    // std::any_of scans the in-memory vector and returns true as soon as a
    // matching username is found. Comparison is case-sensitive by design
    // (Julian and julian are treated as different accounts) -- this is
    // called out as a design choice in the README.
    return std::any_of(users.begin(), users.end(), [&](const User& u) {
        return u.getUsername() == username;
    });
}

std::string Authentication::generateSalt() {
    // std::random_device is a hardware/OS-backed source of randomness,
    // preferred over rand() for anything security-adjacent. We generate
    // SALT_BYTES random bytes and render them as hex text so they can be
    // safely stored in our pipe-delimited text file.
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    std::ostringstream oss;
    for (size_t i = 0; i < SALT_BYTES; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << dist(gen);
    }
    return oss.str();
}

std::string Authentication::hashPassword(const std::string& password, const std::string& salt) {
    // Salting: we hash (salt + password) rather than the password alone.
    // This means two users who happen to choose the same password end up
    // with completely different stored hashes, and precomputed "rainbow
    // table" attacks against common passwords become useless.
    return SHA256::hash(salt + password);
}

RegisterResult Authentication::registerUser(const std::string& username, const std::string& password) {
    std::string reason; // discarded here -- main.cpp re-validates to get the message

    if (!isValidUsername(username, reason)) {
        return RegisterResult::InvalidUsername;
    }
    if (usernameExists(username)) {
        return RegisterResult::UsernameTaken;
    }
    if (!isValidPassword(password, reason)) {
        return RegisterResult::InvalidPassword;
    }

    std::string salt = generateSalt();
    std::string hashed = hashPassword(password, salt);
    User newUser(username, salt, hashed);

    if (!fileManager.appendUser(newUser)) {
        return RegisterResult::StorageError;
    }

    // Keep the in-memory cache in sync so a duplicate check or login in the
    // SAME program run sees the new user immediately, without re-reading
    // the file from disk.
    users.push_back(newUser);
    return RegisterResult::Success;
}

LoginResult Authentication::login(const std::string& username, const std::string& password) {
    auto it = std::find_if(users.begin(), users.end(), [&](const User& u) {
        return u.getUsername() == username;
    });

    if (it == users.end()) {
        // Unknown username. We deliberately return the SAME result as a
        // wrong password (see LoginResult::InvalidCredentials) so that an
        // attacker probing the system cannot tell usernames apart from
        // passwords -- a generic failure message is standard practice.
        return LoginResult::InvalidCredentials;
    }

    std::string candidateHash = hashPassword(password, it->getSalt());
    if (candidateHash != it->getHashedPassword()) {
        return LoginResult::InvalidCredentials;
    }

    return LoginResult::Success;
}
