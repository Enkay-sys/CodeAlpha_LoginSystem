// User.cpp
#include "User.h"

User::User(const std::string& username, const std::string& salt, const std::string& hashedPassword)
    : username(username), salt(salt), hashedPassword(hashedPassword) {}

const std::string& User::getUsername() const {
    return username;
}

const std::string& User::getSalt() const {
    return salt;
}

const std::string& User::getHashedPassword() const {
    return hashedPassword;
}
