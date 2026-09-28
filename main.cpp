// main.cpp
// ---------------------------------------------------------------------------
// Entry point and console user interface for the Login & Registration
// System (CodeAlpha C++ Internship - Task 2).
//
// This file is deliberately "thin": it only handles displaying menus,
// reading raw input, and calling into Authentication for the real logic.
// It does not know how passwords are hashed or how the file is formatted.
// ---------------------------------------------------------------------------
#include <iostream>
#include <limits>
#include <string>
#include "Authentication.h"
#include "FileManager.h"

namespace {
    const std::string USERS_FILE = "users.txt";
    constexpr int MAX_LOGIN_ATTEMPTS = 3; // Additional enhancement (see README)

    void printHeader(const std::string& title) {
        std::cout << "\n====================================\n";
        std::cout << title << "\n";
        std::cout << "====================================\n";
    }

    void printMainMenu() {
        printHeader("LOGIN & REGISTRATION SYSTEM");
        std::cout << "1. Register\n";
        std::cout << "2. Login\n";
        std::cout << "3. Exit\n";
        std::cout << "------------------------------------\n";
        std::cout << "Enter your choice: ";
    }

    // Reads a full line of text (usernames/passwords may not contain '|',
    // which is enforced by validation, so simple getline is sufficient).
    std::string readLine() {
        std::string line;
        std::getline(std::cin, line);
        return line;
    }

    // Reads a menu choice as an integer. Handles non-numeric input (e.g.
    // the user typing "abc") without crashing, by checking the stream's
    // fail state and clearing/discarding the bad input.
    bool readMenuChoice(int& outChoice) {
        std::string line = readLine();
        try {
            size_t pos;
            int value = std::stoi(line, &pos);
            // Ensure the ENTIRE line was a number (reject "3abc").
            if (pos != line.size()) return false;
            outChoice = value;
            return true;
        } catch (...) {
            return false;
        }
    }

    // True once the input stream has been closed / hit end-of-file (e.g.
    // input piped from a file or redirected from another process runs out).
    // Without this check, a loop that keeps re-prompting on invalid input
    // would spin forever reading empty lines after EOF instead of exiting.
    bool inputStreamClosed() {
        return std::cin.eof();
    }

    void handleRegister(Authentication& auth) {
        printHeader("REGISTER");

        std::cout << "Enter username (3-20 chars, letters/numbers/underscore): ";
        std::string username = readLine();

        std::string reason;
        if (!Authentication::isValidUsername(username, reason)) {
            std::cout << "\nRegistration failed: " << reason << "\n";
            return;
        }
        if (auth.usernameExists(username)) {
            std::cout << "\nUsername already exists. Please choose another username.\n";
            return;
        }

        std::cout << "Enter password (min 8 chars, upper+lower+digit+special): ";
        std::string password = readLine();

        if (!Authentication::isValidPassword(password, reason)) {
            std::cout << "\nRegistration failed: " << reason << "\n";
            return;
        }

        RegisterResult result = auth.registerUser(username, password);
        switch (result) {
            case RegisterResult::Success:
                std::cout << "\nRegistration successful! You can now log in as \"" << username << "\".\n";
                break;
            case RegisterResult::UsernameTaken:
                // Rare race: could happen if duplicate slipped through between
                // the check above and the call (defensive handling).
                std::cout << "\nUsername already exists. Please choose another username.\n";
                break;
            case RegisterResult::InvalidUsername:
                std::cout << "\nRegistration failed: invalid username.\n";
                break;
            case RegisterResult::InvalidPassword:
                std::cout << "\nRegistration failed: invalid password.\n";
                break;
            case RegisterResult::StorageError:
                std::cout << "\nUnable to access the user database. Please try again.\n";
                break;
        }
    }

    void handleLogin(Authentication& auth) {
        printHeader("LOGIN");

        for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; ++attempt) {
            std::cout << "Enter username: ";
            std::string username = readLine();
            std::cout << "Enter password: ";
            std::string password = readLine();

            LoginResult result = auth.login(username, password);

            if (result == LoginResult::Success) {
                std::cout << "\nLogin successful!\n";
                std::cout << "Welcome, " << username << ".\n";
                return;
            } else if (result == LoginResult::StorageError) {
                std::cout << "\nUnable to access the user database. Please try again.\n";
                return;
            } else {
                // Deliberately generic: does not reveal whether the
                // username exists (see README -> Security Analysis).
                std::cout << "\nInvalid username or password.\n";
                int remaining = MAX_LOGIN_ATTEMPTS - attempt;
                if (remaining > 0) {
                    std::cout << "Attempts remaining: " << remaining << "\n\n";
                }
            }
        }

        std::cout << "\nToo many failed login attempts.\n";
        std::cout << "Returning to main menu.\n";
        // Note: this is a SESSION-level limit only (not a permanent account
        // lockout) -- see README for why that distinction matters.
    }
}

int main() {
    FileManager fileManager(USERS_FILE);
    Authentication auth(fileManager);

    if (!auth.initialize()) {
        std::cout << "Unable to access the user database. Please check file permissions and try again.\n";
        return 1;
    }

    bool running = true;
    while (running) {
        printMainMenu();

        int choice;
        if (!readMenuChoice(choice)) {
            if (inputStreamClosed()) {
                std::cout << "\nInput stream closed. Exiting.\n";
                running = false;
                continue;
            }
            std::cout << "\nInvalid input. Please enter a number (1-3).\n";
            continue;
        }

        switch (choice) {
            case 1:
                handleRegister(auth);
                break;
            case 2:
                handleLogin(auth);
                break;
            case 3:
                std::cout << "\nGoodbye!\n";
                running = false;
                break;
            default:
                std::cout << "\nInvalid choice. Please select 1, 2, or 3.\n";
                break;
        }
    }

    return 0;
}
