# CodeAlpha_LoginAuthenticationSystem

A console-based **Login and Registration System** built in C++ for **Task 2 of the CodeAlpha C++ Programming Internship**.

## Objective

Build a functional C++ application that lets a user register an account and log in with it, with credentials validated, checked for duplicates, and stored persistently across program runs.

## Features

- Register a new account (username + password)
- Username validation: 3–20 characters, letters/numbers/underscores only
- Password policy: minimum 8 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character
- Duplicate-username detection
- Persistent storage in `users.txt`, surviving program restarts
- Login with credential verification
- Passwords are **never stored in plaintext** — each password is salted and hashed with SHA-256 before being written to disk
- Generic "Invalid username or password" message on any login failure (doesn't leak whether the username exists)
- *Additional enhancement:* limited to 3 login attempts per session before returning to the main menu
- Graceful handling of invalid menu input, empty fields, and a missing/unreadable database file (no crashes)

## Technologies Used

- C++17
- C++ Standard Library only — no third-party dependencies (`<iostream>`, `<fstream>`, `<string>`, `<vector>`, `<random>`, `<algorithm>`, etc.)
- A self-contained, from-scratch SHA-256 implementation (`sha256.h`) written using only standard C++ features

## Project Structure

```
CodeAlpha_LoginAuthenticationSystem/
│
├── main.cpp              # Console UI / menu loop — calls into Authentication
├── User.h / User.cpp     # Plain data class representing one user record
├── Authentication.h/.cpp # Validation rules, hashing, register/login logic
├── FileManager.h/.cpp    # All file I/O (reading/writing users.txt)
├── sha256.h               # Standalone SHA-256 hash implementation
├── users.txt               # Created automatically at runtime (not committed)
└── README.md
```

This mirrors classic separation of concerns: **User** = data, **FileManager** = storage, **Authentication** = business logic, **main** = presentation/UI. No single file is responsible for more than one concern.

## How to Compile

```bash
g++ -std=c++17 -Wall -Wextra -o login_system main.cpp User.cpp Authentication.cpp FileManager.cpp
```

Compiles cleanly (zero warnings) with g++ 13, and is portable to MinGW, Visual Studio, and VS Code's C++ tooling since it uses only the standard library.

## How to Run

```bash
./login_system
```

You'll see:

```
====================================
LOGIN & REGISTRATION SYSTEM
====================================
1. Register
2. Login
3. Exit
------------------------------------
Enter your choice:
```

## How Registration Works

1. User enters a username → validated (length + allowed characters).
2. Program checks the in-memory user list for a duplicate.
3. User enters a password → validated against the password policy.
4. A random salt is generated, the password is hashed with SHA-256 as `SHA256(salt + password)`, and `username|salt|hash` is appended to `users.txt`.
5. A success message is shown.

## How Login Works

1. User enters a username and password.
2. The in-memory user list (loaded from `users.txt` at startup) is searched for the username.
3. If found, the same salt is used to hash the entered password, and the result is compared to the stored hash.
4. Access is granted only on an exact hash match; otherwise the same generic "Invalid username or password" message is shown regardless of whether the username existed or the password was wrong.
5. After 3 failed attempts in a row, the session returns to the main menu (this is a session-level throttle, not a permanent account lock).

## Data Storage

Each user occupies one line in `users.txt`:

```
username|salt|hashedPassword
```

Example:
```
Julian|d935b6932d80f98a|d1178fcd7e6e059400752d96d509ab64a774e61aab7703fcfd7791ceebc3444e
```

A single flat file was chosen (over one-file-per-user) because it is simple to read/write sequentially with `ifstream`/`ofstream`, keeps the whole user list loadable into memory in one pass, and is easy for a reviewer to inspect directly.

## Security Considerations

- **Plaintext storage is dangerous:** if `users.txt` were ever leaked, every password would be immediately usable by an attacker, and because people reuse passwords, that compromise can cascade to other services.
- **Hashing vs. encryption:** encryption is reversible (you can decrypt it back to the original password given the key); hashing is one-way. Authentication only needs to *verify* a password, never *recover* it, so a one-way hash is the correct tool — nothing in the system, including the developer, can read the passwords back out.
- **Salting:** a random salt is generated per user and stored alongside the hash. Salting isn't about secrecy — it's to guarantee that two users with the same password produce different hashes, and that precomputed "rainbow table" attacks against common passwords don't work.
- **Why SHA-256 isn't the full answer:** SHA-256 is a fast, general-purpose cryptographic hash. That speed is a *liability* for password storage, because it makes brute-forcing billions of guesses (e.g. on a GPU) cheap. Production systems use a deliberately **slow, memory-hard** password-hashing algorithm — **bcrypt**, **scrypt**, or **Argon2** — instead. This project uses salted SHA-256 because it can be implemented with zero external dependencies in pure C++, which is appropriate for demonstrating the *concept* of salting-and-hashing in an internship project — but it is explicitly **not** what a production system should ship.
- **Generic failure messages:** the login function never reveals whether a username exists — a real attacker probing the system with random usernames can't distinguish "wrong password" from "no such account," which prevents username enumeration.
- **File-based storage limitations:** a plain text file has no access control, no encryption at rest, and no concurrent-write protection. A production system would use a proper database with parameterized queries (to prevent injection), OS-level file permissions, and encryption at rest.

## Error Handling

| Situation | Detection | Response |
|---|---|---|
| Empty/invalid username or password | Validated before hashing | Specific error message, user returns to menu |
| Duplicate username | Linear scan of the in-memory user list | "Username already exists" |
| Wrong password / unknown username | Hash mismatch or user not found | Generic "Invalid username or password" |
| Non-numeric menu input | `std::stoi` throws, caught | "Invalid input. Please enter a number (1-3)." |
| Out-of-range menu choice | `switch` default case | "Invalid choice. Please select 1, 2, or 3." |
| Missing `users.txt` at startup | `ifstream::is_open()` returns false | Treated as zero existing users (not an error) |
| `users.txt` cannot be written | `ofstream::is_open()`/`fail()` checked | "Unable to access the user database. Please try again." |
| Malformed line in `users.txt` | Field count check while parsing | Line is skipped rather than crashing the program |
| Input stream closed (EOF) | `std::cin.eof()` checked | Program exits gracefully instead of looping forever |

## Testing

The project was manually tested end-to-end (compiled with `-Wall -Wextra`, zero warnings) against 12 cases: fresh registration, duplicate username, invalid username, invalid password, correct login, wrong password, unknown username, invalid menu input (both non-numeric and out-of-range), persistence across a restart, a missing/renamed database file, and multiple users each logging in with their own credentials. All 12 passed.

## Limitations

- Session-based login throttling only — no persistent account lockout.
- SHA-256 + salt, not a dedicated slow password-hashing KDF (see Security Considerations).
- Single flat text file, no database, no concurrent-access protection.
- Console-only interface.

## Future Improvements

*(Explicitly not part of the CodeAlpha Task 2 requirements — additional enhancements only)*

- Replace SHA-256 with a dedicated password-hashing library (bcrypt/Argon2)
- GUI front-end
- Real database (SQLite/PostgreSQL) instead of a flat file
- Persistent account lockout / cooldown after repeated failures
- Password reset flow
- Email verification
- Role-based access control
- Session management / tokens
- Encrypted transport for a networked version
- Audit logging of login attempts

## Author

Enkay — Computer Science undergraduate, KNUST. Built as part of the CodeAlpha C++ Programming Internship.
