MO-IT147 Information Assurance and Security 1
Group 3 - CyberOps
Members: Claricia, Tan, Belda, Pablo Jr.

# TrustPaySecure: Encrypted Payroll Management System for MotorPH

**TrustPaySecure** is a Java-based secure payroll management system with encryption, role-based access control, and input validation. Designed for small organizations that prioritize data privacy, accountability, and secure access.

---

## Features

- User Authentication
  - Role-based login (Admin / User)
  - SHA-256 password hashing

- Payroll Management
  - Add encrypted employee records
  - View salary data with clean formatting
  - Admin-only file deletion with backup

- Security Measures
  - AES encryption for all payroll entries
  - Protection against CSV injection
  - Audit logs of all actions
  - Automatic backups before changes

---

## File Structure

| File / Folder      | Description                                           |
|--------------------|-------------------------------------------------------|
| `TrustPaySecure.java` | Main Java GUI application                          |
| `config.txt`       | Stores hashed credentials (`admin`, `user`)           |
| `payroll.csv`      | Encrypted employee payroll entries                    |
| `audit.log`        | Records all system actions (login, add, delete, etc.) |
| `error.log`        | Captures and logs application runtime errors          |
| `backups/`         | Folder for payroll backups before file overwrite/delete |

---

## Default Credentials

| Role    | Username | Password  |
|---------|----------|-----------|
| Admin   | `admin`  | `admin123`|
| User    | `user`   | `user123` |

Note: Change default credentials in `config.txt` before deployment.

---

## How to Run

### Prerequisites
- Java JDK 8 or later
- IntelliJ IDEA or any Java IDE

### Steps

1. Clone or download this repository
2. Open `TrustPaySecure.java` in your IDE
3. Compile and run the file
4. Login using the provided credentials
5. Start managing payroll securely

---

## Security Coverage (Risk IDs Solved)

| Risk ID | Issue                                 | Mitigation                           |
|---------|----------------------------------------|---------------------------------------|
| R001    | Lack of access control                | Admin vs. user restrictions           |
| R002    | Plaintext credentials                 | SHA-256 hashed passwords              |
| R003    | CSV injection                         | Sanitization of inputs                |
| R004    | No activity logs                      | `audit.log` with all actions          |
| R005    | Unsafe file deletion                  | Admin-only access with confirmation   |
| R006    | Unvalidated inputs                    | Regex checks for name/salary fields   |
| R007    | No error handling/logging             | `error.log` with full stack traces    |
| R008    | Unencrypted payroll data              | AES encryption on read/write          |
| R009    | No data backup                        | Automatic backups on each action      |
| R010    | Hardcoded credentials in code         | External `config.txt` file            |

---

## License

This project is for our school (Mapua Malayan Colleges of Laguna) project
