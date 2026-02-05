# Qrypta 🔐  
### Secure Password Manager with Vaults, RBAC, 2FA & Audit Logging

Qrypta is a **security-first password management system** designed to securely store sensitive secrets inside encrypted vaults while enforcing **strong authentication, role-based access control, and full auditability**.  
The application is built with a modular backend architecture that reflects real-world enterprise security design principles.

Qrypta focuses on **confidentiality, integrity, accountability, and least-privilege access**, making it suitable as a learning, research, and portfolio project for cybersecurity and backend engineering roles.

---

## 🔹 Core Features

### 🔐 Secure Vault Management
- Secrets are stored inside **user-specific vaults**
- Vault access is strictly controlled through permissions
- Sensitive data is encrypted before storage

### 🔑 Authentication & 2FA
- Secure login and session handling
- **Two-Factor Authentication (2FA)** using SMTP-based OTP
- Token-based session validation

### 🧑‍💼 Role-Based Access Control (RBAC)
- Roles define what actions a user can perform
- Enforces the **Principle of Least Privilege**
- Separation of admin, organizational, and user privileges

### 🧾 Audit Logging
- Every critical action is logged:
  - Logins
  - Vault access
  - Secret creation/modification
  - Administrative actions
- Enables traceability, monitoring, and compliance readiness

### 🏢 Organization & Department Management
- Users belong to organizations and departments
- Invitation-based onboarding
- Centralized control for enterprise-style usage

### 🔐 Security Utilities
- Password strength validation
- Secure password generator
- CAPTCHA protection
- Token and permission handling

---

## 🧠 Technology Stack

### Backend
- **Python**
- **Flask** (modular blueprint-based architecture)
- **SQLAlchemy** (ORM)
- **Flask Extensions** (Auth, Sessions, Config handling)

### Security
- Encryption utilities for sensitive data
- OTP-based 2FA via SMTP
- Token-based authentication
- Role & permission enforcement
- Centralized audit logging

### Frontend
- HTML templates (Jinja2)
- Static assets for UI rendering

### Database
- Relational database (SQLite / PostgreSQL / MySQL compatible)

---

All folders users, vaults, utils have common files (models.py, routes.py and services.py)


Architecture Pattern

models.py → Database schema & ORM models

routes.py → API / route definitions

services.py → Business logic & security enforcement

This separation ensures clean code, scalability, and maintainability.


⚙️ Installation & Setup
1️⃣ Clone the Repository
git clone https://github.com/<your-username>/Qrypta.git
cd Qrypta

2️⃣ Create Virtual Environment
python -m venv venv
source venv/bin/activate   # Linux / macOS
venv\Scripts\activate      # Windows

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ Configure Environment

Update SMTP credentials for OTP

Configure database URI in config.py

Set encryption keys and secret tokens securely

▶️ Running the Application
python run.py


The application will start on:

http://127.0.0.1:5000

🔄 Application Workflow

User registers or is invited to an organization

User authenticates using username/password

OTP is sent via email (2FA verification)

User role and permissions are validated

User accesses assigned vaults only

Secrets are encrypted and stored securely

Every action is logged in the audit system

Admins can review logs and manage access

This mirrors real-world enterprise password management workflows.

🚀 Future Enhancements

Hardware-based 2FA (TOTP / WebAuthn)

Password sharing with time-bound access

Advanced SIEM integration for audit logs

Vault versioning and secret history

API access with scoped tokens

Zero-knowledge encryption model

Frontend framework integration (React / Vue)

Dockerized deployment

Cloud-native secret storage support

📌 Purpose

Qrypta is built as a security-focused learning and portfolio project demonstrating:

Secure system design

Access control enforcement

Authentication workflows

Audit and compliance awareness

Real-world backend architecture

🛡️ Disclaimer

This project is intended for educational and demonstration purposes.
Sensitive configurations and secrets must be handled securely before any production use.


## 🗂️ Project Structure

```text
Qrypta/
│
├── app/
│   ├── admin/
│   │   ├── models.py
│   │   ├── routes.py
│   │   └── services.py
│   │
│   ├── audit/
│   │   ├── models.py
│   │   ├── routes.py
│   │   └── services.py
│   │
│   ├── auth/
│   │   ├── models.py
│   │   ├── routes.py
│   │   └── services.py
│   │
│   ├── core/
│   │   ├── encryption.py
│   │   ├── otp.py
│   │   ├── captcha.py
│   │   ├── permissions.py
│   │   ├── tokens.py
│   │   ├── password_generator.py
│   │   └── password_strength.py
│   │
│   ├── organizations/
│   │   ├── departments/
│   │   ├── invitations/
│   │   ├── models.py
│   │   ├── routes.py
│   │   └── services.py
│   │
│   ├── users/
│   ├── vault/
│   ├── utils/
│   ├── templates/
│   ├── static/
│   │   └── images/
│   │
│   ├── config.py
│   ├── extensions.py
│   └── __init__.py
│
├── requirements.txt
├── run.py
├── .gitignore
└── README.md

