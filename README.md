**🔐 Secure Online Voting System**



**🌐 Platform Overview**

This project is built as a web-based application, meaning users interact with it through a browser.



**🛠️ Technology Stack**

Backend: Python using Flask

Database: SQLite (lightweight, file-based database)

Frontend: HTML, CSS (basic UI for forms and pages)



**📌 Why this platform?**

Easy to develop within 10 days

Supports authentication + database security

Ideal for demonstrating SQL Injection and XSS attacks

Minimal setup, runs locally



**🧱 System Architecture**



User → Browser → Flask Server → Database (SQLite)



Browser sends requests (login, vote, etc.)

Flask processes logic and security checks

SQLite stores users, votes, candidates



**⚙️ Project Workflow (Step-by-Step)**



**1️⃣ Project Setup**



Initialize Flask app



**Create project structure:**



/templates

/static

app.py

database.db



**Install required libraries:**

Flask

bcrypt



**2️⃣ Database Design**



**Create tables:**



**Users Table:**


id

username

password (hashed)

has\_voted



**Candidates Table:**

id

name

votes



**3️⃣ User Registration**

User enters username \& password

Password is hashed using bcrypt

Stored securely in database



👉 Prevents plain-text password storage



**4️⃣ Login System (Authentication)**

User enters credentials

Backend verifies using hashed password

Session created for logged-in user



👉 Only authenticated users can access voting page



**5️⃣ Voting Mechanism**

Display list of candidates

User selects one candidate

System checks:

If user already voted

If not:

Vote is recorded

has\_voted = True



👉 Ensures one user = one vote



**6️⃣ Admin Functionality**

Admin login

View total votes per candidate

⚠️ Security Testing (Core Part of Project)

🔴 Step 1: Vulnerable Implementation



**Demonstrate attacks:**



**SQL Injection**



Try login bypass using:



' OR '1'='1

XSS Attack



Input:



<script>alert("Hacked")</script>



**🛡️ Step 2: Securing the Application**



✅ SQL Injection Prevention

Use parameterized queries instead of string concatenation



✅ XSS Prevention

Escape or sanitize user inputs before rendering



✅ Authentication Security

Password hashing (bcrypt)

Session-based login



✅ Access Control

Restrict voting page to logged-in users

Prevent multiple voting



✅ Basic Protection

Limit login attempts

Validate all inputs



**🧪 Testing \& Validation**

Test login with valid/invalid credentials

Attempt SQL injection → should fail after fix

Attempt XSS → should not execute

Try voting twice → should be blocked



**🎯 Key Learning Outcomes**

Secure authentication implementation

Understanding of SQL Injection \& XSS attacks

Input validation and sanitization

Session management and access control

Basic database security practices



**🏁 Conclusion**



This project demonstrates how a web application can be:



Built with basic functionality

Attacked using common vulnerabilities

Secured using industry-standard practices





