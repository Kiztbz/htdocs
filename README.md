# 💻 $-Square $ecurity

🔍 A lightweight and beginner-friendly **Web Security Scanner** designed for new website owners and startups to scan their websites for common vulnerabilities.  
This tool offers **automated security testing** for:

- 🔓 Open Port Scanning  
- 🛡️ SQL Injection Vulnerabilities  
- 💣 Cross-Site Scripting (XSS) Attacks  

It generates actionable reports, provides mitigation guidance, and includes educational tips — all wrapped in a sleek, hacker-themed UI.

---

## 🌐 Live Demo

🎉 Try the tool instantly on Render:  
👉 [https://security-scanner-vts4.onrender.com](https://security-scanner-vts4.onrender.com)

---

## 🔧 Features

✅ **Port Scanner**  
- Identifies open ports on a target domain.  
- Lists potential risks associated with exposed ports.  

✅ **SQL Injection Scanner**  
- Checks basic SQLi vulnerabilities.  
- Displays warnings with prevention tips.  

✅ **Cross-Site Scripting (XSS) Scanner**  
- Detects reflected XSS issues.  
- Educates with prevention practices.  

✅ **Automated Report Generation**  
- Produces a structured, clear **PDF report** including:  
  - Executive summary  
  - Key findings  
  - Recommended mitigations  

✅ **Tips Section**  
- Security best practices for each scanner.  
- Educates site owners and developers.

✅ **About Page**  
- Shows the mission of the project and problems it solves.

---

## 📸 Screenshots

### 🔐 Scanner & Report Generation
![Scanner](https://github.com/user-attachments/assets/6f7ae17a-d593-4617-bb67-5231425ceb6a)

### 🧠 Tips Section
![Tips](https://github.com/user-attachments/assets/66fc6c38-81f4-4749-858a-eeb5599a59b9)

### 👥 About Page
![About](https://github.com/user-attachments/assets/03482c1f-5cc4-4e52-b827-971d7b84dfb1)

> ⚠️ *Note: Screenshots are just visual previews. For full functionality, try the [live demo](https://security-scanner-vts4.onrender.com) or run locally.*

---

## 🚀 Getting Started

### Requirements
- PHP (for backend scanning logic)
- Localhost server (like XAMPP/WAMP)
- Any modern browser

---

## 🛠️ Local Setup

If you'd like to run it locally, follow these quick steps:

```bash
# Clone the repository
git clone https://github.com/Omfalcon/Security-scanner.git
cd Security-scanner

# Move the project to your server's root directory (e.g., for XAMPP:)
mv Security-scanner /xampp/htdocs/

# Start Apache via your XAMPP/WAMP control panel

# Then, open your browser and visit:
http://localhost/Security-scanner
