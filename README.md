# 🛡️ SentinelX

### Secure Browsing. Smarter Protection.

SentinelX is a browser security extension built to make everyday browsing safer. It continuously analyzes websites as you browse and warns you about potentially harmful or suspicious pages before they can cause damage.

The project was developed with the goal of helping users identify common web threats such as phishing pages, unsafe websites, hidden elements, and insecure connections through clear, easy-to-understand security alerts.

---

## Why SentinelX?

Cyber threats have become increasingly sophisticated, making it difficult for users to distinguish between legitimate and malicious websites.

SentinelX was created to provide an additional layer of protection by monitoring browsing activity in real time and presenting security warnings in a simple, understandable manner. Instead of overwhelming users with technical information, SentinelX focuses on providing practical insights that help users make safer decisions online.

---

## Key Features

* 🔍 Real-time website monitoring
* 🛡️ Detection of suspicious and phishing websites
* 🌐 Domain trust verification
* 🔒 Secure connection (HTTPS) validation
* 📋 Clipboard activity monitoring for suspicious behavior
* 🧩 Hidden iframe detection
* ⚠️ Interactive security warning overlays
* 📊 Risk assessment based on multiple security indicators
* 💡 Clear explanations to help users understand detected risks
* ⚡ Lightweight design with minimal impact on browsing performance

---

## How It Works

```
User Opens a Website
          │
          ▼
Browser Extension Starts Monitoring
          │
          ▼
Website Security Checks
          │
          ├── Domain Verification
          ├── Connection Security
          ├── Hidden Element Detection
          ├── Browser Activity Analysis
          └── Threat Evaluation
          │
          ▼
Risk Score Generated
          │
          ▼
Security Warning (If Required)
```

---

## Technology Stack

### Frontend

* JavaScript (ES6)
* HTML5
* CSS3

### Browser Platform

* Chrome Extension APIs
* Manifest Version 3

### Backend

* Node.js

### Development Tools

* Visual Studio Code
* Git
* GitHub

---

## Project Structure

```
SentinelX/
│
├── assets/
├── background/
├── content/
├── popup/
├── services/
├── utils/
├── manifest.json
├── package.json
└── README.md
```

> Folder names may differ slightly depending on the latest project version.

---

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/alinashaji-12/SentinelX.git
```

### Install Dependencies

```bash
npm install
```

### Load the Extension

1. Open **Google Chrome** or any Chromium-based browser.
2. Navigate to:

```
chrome://extensions
```

3. Enable **Developer Mode**.
4. Click **Load unpacked**.
5. Select the SentinelX project folder.

The extension is now ready for use.

---

## Security Checks Performed

SentinelX evaluates several indicators while a webpage is loading, including:

* Website authenticity
* Suspicious domains
* Connection security (HTTPS)
* Hidden iframes
* Potential phishing indicators
* Unsafe browser behaviors
* Overall website risk level

These checks work together to help identify potentially unsafe websites before users interact with them.

---

## Future Enhancements

Some planned improvements include:

* Chrome Web Store release
* Support for additional browsers
* Expanded threat detection capabilities
* Enhanced reporting and analytics
* Improved performance optimization
* Community feedback integration

---

## Project Highlights

* Modern browser security extension
* Built using Manifest V3
* Modular and maintainable architecture
* Focused on usability and performance
* Designed with a security-first approach
* Easy to install and extend

---

## Contributing

Contributions, suggestions, and improvements are always welcome.

If you discover an issue or have an idea for enhancing SentinelX, feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License.

---

## About the Developer

Alina Shaji

Final-year B.Tech Computer Science Engineering (Artificial Intelligence & Machine Learning) student with an Honours in Cyber Security. Passionate about building secure, user-focused software and exploring the intersection of cybersecurity, artificial intelligence, and modern web technologies.

GitHub: https://github.com/alinashaji-12

Feel free to explore the repository, share feedback, or contribute to the project.
---

## Support

If you found this project useful or interesting, consider giving it a ⭐ on GitHub. Your support helps the project reach more developers and encourages future improvements.
