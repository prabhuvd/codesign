A lightweight code signing server built with Python and Flask for secure update of Battery Management System.

Features

Secure code signing: Authenticates files using cryptographic signatures for integrity and trust.

User-friendly interface: Simple web interface for file uploads and signed file downloads.

Python-based: Leverages the power of Python and Flask for efficient development and deployment.

Minimal dependencies: Requires only Python and the following libraries:
cryptography==3.4.8
flash==1.0.3
Flask==3.0.0
Installation

Clone the repository:
Bash git clone https://github.com/prabhuvd/codesign.git

Use code with caution. Learn more
Install dependencies:
Bash
cd code-signing-server
pip install -r requirements.txt
Use code with caution. Learn more
Usage
Run the server:
Bash
python app.py
Use code with caution. Learn more
Access the interface:
Open your web browser and navigate to http://127.0.0.1:5000/ (or the specified port).
Upload a binary file:
Click the "Choose File" button and select the file to be signed.
Download the signed file:
Click the "Download Signed File" button to retrieve the authenticated version.
Contributing
We welcome contributions! Please check out the Contributing Guidelines: CONTRIBUTING.md for details.

License
This project is licensed under the MIT License. See the LICENSE: LICENSE file for details.

Contact
For any questions or feedback, feel free to reach out to [your contact information].