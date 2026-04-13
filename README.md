# OneSideAuthSalsa20 🔐

**OneSideAuthSalsa20** is an educational and demonstration tool that implements a one-side authentication protocol based on the **Salsa20** stream cipher and **timestamps**.

This project was developed as a course work to visualize cryptographic processes and demonstrate protection mechanisms against replay attacks.

## Key Features

- **Time-Based Authentication:** Uses synchronized timestamps ($t_A$) to ensure request freshness and prevent replay attacks.
- **Salsa20 Engine:** A custom implementation of the Salsa20 algorithm (256-bit key) featuring a visualization of the 20-round transformation process.
- **Step-by-Step Visualization:** An interactive web interface (inspired by CrypTool) that guides users through every stage: from data concatenation to server-side validation.
- **HEX Inspector:** Real-time inspection of input data, keystreams, and ciphertexts in hexadecimal format.

## Tech Stack

- **Backend:** Python 3.10+, Flask
- **Frontend:** JavaScript (ES6), HTML5, CSS3 (Modern UI)
- **Cryptography:** Native implementation of the Salsa20 ARX architecture (Addition, Rotation, XOR).

## How the Protocol Works

1. **Client Side:** Generates a data packet `t_A || I_B`, where $t_A$ is the current timestamp and $I_B$ is the server identifier.
2. **Encryption:** The packet is encrypted using Salsa20 with a shared secret key $k$.
3. **Server Side:** Decrypts the packet, extracts the identifier, and calculates the time delay $\Delta t^* = t_B - t_A$.
4. **Decision:** Access is granted only if the server ID matches and the delay $\Delta t^*$ is within the allowed window $\Delta t$.

## Installation & Setup

To get this project running locally, follow these steps:

Clone the Repository:

Bash
git clone https://github.com/MilaGttP/OneSideAuthSalsa20.git
cd OneSideAuthSalsa20
Create a Virtual Environment:

Windows:

Bash
python -m venv venv
venv\Scripts\activate
macOS/Linux:

Bash
python3 -m venv venv
source venv/bin/activate
Install Dependencies:

Bash
pip install -r requirements.txt
Run the Application:

Bash
python app.py
Access the Dashboard:
Open your browser and navigate to http://localhost:5000

Author
Liudmyla — MilaGttP

Developed as a Course Project at VNTU, 2026.
