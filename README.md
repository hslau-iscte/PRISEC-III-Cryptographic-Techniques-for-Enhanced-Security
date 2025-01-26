# Cryptographic-Techniques-for-Enhanced-Security

This project demonstrates the use of various encryption algorithms (AES, ChaCha20, Blowfish, RSA, ECC) and hashing techniques through a Flask-based web application. It serves as a practical implementation of cryptographic methods for learning and testing purposes.

## Features

- **AES (Advanced Encryption Standard)**: Encryption in CTR mode for secure and efficient data protection.
- **ChaCha20**: A modern stream cipher offering high-speed encryption and resistance to vulnerabilities.
- **Blowfish**: A fast symmetric key cipher for secure data encryption.
- **RSA (Rivest-Shamir-Adleman)**: Public-key encryption for secure communication.
- **ECC (Elliptic-Curve Cryptography)**: Secure key exchange using Curve25519.
- **HMAC (Hash-based Message Authentication Code)**: Data integrity verification using SHA-512.

## Prerequisites

Before running the project, ensure you have the following installed:

- **Python 3.8 or above**
- **pip**: Python package manager
- **Flask**: A web framework for Python
- **pycryptodome**: Cryptographic library
- **cryptography**: Advanced cryptographic library

To install the required Python libraries, use the `requirements.txt` file.

## Installation and Setup

### Step 1: Clone the Repository

Clone this repository to your local machine:
```bash
git clone https://github.com/yourusername/encryption-demo.git
cd encryption-demo
```

### Step 2: Set Up a Virtual Environment

It is recommended to use a virtual environment to manage dependencies:

1. **Create a Virtual Environment**  
   ```bash
   python -m venv venv
   ```

2. **Activate the Virtual Environment**  
   - On **Windows**:
     ```bash
     venv\Scripts\activate
     ```
   - On **macOS/Linux**:
     ```bash
     source venv/bin/activate
     ```

3. **Install Dependencies**  
   With the virtual environment active, install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Project Locally

### Step 1: Start the Flask Server

Run the Flask application with the following command:
```bash
python app.py
```

### Step 2: Access the Application

Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

You will now see the application running locally on your machine. You can use the web interface to test various encryption and decryption methods.

## Project Structure

- **`app.py`**: Main Flask application file containing the encryption logic.
- **`templates/`**: HTML templates for the web interface.
- **`static/`**: Static files (CSS, JavaScript) for the frontend.
- **`requirements.txt`**: File listing all Python dependencies for the project.

## Encryption Algorithms Used

1. **AES (CTR Mode)**: Symmetric encryption for secure data protection.
2. **ChaCha20**: High-performance stream cipher.
3. **Blowfish**: Symmetric block cipher with variable key size.
4. **RSA**: Asymmetric encryption for secure key exchange.
5. **ECC (Curve25519)**: Efficient and secure key exchange method.
6. **HMAC (SHA-512)**: Ensures data integrity with cryptographic hashing.

---

## Troubleshooting

If you encounter any issues, follow these steps:

1. Verify your Python version:
   ```bash
   python --version
   ```
2. Ensure all dependencies are installed:
   ```bash
   pip install -r requirements.txt
   ```
3. Check the error logs in the terminal for detailed error messages.
4. Restart the Flask server after making any code changes.


## Contributions

Contributions are welcome! If you find a bug or have an idea for improvement, feel free to open an issue or submit a pull request.


