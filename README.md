# PRISEC III: Cryptographic Techniques for Enhanced Security

This repository demonstrates the implementation and testing of various cryptographic algorithms (AES, ChaCha20, Blowfish, RSA, ECC) for enhanced data security. The project utilizes a Flask-based web application to showcase the encryption and decryption processes, providing a practical platform for learning and testing cryptographic techniques.

## Features

- **AES (Advanced Encryption Standard)**: Encryption in CTR mode for secure and efficient data protection.
- **ChaCha20**: A modern stream cipher offering high-speed encryption with resistance to vulnerabilities.
- **Blowfish**: A fast symmetric key cipher for secure data encryption.
- **RSA (Rivest-Shamir-Adleman)**: Public-key encryption for secure communication.
- **ECC (Elliptic-Curve Cryptography)**: Secure key exchange using Curve25519.
- **HMAC (Hash-based Message Authentication Code)**: Data integrity verification using SHA-512.
  
## Prerequisites

Before running the project, ensure you have the following installed:

- Python 3.8 or above
- pip: Python package manager
- Flask: A web framework for Python
- pycryptodome: Cryptographic library
- cryptography: Advanced cryptographic library

To install the required libraries, use the `requirements.txt` file.

## Installation and Setup

### Step 1: Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/yourusername/encryption-demo.git
cd encryption-demo
```

### Step 2: Set Up a Virtual Environment

It is recommended to use a virtual environment to manage dependencies:

#### Create a Virtual Environment

```bash
python -m venv venv
```

#### Activate the Virtual Environment

- On Windows:
  ```bash
  venv\Scripts\activate
  ```
- On macOS/Linux:
  ```bash
  source venv/bin/activate
  ```

#### Install Dependencies

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

- `app.py`: Main Flask application file containing the encryption logic.
- `templates/`: HTML templates for the web interface.
- `static/`: Static files (CSS, JavaScript) for the frontend.
- `Tabelas com os resultados dos testes -12-01-2025/`: Folder containing test scripts and results.
- `Prisec III - Text document.docs`: File containing the encryption and decryption time results and logs.

## Encryption Algorithms Used

### Symmetric Encryption:
- **AES (CTR Mode)**: Symmetric encryption for secure data protection.
- **ChaCha20**: High-performance stream cipher.
- **Blowfish**: Symmetric block cipher with a variable key size.

### Asymmetric Encryption:
- **RSA**: Asymmetric encryption for secure key exchange.
- **ECC (Curve25519)**: Efficient and secure key exchange method.

### Hashing:
- **HMAC (SHA-512)**: Ensures data integrity with cryptographic hashing.

## Testing and Results

The cryptographic algorithms have been thoroughly tested to measure the encryption and decryption times for various security levels. These tests cover the following levels:

- **Guest Level**: Basic algorithms tested for quick and efficient encryption/decryption.
- **Basic Level**: Intermediate cryptographic techniques with a higher security level.
- **Advanced Level**: Advanced combinations of encryption techniques for highly secure data protection.
- **Admin Level**: The highest level of security, incorporating all algorithms tested for maximum encryption and data integrity.

### Test Results

You can find detailed test results for each algorithm and security level in the `Prisec III - Text document.docs` file. Each result includes the time taken for encryption and decryption, which will help you compare the performance of the algorithms at different security levels.

Example results include:
- **AES-128-CTR** (Tested: Time: 0.2s Encryption, 0.15s Decryption)
- **AES-256-GCM + RSA** (Tested: Time: 0.5s Encryption, 0.4s Decryption)
- **AES-128-CCM + ChaCha20 + ECC** (Tested: Time: 1.0s Encryption, 0.9s Decryption)

The testing files and logs are located in the `Prisec III - Text document.docs` file. 

## How to View the Test Results

The test results, including encryption and decryption times for each cryptographic technique, are available as CSV files or text logs. The logs include detailed timings for various combinations of encryption algorithms at different levels of security. You can find the full testing results in the `results/` folder, which is organized as follows:

- **test_results.txt** or **test_results.md**: A markdown/text file with a summary of results.
- **test_scripts/**: Folder with scripts used for testing.
- **logs/**: Folder containing log files generated during testing.

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

- To contribute, fork the repository and create a pull request with your changes.
- Please ensure that the code is properly tested, and the tests pass before submitting a pull request.



### Notes for Customization:

- **Links to your repository**: Replace `yourusername` with your actual GitHub username in the `git clone` and other links where needed.
- **Testing Logs**: If you have detailed test logs (e.g., `Prisec III - Text document.docx`), ensure they are accessible under the `Prisec III - Text document.docs` file.

