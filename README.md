# File Encryptor

Secure File Encryptor is a Python-based GUI application that provides a simple and secure way to encrypt and decrypt files using AES-256 GCM encryption. The tool uses password-based key derivation (PBKDF2 with HMAC-SHA256) to generate encryption keys and features a user-friendly interface built with Tkinter. It supports drag-and-drop file management, batch processing, and optional secure deletion of the original files.

## Features

- **AES-256 GCM Encryption:** Encrypt files securely using industry-standard AES encryption.
- **Password-Based Key Derivation:** Uses PBKDF2 with HMAC-SHA256 to derive a strong encryption key from your password.
- **Graphical User Interface (GUI):** Built with Tkinter for ease of use.
- **Drag-and-Drop Support:** Easily add files by dragging them into the file list.
- **Batch Processing:** Encrypt or decrypt multiple files at once.
- **Secure Delete:** Optionally overwrite original files with random data before deletion to enhance security.
- **Theme Toggle:** Switch between light and dark modes for a comfortable viewing experience.
- **Activity Log:** View real-time activity logs within the application and in an external log file (`file_encryptor.log`).


## Requirements

- **Python 3.x** (Tested on Python 3.6+)
- **Python Packages:**
  - cryptography (for encryption/decryption)
  - tkinter (usually included with standard Python installations)

### Installing Dependencies

Install the `cryptography` package using pip:

```bash
pip install cryptography
```

## Installation
Clone this repository or download the source code.
Ensure you have Python 3.x installed on your system.
Install the required Python packages as mentioned above.

## Usage
Running the Application:

Navigate to the directory containing the source code and run the application with:

```bash
python secure_file_encryptor.py 
```

## Encrypting Files:

Add Files: Use the "Add Files" button or drag-and-drop files into the list.
Set Password: Enter and confirm your password in the designated fields.
Options: (Optional) Enable secure deletion to overwrite original files after encryption.
Encrypt: Click the "Encrypt Files" button to start the encryption process.

## Decrypting Files:

Add Encrypted Files: Select files with the .encrypted extension.
Enter Password: Provide the password used during encryption.
Decrypt: Click the "Decrypt Files" button to restore the original files.

## Setting Output Directory:

Click on "Set Output Directory" to choose where the encrypted or decrypted files will be saved.

## Theme Toggle:

Switch between light and dark themes by clicking the "Toggle Dark Mode" button.

## Viewing Logs:

Monitor the application’s activity in the "Activity Log" pane.
Detailed logs are also saved in the file_encryptor.log file.

## How It Works
### Encryption Process
 Salt & Nonce Generation:
    Generates a random salt and nonce for each file.

### Key Derivation:
  Derives a 256-bit key from the user-provided password using PBKDF2.

### Data Encryption:
  Encrypts file data using AES-GCM.
### Output File Format:
  Writes a custom header (SECENC), salt, nonce, and the encrypted data to the output file.

## Decryption Process
### Header Verification:
  Checks for the SECENC identifier in the file.
  
### Key Derivation:
  Derives the key using the stored salt and the provided password.

### Data Decryption:
  Decrypts the file using AES-GCM and restores the original data.

### Secure Deletion
  #### Overwrite Method:
  The original file is overwritten three times with random data before deletion to reduce the risk of data recovery.

## Security Considerations
### Password Safety:
  Use a strong, unique password. The application does not store your password.
### Backup Your Data:
  Always maintain backups of important files as no encryption system is completely foolproof.
### Secure Delete Caveat:
While the secure deletion feature minimizes data recovery risks, its effectiveness can vary based on the underlying file system and storage hardware.

## Troubleshooting
### Incorrect Password:
Decryption will fail if an incorrect password is provided. Ensure you enter the same password used during encryption.

### Invalid File Format:
Only files encrypted with this application (with the SECENC header) can be decrypted. Attempting to decrypt non-conforming files will result in an error.

# Disclaimer
 ## This tool is provided "as is" without any warranty. The authors are not responsible for any data loss or damage resulting from its use.

## ScreenShots

<img width="400" alt="pg11" src="https://github.com/user-attachments/assets/17784e99-3b6c-49c4-ab32-afb469c77b0b" />
<img width="400" alt="pg11" src="https://github.com/user-attachments/assets/345822f4-a579-456a-8bbb-08abadac70c0" />
