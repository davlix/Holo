# Folder Encryption/Decryption Tool

## Deskripsi (Description)

Program ini adalah alat untuk mengenkripsi dan mendekripsi folder menggunakan algoritma AES-256. Program ini juga memverifikasi integritas file setelah dekripsi untuk memastikan tidak ada perubahan yang tidak diinginkan. Antarmuka pengguna grafis (GUI) disediakan untuk memudahkan penggunaan.

This program is a tool for encrypting and decrypting folders using the AES-256 algorithm. It also verifies file integrity after decryption to ensure no unwanted changes have occurred. A graphical user interface (GUI) is provided for ease of use.

## Fitur (Features)

- **Enkripsi Folder (Folder Encryption)**: Mengenkripsi semua file dalam folder yang dipilih.
- **Dekripsi Folder (Folder Decryption)**: Mendekripsi semua file dalam folder yang dienkripsi.
- **Pemeriksaan Integritas File (File Integrity Check)**: Memverifikasi integritas file setelah dekripsi.
- **Antarmuka GUI (GUI Interface)**: Memudahkan pengguna untuk memilih folder dan memasukkan kata sandi.

- **Folder Encryption**: Encrypts all files in the selected folder.
- **Folder Decryption**: Decrypts all files in the encrypted folder.
- **File Integrity Check**: Verifies file integrity after decryption.
- **GUI Interface**: Allows users to easily select folders and enter passwords.

## Instalasi (Installation)

1. Clone repositori ini:
   ```bash
   git clone https://github.com/davlix/Holo.git
   ```
2. Pindah ke direktori proyek:
   ```bash
   cd Holo
   ```
3. Instal dependensi:
   ```bash
   pip install -r requirements.txt
   ```
## Instalasi English (Installation)

1. Clone this repository:
   ```bash
   git clone https://github.com/davlix/Holo.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Holo
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Penggunaan (Usage)

1. Jalankan program:
   ```bash
   python Holo.py
   ```
2. Pilih folder yang ingin dienkripsi atau didekripsi.
3. Masukkan kata sandi.
4. Klik tombol "Encrypt" untuk mengenkripsi atau "Decrypt" untuk mendekripsi.

## Penggunaan English (Usage)

1. Run the program:
   ```bash
   python Holo.py
   ```
2. Select the folder you want to encrypt or decrypt.
3. Enter the password.
4. Click the "Encrypt" button to encrypt or "Decrypt" button to decrypt.

## Logging Aktivitas (Activity Logging)

Semua aktivitas enkripsi dan dekripsi akan dicatat ke dalam file `encryption_activity.log` untuk pemantauan dan audit.

All encryption and decryption activities will be logged in the `encryption_activity.log` file for monitoring and auditing.

## Pemeriksaan Integritas File (File Integrity Check)

Program ini menghitung hash SHA-256 dari file sebelum dan sesudah enkripsi/dekripsi untuk memverifikasi integritas file. Hash ini disimpan dalam file `.hash` dan digunakan untuk memverifikasi bahwa file tidak diubah selama proses enkripsi/dekripsi.

This program calculates the SHA-256 hash of the file before and after encryption/decryption to verify file integrity. This hash is stored in a `.hash` file and used to ensure the file has not been altered during the encryption/decryption process.

## Kontribusi (Contributing)

Kontribusi selalu diterima! Silakan fork repositori ini dan buat pull request dengan perubahan Anda.

Contributions are always welcome! Please fork this repository and create a pull request with your changes.
