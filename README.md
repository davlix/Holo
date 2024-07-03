# Folder Encryption Tool

## Deskripsi

Folder Encryption Tool adalah aplikasi untuk mengenkripsi dan mendekripsi folder dengan menggunakan enkripsi ganda AES-256 dan ChaCha20Poly1305. Aplikasi ini mendukung Windows, macOS, dan Linux. Selain itu, aplikasi ini memiliki beberapa fitur keamanan tambahan seperti pengelolaan kunci yang lebih baik, autentikasi multifaktor (MFA), log aktivitas yang lebih detil, pemindaian malware, pemantauan real-time, penanganan error yang lebih baik, penggunaan salt dan IV yang unik, dan hash yang lebih kuat.

## Fitur
1. **Enkripsi Ganda**: Menggunakan dua lapisan enkripsi dengan algoritma AES-256 dan ChaCha20Poly1305.
2. **Pengelolaan Kunci yang Lebih Baik**: Menggunakan salt untuk menghasilkan kunci yang unik untuk setiap kata sandi.
3. **Autentikasi Multifaktor (MFA)**: Mendukung autentikasi multifaktor untuk keamanan tambahan (fitur ini memerlukan integrasi lebih lanjut).
4. **Pemutakhiran Kata Sandi**: Memungkinkan pengguna untuk memperbarui kata sandi dan mengenkripsi ulang file dengan kata sandi baru.
5. **Log Aktivitas yang Lebih Detil**: Mencatat detail aktivitas pengguna termasuk waktu dan deskripsi aktivitas.
6. **Pemindaian Malware**: Memindai file sebelum dan sesudah enkripsi untuk memastikan bebas dari ancaman (memerlukan integrasi dengan perangkat lunak pihak ketiga).
7. **Pemantauan Real-Time**: Memantau aktivitas mencurigakan secara real-time (memerlukan integrasi dengan perangkat lunak pemantauan).
8. **Penanganan Error yang Lebih Baik**: Mencatat setiap kesalahan dengan detail.
9. **Penggunaan Salt dan IV yang Unik**: Setiap file dan sesi enkripsi menggunakan salt dan IV yang unik.
10. **Hash yang Lebih Kuat**: Menggunakan algoritma hash SHA-256 dengan nonce untuk meningkatkan keamanan.
11. **Antarmuka Pengguna GUI**: Aplikasi memiliki antarmuka pengguna grafis yang memudahkan penggunaan.

## Persyaratan
- Python 3.6 atau lebih tinggi
- cryptography
- tkinter
- hashlib

## Instalasi

1. Clone repositori:
    ```bash
    git clone https://github.com/username/folder-encryption-tool.git
    ```
2. Masuk ke direktori proyek:
    ```bash
    cd folder-encryption-tool
    ```
3. Install dependensi:
    ```bash
    pip install -r requirements.txt
    ```

## Penggunaan

1. Jalankan aplikasi:
    ```bash
    python encryption_tool.py
    ```
2. Pilih folder yang ingin dienkripsi atau didekripsi.
3. Masukkan kata sandi untuk enkripsi atau dekripsi.
4. Klik tombol untuk memulai proses enkripsi atau dekripsi.

## Contoh Kode

```python
# Contoh untuk mengenkripsi folder
encrypt_folder('/path/to/folder', 'password')

# Contoh untuk mendekripsi folder
decrypt_folder('/path/to/folder', 'password')

# Contoh untuk memperbarui kata sandi
update_password('/path/to/folder', 'old_password', 'new_password')
