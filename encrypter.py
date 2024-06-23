import argparse
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as symmetric_padding
import os

# Функция для генерации ключей RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Функция для сохранения ключей в файлы
def save_rsa_key_to_file(key, filename):
    with open(filename, "wb") as f:
        f.write(key)

# Функция для загрузки ключа из файла
def load_rsa_key_from_file(filename):
    with open(filename, "rb") as f:
        key_data = f.read()
        key = serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend()
        )
        return key

# Функция для шифрования текста с использованием открытого ключа
def encrypt_text_with_rsa(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Функция для дешифрования текста с использованием закрытого ключа
def decrypt_text_with_rsa(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Функция для шифрования файла с использованием открытого ключа
def encrypt_file_with_rsa(public_key, input_file, output_file):
    chunk_size = 256
    padding = symmetric_padding.PKCS7(256).padder()

    with open(input_file, 'rb') as f_in:
        with open(output_file, 'wb') as f_out:
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                padded_data = padding.update(chunk)
                encrypted_data = public_key.encrypt(
                    padded_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                f_out.write(encrypted_data)

# Функция для дешифрования файла с использованием закрытого ключа
def decrypt_file_with_rsa(private_key, input_file, output_file):
    chunk_size = 256
    padding = symmetric_padding.PKCS7(256).unpadder()

    with open(input_file, 'rb') as f_in:
        with open(output_file, 'wb') as f_out:
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                decrypted_data = private_key.decrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                unpadded_data = padding.update(decrypted_data)
                f_out.write(unpadded_data)
            f_out.write(padding.finalize())

# Функция для выбора файла и выполнения шифрования/дешифрования
def choose_file_and_execute(action_type):
    chosen_file = filedialog.askopenfilename()
    if chosen_file:
        if action_type == "encrypt":
            encrypted_file = chosen_file + ".encrypted"
            encrypt_file_with_rsa(public_key, chosen_file, encrypted_file)
            messagebox.showinfo("Encryption", f"Файл успешно зашифрован: {encrypted_file}")
        elif action_type == "decrypt":
            decrypted_file = chosen_file[:-10]  # удаление расширения ".encrypted"
            decrypt_file_with_rsa(private_key, chosen_file, decrypted_file)
            messagebox.showinfo("Decryption", f"Файл успешно дешифрован: {decrypted_file}")

# Функция для GUI интерфейса
def create_gui():
    root = tk.Tk()
    root.title("RSA Encryptor")

    encrypt_button = tk.Button(root, text="Шифровать файл", command=lambda: choose_file_and_execute("encrypt"))
    encrypt_button.pack(pady=10)

    decrypt_button = tk.Button(root, text="Дешифровать файл", command=lambda: choose_file_and_execute("decrypt"))
    decrypt_button.pack(pady=10)

    root.mainloop()

# Функция для парсинга аргументов командной строки
def parse_arguments():
    parser = argparse.ArgumentParser(description="Программа для шифрования и дешифрования файлов с использованием RSA.")
    parser.add_argument("--generate-keys", action="store_true", help="Сгенерировать ключи RSA и сохранить их в файлы.")
    return parser.parse_args()

# Пример использования
if __name__ == "__main__":
    # Парсинг аргументов командной строки
    args = parse_arguments()

    # Если указан параметр --generate-keys, генерируем ключи и выходим
    if args.generate_keys:
        private_key, public_key = generate_rsa_keys()
        save_rsa_key_to_file(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ),
            "private_key.pem"
        )
        save_rsa_key_to_file(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            "public_key.pem"
        )
        print("Сгенерированы и сохранены ключи RSA в файлы private_key.pem и public_key.pem.")
        exit()

    # Генерация ключей RSA, если ключи не сгенерированы заранее
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        private_key, public_key = generate_rsa_keys()
        save_rsa_key_to_file(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ),
            "private_key.pem"
        )
        save_rsa_key_to_file(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            "public_key.pem"
        )

    # Создание GUI интерфейса для выбора файлов и выполнения операций
    create_gui()

    # Очистка файлов
    os.remove("private_key.pem")
    os.remove("public_key.pem")
