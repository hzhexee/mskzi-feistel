# Заменяем импорт PyCryptodome на нашу реализацию IDEA
from Crypto.Random import get_random_bytes  # Функция для генерации криптостойких случайных байтов
import os  # Модуль для работы с операционной системой
from idea import idea_encrypt_block, idea_decrypt_block  # Импортируем нашу реализацию IDEA

BLOCK_SIZE = 8  # Размер блока шифрования в байтах (64 бита)

def pad(data):
    """
    Добавление PKCS#7 паддинга для приведения данных к кратности размера блока.
    
    Параметры:
        data (bytes): Данные, к которым нужно добавить паддинг
        
    Возвращает:
        bytes: Данные с добавленным паддингом, кратные размеру блока
        
    Принцип работы: 
    Если данным нужно добавить N байт для достижения кратности блока,
    то добавляем N байт, каждый со значением N.
    """
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """
    Удаление PKCS#7 паддинга после дешифрования.
    
    Параметры:
        data (bytes): Дешифрованные данные с паддингом
        
    Возвращает:
        bytes: Данные с удаленным паддингом
        
    Вызывает:
        ValueError: Если паддинг имеет неверный формат
    """
    pad_len = data[-1]  # Последний байт содержит количество добавленных байтов
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Неверный паддинг.")
    return data[:-pad_len]

def cbc_encrypt(plaintext, key, iv):
    """
    Реализация режима CBC (Cipher Block Chaining) для шифрования.
    
    Параметры:
        plaintext (bytes): Данные для шифрования (с паддингом)
        key (bytes): Ключ шифрования (16 байт)
        iv (bytes): Вектор инициализации (8 байт)
        
    Возвращает:
        bytes: Зашифрованные данные
    """
    ciphertext = bytearray()
    prev_block = iv
    
    # Обрабатываем каждый блок
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i+BLOCK_SIZE]
        
        # XOR блока с предыдущим зашифрованным блоком (или IV для первого блока)
        xored_block = bytes(b1 ^ b2 for b1, b2 in zip(block, prev_block))
        
        # Шифруем блок
        encrypted_block = idea_encrypt_block(xored_block, key)
        ciphertext.extend(encrypted_block)
        
        # Сохраняем текущий зашифрованный блок для следующей итерации
        prev_block = encrypted_block
    
    return bytes(ciphertext)

def cbc_decrypt(ciphertext, key, iv):
    """
    Реализация режима CBC (Cipher Block Chaining) для дешифрования.
    
    Параметры:
        ciphertext (bytes): Зашифрованные данные
        key (bytes): Ключ дешифрования (16 байт)
        iv (bytes): Вектор инициализации (8 байт)
        
    Возвращает:
        bytes: Расшифрованные данные (с паддингом)
    """
    plaintext = bytearray()
    prev_block = iv
    
    # Обрабатываем каждый блок
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        
        # Дешифруем текущий блок
        decrypted_block = idea_decrypt_block(block, key)
        
        # XOR результат с предыдущим зашифрованным блоком (или IV для первого блока)
        xored_block = bytes(b1 ^ b2 for b1, b2 in zip(decrypted_block, prev_block))
        plaintext.extend(xored_block)
        
        # Обновляем prev_block для следующей итерации
        prev_block = block
    
    return bytes(plaintext)

def encrypt_file(input_file, output_file, key):
    """
    Шифрование файла с использованием алгоритма IDEA в режиме CBC.
    
    Параметры:
      input_file (str)  - путь к исходному файлу
      output_file (str) - путь для сохранения зашифрованного файла
      key (bytes)       - ключ шифрования (16 байт, 128 бит)
      
    Режим CBC (Cipher Block Chaining):
    - Каждый блок открытого текста XOR-ится с предыдущим зашифрованным блоком перед шифрованием
    - Для первого блока используется случайный вектор инициализации (IV)
    - Обеспечивает лучшую защиту по сравнению с ECB, т.к. даже одинаковые блоки открытого текста
      шифруются по-разному
    """
    # Проверка длины ключа
    if len(key) != 16:
        raise ValueError("Ключ должен быть длиной 16 байт (128 бит).")
    
    # Чтение исходного файла
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    # Добавление паддинга для выравнивания до размера блока
    plaintext = pad(plaintext)
    
    # Генерация случайного вектора инициализации (IV) для режима CBC
    iv = get_random_bytes(BLOCK_SIZE)
    
    # Шифрование данных с использованием нашей реализации CBC
    ciphertext = cbc_encrypt(plaintext, key, iv)
    
    # Записываем IV вместе с зашифрованными данными (IV в начале файла)
    # IV необходим для дешифрования и должен быть доступен получателю
    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)
    print(f"Файл успешно зашифрован и сохранён как {output_file}")

def decrypt_file(input_file, output_file, key):
    """
    Дешифрование файла.
    
    Параметры:
      input_file  - путь к зашифрованному файлу
      output_file - путь для сохранения расшифрованного файла
      key         - ключ дешифрования (16 байт)
    """
    if len(key) != 16:
        raise ValueError("Ключ должен быть длиной 16 байт (128 бит).")
    
    with open(input_file, 'rb') as f:
        file_data = f.read()
    
    iv = file_data[:BLOCK_SIZE]
    ciphertext = file_data[BLOCK_SIZE:]
    
    # Дешифрование с использованием нашей реализации CBC
    plaintext_padded = cbc_decrypt(ciphertext, key, iv)
    
    try:
        # Добавляем проверку паддинга перед удалением
        pad_len = plaintext_padded[-1]
        if pad_len < 1 or pad_len > BLOCK_SIZE:
            raise ValueError("Неверный паддинг: значение байта паддинга вне допустимого диапазона")
            
        # Проверяем, что все байты паддинга имеют правильное значение
        padding_bytes = plaintext_padded[-pad_len:]
        if not all(b == pad_len for b in padding_bytes):
            raise ValueError("Неверный паддинг: неконсистентные значения байтов паддинга")
            
        plaintext = unpad(plaintext_padded)
    except ValueError as e:
        print("Ошибка при удалении паддинга:", e)
        # Для отладки добавим вывод последних байтов дешифрованных данных
        print(f"Последние 16 байт дешифрованных данных (hex): {plaintext_padded[-16:].hex()}")
        return
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(f"Файл успешно дешифрован и сохранён как {output_file}")

# Пример использования
if __name__ == "__main__":
    # Пример ключа (в реальных приложениях ключ должен генерироваться и храниться безопасно)
    key = b'1234567890abcdef'  # 16 байт
    
    # Задайте пути к вашим файлам
    input_file = 'plain.txt'
    encrypted_file = 'encrypted.bin'
    decrypted_file = 'decrypted.txt'
    
    # Шифрование
    encrypt_file(input_file, encrypted_file, key)
    
    # Дешифрование
    decrypt_file(encrypted_file, decrypted_file, key)
