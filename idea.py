# IDEA cipher implementation in pure Python

# Константы
MODULO = 0x10000      # 2^16 для сложения
MUL_MOD = 0x10001     # 2^16+1 для умножения

def idea_mul(x, y):
    """
    IDEA-мультипликативная операция:
    x и y трактуются как 16-битные числа, где 0 трактуется как 65536.
    Результат вычисляется по модулю (2^16+1) и, если он равен 65536, возвращается 0.
    """
    if x == 0:
        x = MUL_MOD - 1
    if y == 0:
        y = MUL_MOD - 1
    result = (x * y) % MUL_MOD
    return 0 if result == MUL_MOD - 1 else result

def idea_add(x, y):
    """Операция сложения по модулю 2^16."""
    return (x + y) % MODULO

def generate_subkeys(key: bytes) -> list:
    """
    Генерация 52 16-битных подключей из 128-битного ключа (16 байт)
    согласно алгоритму IDEA.
    """
    if len(key) != 16:
        raise ValueError("Ключ должен быть 128-битным (16 байт)")
    # Преобразуем ключ в 128-битное число
    key_int = int.from_bytes(key, byteorder='big')
    subkeys = []
    # Всего нужно 52 подключей, для каждой группы из 8 подключей выполняется циклический сдвиг на 25 бит
    for i in range(52):
        if i > 0 and i % 8 == 0:
            # Циклический сдвиг влево на 25 бит
            key_int = ((key_int << 25) | (key_int >> (128 - 25))) & ((1 << 128) - 1)
        # Извлекаем верхние 16 бит
        subkey = key_int >> (128 - 16)
        subkeys.append(subkey & 0xFFFF)
        # Сдвигаем ключ влево на 16 бит для следующего подклуча
        key_int = (key_int << 16) & ((1 << 128) - 1)
    return subkeys[:52]

def mul_inv(x: int) -> int:
    """
    Вычисление мультипликативного обратного элемента для IDEA (модуль 65537).
    Если x равен 0, то он трактуется как 65536.
    """
    if x <= 1:
        return x
    t0, t1 = 0, 1
    r0, r1 = MUL_MOD, x
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if t0 < 0:
        t0 += MUL_MOD
    return t0

def generate_decryption_subkeys(enc_subkeys: list) -> list:
    """
    Вычисление подключей для дешифрования на основе подключей шифрования.
    """
    dec_subkeys = [0] * 52
    # Последняя четверка подключей (выходное преобразование)
    dec_subkeys[0] = mul_inv(enc_subkeys[48])
    dec_subkeys[1] = (-enc_subkeys[49]) % MODULO
    dec_subkeys[2] = (-enc_subkeys[50]) % MODULO
    dec_subkeys[3] = mul_inv(enc_subkeys[51])
    # Обработка восьми раундов в обратном порядке
    for r in range(1, 9):
        j = r * 6
        dec_subkeys[j + 0] = mul_inv(enc_subkeys[48 - r * 6])
        if r == 8:
            # Последний раунд не имеет обмена средних подключей
            dec_subkeys[j + 1] = (-enc_subkeys[50 - r * 6]) % MODULO
            dec_subkeys[j + 2] = (-enc_subkeys[49 - r * 6]) % MODULO
        else:
            dec_subkeys[j + 1] = (-enc_subkeys[50 - r * 6]) % MODULO
            dec_subkeys[j + 2] = (-enc_subkeys[49 - r * 6]) % MODULO
        dec_subkeys[j + 3] = mul_inv(enc_subkeys[51 - r * 6])
        if r != 8:
            dec_subkeys[j + 4] = enc_subkeys[52 - r * 6]
            dec_subkeys[j + 5] = enc_subkeys[47 - r * 6]
    return dec_subkeys

def idea_encrypt_block(block: bytes, key: bytes) -> bytes:
    """
    Шифрование 64-битного блока (8 байт) с использованием IDEA.
    """
    if len(block) != 8:
        raise ValueError("Блок должен быть 8 байт (64 бита)")
    # Генерируем подклучи
    subkeys = generate_subkeys(key)
    # Разбиваем блок на 4 16-битных слова
    X1 = int.from_bytes(block[0:2], byteorder='big')
    X2 = int.from_bytes(block[2:4], byteorder='big')
    X3 = int.from_bytes(block[4:6], byteorder='big')
    X4 = int.from_bytes(block[6:8], byteorder='big')
    
    # 8 раундов
    for i in range(8):
        j = i * 6
        A = idea_mul(X1, subkeys[j + 0])
        B = idea_add(X2, subkeys[j + 1])
        C = idea_add(X3, subkeys[j + 2])
        D = idea_mul(X4, subkeys[j + 3])
        E = A ^ C
        F = B ^ D
        G = idea_mul(E, subkeys[j + 4])
        H = idea_add(F, G)
        I = idea_mul(H, subkeys[j + 5])
        J = idea_add(G, I)
        X1 = A ^ I
        X4 = D ^ J
        # Для раундов 1-7 меняем местами X2 и X3
        if i != 7:
            X2, X3 = C ^ I, B ^ J
        else:
            X2, X3 = idea_add(B, subkeys[48]), idea_add(C, subkeys[49])
    # Финальное преобразование с подключами 48-51
    Y1 = idea_mul(X1, subkeys[48])
    Y2 = idea_add(X3, subkeys[49])
    Y3 = idea_add(X2, subkeys[50])
    Y4 = idea_mul(X4, subkeys[51])
    # Собираем итоговый блок
    result = (Y1.to_bytes(2, byteorder='big') +
              Y2.to_bytes(2, byteorder='big') +
              Y3.to_bytes(2, byteorder='big') +
              Y4.to_bytes(2, byteorder='big'))
    return result

def idea_decrypt_block(block: bytes, key: bytes) -> bytes:
    """
    Дешифрование 64-битного блока (8 байт) с использованием IDEA.
    """
    if len(block) != 8:
        raise ValueError("Блок должен быть 8 байт (64 бита)")
    # Генерируем подклучи шифрования и вычисляем подклучи дешифрования
    enc_subkeys = generate_subkeys(key)
    dec_subkeys = generate_decryption_subkeys(enc_subkeys)
    # Разбиваем блок на 4 16-битных слова
    X1 = int.from_bytes(block[0:2], byteorder='big')
    X2 = int.from_bytes(block[2:4], byteorder='big')
    X3 = int.from_bytes(block[4:6], byteorder='big')
    X4 = int.from_bytes(block[6:8], byteorder='big')
    
    # 8 раундов дешифрования
    for i in range(8):
        j = i * 6
        A = idea_mul(X1, dec_subkeys[j + 0])
        B = idea_add(X2, dec_subkeys[j + 1])
        C = idea_add(X3, dec_subkeys[j + 2])
        D = idea_mul(X4, dec_subkeys[j + 3])
        E = A ^ C
        F = B ^ D
        G = idea_mul(E, dec_subkeys[j + 4])
        H = idea_add(F, G)
        I = idea_mul(H, dec_subkeys[j + 5])
        J = idea_add(G, I)
        X1 = A ^ I
        X4 = D ^ J
        if i != 7:
            X2, X3 = C ^ I, B ^ J
        else:
            X2, X3 = idea_add(B, dec_subkeys[48]), idea_add(C, dec_subkeys[49])
    # Финальное преобразование с подключами 48-51 дешифрования
    Y1 = idea_mul(X1, dec_subkeys[48])
    Y2 = idea_add(X3, dec_subkeys[49])
    Y3 = idea_add(X2, dec_subkeys[50])
    Y4 = idea_mul(X4, dec_subkeys[51])
    result = (Y1.to_bytes(2, byteorder='big') +
              Y2.to_bytes(2, byteorder='big') +
              Y3.to_bytes(2, byteorder='big') +
              Y4.to_bytes(2, byteorder='big'))
    return result

# Пример использования:
if __name__ == "__main__":
    # 128-битный ключ (16 байт)
    key = b"1234567890abcdef"
    # 64-битный блок для шифрования (8 байт)
    plaintext = b"ABCDEFGH"
    
    ciphertext = idea_encrypt_block(plaintext, key)
    decrypted = idea_decrypt_block(ciphertext, key)
    
    print("Исходный текст:", plaintext)
    print("Зашифрованный (hex):", ciphertext.hex())
    print("Дешифрованный текст:", decrypted)
