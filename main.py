def vec_xor(vec1, vec2):
    """
    Выполняет побитовую операцию XOR между элементами двух векторов разной длины.
    Более короткий вектор дополняется нулями до длины большего.
    """
    result = []
    max_len = max(len(vec1), len(vec2))
    
    for i in range(max_len):
        v1 = vec1[i] if i < len(vec1) else 0
        v2 = vec2[i] if i < len(vec2) else 0
        result.append(v1 ^ v2)
    
    return result

def vec_invert(vect):
    """
    Выполняет побитовую инверсию каждого элемента вектора.
    
    Args:
        vect: Исходный вектор байтов
    
    Returns:
        Новый вектор с инвертированными битами, ограниченными 8 битами (0-255)
    """
    return [~x & 0xFF for x in vect]  # Маска 0xFF для ограничения результата одним байтом

def bit_left(vect):
    """
    Выполняет побитовый сдвиг влево для каждого элемента вектора.
    
    Args:
        vect: Исходный вектор байтов
    
    Returns:
        Новый вектор со сдвинутыми влево битами, ограниченными 8 битами (0-255)
    """
    return [(x << 1) & 0xFF for x in vect]  # Маска для ограничения результата одним байтом

def permute_word(word, key):
    """
    Выполняет перестановку элементов вектора на основе ключа.
    
    Args:
        word: Исходный вектор байтов
        key: Ключ перестановки (целое число)
    
    Returns:
        Новый вектор с переставленными элементами
    """
    word = word.copy()  # Создаем копию, чтобы не изменять оригинал
    for i in range(len(word)):
        # Вычисляем новую позицию элемента, используя ключ
        new_index = (i + key) % len(word)
        # Меняем местами элементы
        word[i], word[new_index] = word[new_index], word[i]
    return word

def f(right, key):
    """
    Функция Фейстеля - основная функция преобразования в сети.
    
    Args:
        right: Правая половина блока
        key: Ключ раунда
    
    Returns:
        Преобразованный вектор для операции XOR с левой половиной блока
    """
    # Последовательно применяем XOR с ключом, инверсию и побитовый сдвиг влево
    return bit_left(vec_invert(vec_xor(right, key)))

def keys_gen(key, decrypt, rounds):
    """
    Генерирует последовательность ключей для каждого раунда шифрования/дешифрования.
    
    Args:
        key: Базовый ключ шифрования
        decrypt: Флаг режима (True для дешифрования, False для шифрования)
        rounds: Количество раундов шифрования
    
    Returns:
        Список ключей для всех раундов
    """
    res = []
    # Генерируем уникальный ключ для каждого раунда
    for i in range(rounds):
        res.append(permute_word(key.copy(), i))
    
    # Для дешифрования используем ключи в обратном порядке
    if decrypt:
        res.reverse()
    return res

def crypt_round(block, round_key):
    """
    Выполняет один раунд шифрования в сети Фейстеля.
    
    Args:
        block: Блок данных для шифрования
        round_key: Ключ текущего раунда
    
    Returns:
        Преобразованный блок после одного раунда
    """
    # Разделяем блок на левую и правую части
    left = block[:len(block)//2]
    right = block[len(block)//2:]
    
    # Применяем функцию Фейстеля к правой части и выполняем XOR с левой частью
    new_right = vec_xor(left, f(right.copy(), round_key))
    
    # Новый блок: старая правая часть становится левой, а результат XOR - новой правой
    return right + new_right

def crypt_block(block, key, decrypt, rounds):
    """
    Шифрует или дешифрует блок данных с использованием сети Фейстеля.
    
    Args:
        block: Блок данных для шифрования/дешифрования
        key: Ключ шифрования
        decrypt: Флаг режима (True для дешифрования, False для шифрования)
        rounds: Количество раундов шифрования
    
    Returns:
        Зашифрованный или дешифрованный блок данных
    """
    # Генерируем ключи для всех раундов
    keys = keys_gen(key, decrypt, rounds)
    
    # Выполняем указанное количество раундов шифрования
    for round_key in keys:
        block = crypt_round(block, round_key)
    
    # Выполняем финальную перестановку (меняем местами левую и правую части)
    left = block[:len(block)//2]
    right = block[len(block)//2:]
    return right + left

def pad_block(block):
    """Дополняет блок до четной длины, если необходимо"""
    if len(block) % 2 != 0:
        return block + [0]  # Добавляем нулевой байт
    return block

def main():
    """
    Основная функция для демонстрации работы сети Фейстеля.
    Шифрует и затем дешифрует тестовый блок данных.
    """
    # Исходные данные
    block = pad_block(list(b"leshaartamonovdvoeshnik"))
    # Ключ шифрования
    key = list(b"nezachet")
    # Количество раундов шифрования
    rounds = 10
    
    # Шифрование исходного блока
    encrypt = crypt_block(block.copy(), key.copy(), False, rounds)
    # Дешифрование зашифрованного блока
    decrypt = crypt_block(encrypt.copy(), key.copy(), True, rounds)
    
    # Вывод результатов
    print(block)    # Исходный блок
    print(encrypt)  # Зашифрованный блок
    print(decrypt)  # Дешифрованный блок (должен совпадать с исходным)

if __name__ == "__main__":
    main()
