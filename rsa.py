"""
RSA Encryption/Decryption Tool
(Асимметричный алгоритм шифрования RSA с поддержкой генерации ключей, шифрования и расшифрования данных)
"""

import random
import sys
import argparse
import base64
import os
import math


class RSA:
    """
    Асимметричный криптографический алгоритм RSA (Rivest–Shamir–Adleman)
    """

    # ПАРАМЕТРЫ АЛГОРИТМА
    # ---------------------------------------------

    MIN_KEY_SIZE = 2048  # Минимальный безопасный размер ключа (бит)
    MIN_PRIME_SIZE = 128 # Минимальный размер простого числа (бит)
    MIN_PRIME_ROUNDS = 128  # Минимальное количество раундов определения простых чисел
    DEFAULT_PUBLIC_EXPONENTS = [3, 17, 65537]  # Рекомендуемые значения открытой экспоненты e
    DEFAULT_ENCODING = 'utf-8'  # Кодировка для текстовых данных
    PUBLIC_TYPE = 'PUBLIC'  # Тип публичного ключа
    PRIVATE_TYPE = 'PRIVATE'  # Тип приватного ключа
    PEM_HEADER = {  # Заголовки PEM-формата
        PUBLIC_TYPE: '-----BEGIN RSA PUBLIC KEY-----\n',
        PRIVATE_TYPE: '-----BEGIN RSA PRIVATE KEY-----\n'
    }
    PEM_FOOTER = {  # Футеры PEM-формата
        PUBLIC_TYPE: '\n-----END RSA PUBLIC KEY-----',
        PRIVATE_TYPE: '\n-----END RSA PRIVATE KEY-----'
    }

    def __init__(self, encoding: str = DEFAULT_ENCODING):
        """
        Инициализация шифра.
        :param encoding: Кодировка для текстовых данных
        """
        self.encoding = encoding


    # ПРОВЕРКА ПРОСТОТЫ ЧИСЕЛ
    # ---------------------------------------------

    @staticmethod
    def is_prime(n: int, k: int = MIN_PRIME_ROUNDS) -> bool:
        """
        Тест Миллера-Рабина для проверки простоты числа
        :param n: Число для проверки
        :param k: Количество раундов теста
        :return: True - число вероятно простое, False - составное число
        """

        # Быстрые проверки для малых чисел
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Представление n-1 в виде d*2^s
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        # Проведение k раундов теста
        for _ in range(k):
            a = random.randint(2, min(n - 2, 1 << 20))
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for __ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False  # Число составное
        return True  # Вероятно простое число

    @staticmethod
    def is_prime_ferma(n: int, k: int = MIN_PRIME_ROUNDS) -> bool:
        """
        Улучшенный тест Ферма (с проверкой на числа Кармайкла) для проверки простоты числа
        :param n: Число для проверки
        :param k: Количество раундов теста
        :return: True - число вероятно простое, False - составное число
        """

        # Базовые проверки
        if n <= 1:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False

        # Проверка на квадрат (числа Кармайкла свободны от квадратов)
        sqrt_n = int(math.isqrt(n))
        if sqrt_n * sqrt_n == n:
            return False

        # Проверка малых делителей (оптимизация)
        small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29]
        for p in small_primes:
            if n % p == 0:
                return n == p

        # Основной тест Ферма
        for _ in range(k):
            a = random.randint(2, n - 2)
            if pow(a, n - 1, n) != 1:
                return False  # Число составное

        # Дополнительная проверка на числа Кармайкла
        # Фильтрация известных чисел Кармайкла: n свободно от квадратов и для всех простых делителей p: (p-1) делит (n-1)
        carmichael_numbers = { 561, 1105, 1729, 2465, 2821, 6601, 8911, 10585, 15841, 29341, 41041, 46657, 52633 }
        if n in carmichael_numbers:
            return False

        return True  # Вероятно простое число


    # СЕРИАЛИЗАЦИЯ КЛЮЧЕЙ
    # ---------------------------------------------

    def key_to_pem(self, key: tuple, key_type: str) -> str:
        """
        Сериализация ключа в PEM-формат
        [4 байта: длина e][e][4 байта: длина n][n]
        :param key: Кортеж (e, n) или (d, n).
        :param key_type: Тип ключа (PUBLIC/PRIVATE).
        :return: Строка в PEM-формате.
        """
        e, n = key

        # Преобразуем каждый компонент с указанием длины
        e_bytes = e.to_bytes((e.bit_length() + 7) // 8, 'big')  # Байтовое представление e
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')  # Байтовое представление n

        # Формируем ключ: [длина e][e][длина n][n]
        key_bytes = (
            len(e_bytes).to_bytes(4, 'big') +  # Длина e (4 байта)
            e_bytes +                                          # Байты e
            len(n_bytes).to_bytes(4, 'big') +  # Длина n (4 байта)
            n_bytes                                            # Байты n
        )

        # Кодируем в Base64
        b64 = base64.b64encode(key_bytes).decode(self.encoding)
        # Форматирование PEM
        return (
            self.PEM_HEADER[key_type] +
            '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64)) +
            self.PEM_FOOTER[key_type]
        )

    def pem_to_key(self, pem: str) -> tuple:
        """
        Десериализация ключа из PEM-формата
        :param pem: Строка в PEM-формате.
        :return: Кортеж (e, n) или (d, n).
        """
        try:
            lines = pem.strip().split('\n')[1:-1]  # Удаление заголовка и футера
            key_bytes = base64.b64decode(''.join(lines))  # Декодирование Base64

            # Длина e и данные
            e_len = int.from_bytes(key_bytes[:4], 'big')
            e = int.from_bytes(key_bytes[4:4 + e_len], 'big')

            # Длина n и данные
            n_start = 4 + e_len
            n_len = int.from_bytes(key_bytes[n_start:n_start + 4], 'big')
            n = int.from_bytes(key_bytes[n_start + 4:n_start + 4 + n_len], 'big')

            return (e, n)
        except Exception as err:
            raise ValueError(f"Ошибка чтения PEM: {err}")


    # ГЕНЕРАЦИЯ КЛЮЧЕЙ
    # ---------------------------------------------

    @classmethod
    def get_prime_number(cls, num_size: int) -> int:
        """
        Формирование простого числа по указанному размеру (бит)
            1. Генерация случайного числа с установленным старшим битом
            2. Проверка на простоту методом Миллера-Рабина
            3. Повтор до нахождения простого числа
        :param num_size: Размер числа в битах
        :return: Простое число
        """
        if num_size < cls.MIN_PRIME_SIZE:
            raise ValueError("Слишком маленький размер простого числа")

        while True:
            # Генерация числа с установленным старшим битом
            num = random.getrandbits(num_size)
            num |= (1 << (num_size - 1)) | 1  # Гарантируем нечетность и размер
            if cls.is_prime_ferma(num):  # Проверка тестом Миллера-Рабина
                return num

    def generate_keys(self, key_size: int = MIN_KEY_SIZE, exponent: int = DEFAULT_PUBLIC_EXPONENTS[-1]) -> tuple:
        """
        Генерация ключевой пары RSA
            1. Проверка минимального размера ключа.
            2. Генерация двух различных простых чисел p и q.
            3. Вычисление модуля n = p * q.
            4. Вычисление φ(n) = (p-1)(q-1).
            5. Проверка, что e и φ(n) взаимно просты.
            6. Вычисление d = e⁻¹ mod φ(n).
        :param key_size: Размер модуля n в битах
        :param exponent: Значение открытой экспоненты зашифрования
        :return: Кортеж (публичный_ключ, приватный_ключ)
        """
        # Проверка параметров
        if key_size < self.MIN_KEY_SIZE:
            raise ValueError(f"Минимальный размер ключа {self.MIN_KEY_SIZE} бит")
        if exponent not in self.DEFAULT_PUBLIC_EXPONENTS:
            print(f"Внимание: указанное значение открытой экспоненты e={exponent} не входит в рекомендуемые значения ({', '.join(str(exp) for exp in self.DEFAULT_PUBLIC_EXPONENTS)})", file=sys.stderr)

        part_size = key_size // 2
        min_diff = (2 ** (part_size - 100))  # Минимальная разница между простыми числами
        attempt = 0

        # Генерация различных простых чисел
        while True:
            attempt += 1
            p = self.get_prime_number(part_size)
            q = self.get_prime_number(part_size)

            # Вывод прогресса каждые 10 попыток
            if attempt % 10 == 0:
                print(f"    ---> Поиск простых чисел... Попытка #{attempt}", file=sys.stderr)

            # Проверка условий:
            # 1. Различие p и q
            # 2. Одинаковая битовая длина
            # 3. Разница между p и q достаточно велика
            if p != q and (p.bit_length() == q.bit_length()) and abs(p - q) > min_diff:  # Проверка различия и одинакового размера
                if attempt > 1:
                    print(f"    ---> Надёжные простые числа найдены за {attempt} попыток", file=sys.stdout)
                break

        n = p * q  # модуль алгоритма
        fi_n = (p - 1) * (q - 1)  # функция Эйлера для n

        # Проверка взаимной простоты e и φ(n)
        if math.gcd(exponent, fi_n) != 1:
            raise ValueError("e и φ(n) должны быть взаимно простыми")

        # Вычисление закрытой экспоненты расшифрования d
        d = pow(exponent, -1, fi_n)

        return (exponent, n), (d, n)


    # ДОПОЛНЕНИЕ ДАННЫХ
    # ---------------------------------------------

    @staticmethod
    def pad_data(data: bytes, block_size: int) -> bytes:
        """
        Дополнение данных до размера блока
        [4 байта длины данных][данные][случайные байты]
            1. Проверить, что данные помещаются в блок с учетом заголовка
            2. Создать 4-байтовый заголовок с длиной данных
            3. Сгенерировать случайное дополнение нужного размера
            4. Объединить части в один блок
        :param data: Исходные данные
        :param block_size: Общий размер блока после дополнения
        :return: Дополненный блок для шифрования
        """
        data_len = len(data)

        # Максимальный размер данных: блок минус 4 байта заголовка
        max_data_size = block_size - 4
        if data_len > max_data_size:
            raise ValueError(f"Данные ({data_len} байт) превышают максимальный размер для блока {block_size} байт (максимум: {max_data_size} байт)")

        # Заголовок длины (4 байта)
        length_header = data_len.to_bytes(4, byteorder='big')

        # Генерируем случайное дополнение (псевдослучайные байты через системный генератор)
        padding_size = block_size - data_len - 4
        padding = os.urandom(padding_size)

        # Блок: [заголовок] + [данные] + [дополнение]
        return length_header + data + padding

    @staticmethod
    def unpad_data(padded_data: bytes) -> bytes:
        """
        Восстановление данных из дополненного блока
            1. Проверить минимальный размер блока (4 байта)
            2. Извлечь длину данных из первых 4 байт
            3. Проверить что длина не превышает доступный размер
            4. Вернуть данные соответствующей длины
        :param padded_data: Полный блок с дополнением
        :return: Исходные данные
        """
        # Минимальный размер блока (4 байта заголовка)
        if len(padded_data) < 4:
            raise ValueError(f"Некорректный размер блока: {len(padded_data)} байт (требуется минимум 4 байта для заголовка)")

        # Длина из первых 4 байт
        length = int.from_bytes(padded_data[:4], byteorder='big')

        # Проверяем что данные не выходят за пределы блока
        if 4 + length > len(padded_data):
            raise ValueError(f"Некорректная длина данных: {length} байт (доступно в блоке: {len(padded_data) - 4} байт)")

        # Извлекаем данные без дополнения
        return padded_data[4:4 + length]


    # ЗАШИФРОВАНИЕ/РАСШШИФРОВАНИЕ
    # ---------------------------------------------

    @staticmethod
    def _decrypt_block_size(n: int) -> int:
        """
        Вычисление размера блока шифротекста (в байтах), равный размеру модуля n.
        1. Определяем размер модуля n в байтах: (n.bit_length() + 7) // 8.
           - `bit_length()` возвращает количество бит в числе.
           - Добавление 7 и деление на 8 округляет до ближайшего большего числа байт.
           - Все блоки шифротекста должны иметь размер, равный длине модуля.
        :param n: Модуль RSA (публичная часть ключа).
        :return: Размер блока шифротекста.
        """
        return (n.bit_length() + 7) // 8  # Размер модуля в байтах

    @classmethod
    def _encrypt_block_size(cls, n: int) -> int:
        """
        Вычисление максимального размера блока открытого текста (в байтах) перед дополнением.
            1. Вычисление размера блока шифротекста (в байтах), равный размеру модуля n.
            2. Вычитаем 4 байта, зарезервированные для заголовка длины данных.
        :param n: Модуль RSA (публичная часть ключа).
        :return: Максимальный размер данных для шифрования в одном блоке.
        """
        return cls._decrypt_block_size(n) - 4  # 4 байта для заголовка длины

    def encrypt(self, data: str, public_key: tuple) -> bytes:
        """
        Шифрование данных с использованием публичного ключа
            1. Преобразование строки в байты.
            2. Разбиение на блоки с дополнением.
            3. Шифрование каждого блока: c = m^e mod n.
            4. Объединение блоков шифротекста.
        :param data: Текст для шифрования.
        :param public_key: Публичный ключ (e, n).
        :return: Шифртекст (байт)
        """
        e, n = public_key
        data_bytes = data.encode(self.encoding) # Кодирование строки в UTF8
        encrypted_blocks = []

        encrypt_block_size = self._encrypt_block_size(n)  # Размер блока шифротекста
        decrypt_block_size = self._decrypt_block_size(n)  # Максимальный размер блока данных

        # Разбиваем данные на блоки, дополняет каждый до размера модуля
        blocks = []
        for i in range(0, len(data_bytes), encrypt_block_size):
            block = data_bytes[i:i + encrypt_block_size]
            padded_block = self.pad_data(block, decrypt_block_size)
            blocks.append(padded_block)

        # Шифрование каждого блока
        for block in blocks:
            m = int.from_bytes(block, 'big')
            if m >= n:
                raise ValueError("Блок данных превышает модуль n")
            c = pow(m, e, n)  # Шифрование
            encrypted_block = c.to_bytes(decrypt_block_size, 'big')
            encrypted_blocks.append(encrypted_block)

        return b''.join(encrypted_blocks)  # Объединение блоков

    def decrypt(self, ciphertext: bytes, private_key: tuple) -> str:
        """
        Расшифрование данных с использованием приватного ключа
            1. Проверка кратности размера шифротекста размеру блока.
            2. Разбиение на блоки.
            3. Расшифровка каждого блока: m = c^d mod n.
            4. Удаление дополнения и объединение данных.
            5. Декодирование в строку.
        :param ciphertext: Шифртекст.
        :param private_key: Приватный ключ (d, n).
        :return: Расшифрованный текст.
        """
        d, n = private_key
        decrypt_block_size = self._decrypt_block_size(n)  # Размер блока
        decrypted_data = bytearray()

        ciphertext_len = len(ciphertext)
        if ciphertext_len % decrypt_block_size != 0:
            raise ValueError(f"Длина шифртекста ({ciphertext_len}) не кратна размеру блока ({decrypt_block_size})")

        # Обработка блоков
        for i in range(0, ciphertext_len, decrypt_block_size):
            block = ciphertext[i:i + decrypt_block_size]
            c = int.from_bytes(block, 'big')  # Блок шифротекста
            m = pow(c, d, n)  # Расшифровка
            decrypted_block = m.to_bytes(decrypt_block_size, 'big')
            try:
                unpadded_block = self.unpad_data(decrypted_block)  # Удаление дополнения
                decrypted_data.extend(unpadded_block)
            except Exception as ex:
                block_num = i // decrypt_block_size
                raise ValueError(f"Ошибка в блоке {block_num}: {ex}")

        return decrypted_data.decode(self.encoding)  # Декодирование строки


# ИНТЕРФЕЙС ПОЛЬЗОВАТЕЛЯ
# ---------------------------------------------

def interactive_mode():
    """Интерактивный режим работы"""
    print("*** Асимметричный криптографический алгоритм RSA ***")
    print("-------------------------------------------------------------------------------------------------", end='\n\n')

    try:
        # Выбор режима работы алгоритма
        while True:
            mode = input("Выберите режим работы алгоритма (генерация ключей - [key], зашифровать - [encrypt], расшифровать - [decrypt]): ").strip().lower()
            if mode not in ["k", "key", "e", "encrypt", "d", "decrypt"]:
                print("Ошибка: некорректный выбор режима работы алгоритма (необходимо выбрать из списка: [k]/[key], [e]/[encrypt], [d]/[decrypt])", end='\n\n')
                continue
            break
        is_key_gen = mode in ["k", "key"]
        is_encrypt_operation = mode in ["e", "encrypt"]
        # --------------------------------------------------------------------------------------------------------------

        # Инициализация алгоритма
        rsa = RSA()

        # Генерация ключей
        if is_key_gen:
            # Размер ключа
            while True:
                default_key_size = RSA.MIN_KEY_SIZE
                key_size = int(input(f"Размер ключа (по умолчанию {default_key_size} бит): ") or default_key_size)
                if key_size < RSA.MIN_KEY_SIZE:
                    print(f"Ошибка: минимально допустимый размер ключа {RSA.MIN_KEY_SIZE} бит", end='\n\n')
                    continue
                break

            # Экспонента зашифрования
            while True:
                default_exponent = RSA.DEFAULT_PUBLIC_EXPONENTS[-1]
                exponent = int(input(f"Открытая экспонента зашифрования (по умолчанию {default_exponent}): ") or default_exponent)
                if exponent not in RSA.DEFAULT_PUBLIC_EXPONENTS:
                    print(f"Ошибка: экспонента зашифрования должна быть выбрана из указанного списка допустимых экспонент ({', '.join(str(e) for e in RSA.DEFAULT_PUBLIC_EXPONENTS)})", end='\n\n')
                    continue
                break

            # Генерация ключевой пары
            pub_key, priv_key = rsa.generate_keys(key_size, exponent)

            # Публичный ключ
            default_pub_file = "public.key"
            pub_file = input(f"Файл для публичного ключа (по умолчанию {default_pub_file}): ").strip() or default_pub_file
            with open(pub_file, 'w') as file:
                file.write(rsa.key_to_pem(pub_key, RSA.PUBLIC_TYPE))
            # ----------------------------------------------------------------------------------------------------------

            # Приватный ключ
            default_priv_file = "private.key"
            priv_file = input(f"Файл для приватного ключа (по умолчанию {default_priv_file}): ").strip() or default_priv_file
            with open(priv_file, 'w') as file:
                file.write(rsa.key_to_pem(priv_key, RSA.PRIVATE_TYPE))
            # ----------------------------------------------------------------------------------------------------------

            print(f"Ключевая пара успешно сгенерирована (PUBLIC: '{pub_file}', PRIVATE: '{priv_file}')!")

        # Зашифрование/Расшифрование
        else:
            # Выбор источника данных
            while True:
                source = input("Выберите источник данных (текст - [text], файл - [file]): ").strip().lower()
                if source not in ["t", "text", "f", "file"]:
                    print("Ошибка: некорректный выбор источника данных (необходимо выбрать из списка: [t]/[text], [f]/[file])", end='\n\n')
                    continue
                break
            is_file_source = source in ["f", "file"]
            # ----------------------------------------------------------------------------------------------------------

            # Получение входных данных
            while True:
                if is_file_source:
                    default_source_file = "decrypted_data.txt" if is_encrypt_operation else "encrypted_data.bin"
                    source_file = input(f"Введите путь к файлу в {('текстовом' if is_encrypt_operation else 'Base64')} формате (по умолчанию {default_source_file}): ").strip() or default_source_file
                    if not os.path.exists(source_file):
                        print(f"Ошибка: файл '{source_file}' с входными данными не найден!", end='\n\n')
                        continue
                    source_file_mode = "r" if is_encrypt_operation else "rb"
                    source_file_encoding = rsa.encoding if is_encrypt_operation else None
                    with open(source_file, mode=source_file_mode, encoding=source_file_encoding) as file:
                        data = file.read()
                else:
                    text = input(f"Введите текст (в {('читаемом' if is_encrypt_operation else 'Base64')} формате): ").strip() or "Rivest–Shamir–Adleman"
                    if not text:
                        print("Ошибка: текст для обработки не указан!", end='\n\n')
                        continue
                    data = text if is_encrypt_operation else base64.b64decode(text)
                break
            # ----------------------------------------------------------------------------------------------------------

            # Определение ключа
            while True:
                default_key_file = "public.key" if is_encrypt_operation else "private.key"
                key_file = input(f"Введите путь к {('публичному' if is_encrypt_operation else 'приватному')} ключу (по умолчанию {default_key_file}): ").strip() or default_key_file
                if not os.path.exists(key_file):
                    print(f"Ошибка: файл '{key_file}' с {('публичным' if is_encrypt_operation else 'приватным')} ключом не найден!", end='\n\n')
                    continue
                break
            with open(key_file, mode='r', encoding=rsa.encoding) as file:
                key = rsa.pem_to_key(file.read())
            # ----------------------------------------------------------------------------------------------------------

            # Обработка данных
            result_data = rsa.encrypt(data, key) if is_encrypt_operation else rsa.decrypt(data, key)

            # Выбор режима вывода данных
            while True:
                output = input("Выберите режим вывода обработанных данных (консоль - [console], файл - [file]): ").strip().lower()
                if output not in ["c", "console", "f", "file"]:
                    print("Ошибка: некорректный выбор режима вывода обработанных данных (необходимо выбрать из списка: [c]/[console], [f]/[file])", end='\n\n')
                break
            is_file_output = output in ["f", "file"]
            # --------------------------------------------------------------------------------------------------------------

            # Вывод результата
            if is_file_output:
                default_output_file = "encrypted_data.bin" if is_encrypt_operation else "decrypted_data.txt"
                output_file = input(f"Введите путь для сохранения файла с данными (по умолчанию {default_output_file}): ").strip() or default_output_file
                output_file_mode = "wb" if is_encrypt_operation else "w"
                output_file_encoding = None if is_encrypt_operation else rsa.encoding
                with open(output_file, mode=output_file_mode, encoding=output_file_encoding) as file:
                    file.write(result_data)
                print(f"\nЗаписано в файл [{file.name}]: {len(result_data)} байт")
            else:
                print(f"\n{'Зашифрованные данные (в Base64 формате)' if is_encrypt_operation else 'Расшифрованные данные'}:")
                print(base64.b64encode(result_data).decode() if is_encrypt_operation else result_data)
    except Exception as ex:
        print(f"Ошибка: {ex}", file=sys.stderr)
        sys.exit(1)

def arguments_mode():
    """Режим аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="Асимметричный криптографический алгоритм RSA",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # генерация ключей
    genkeys_command = 'genkeys'
    gen_parser = subparsers.add_parser(genkeys_command, help='Генерация ключевой пары')
    gen_parser.add_argument('-s', '--key_size', type=int, default=RSA.MIN_KEY_SIZE, help=f"Размер ключа в битах (минимум {RSA.MIN_KEY_SIZE} бит)")
    gen_parser.add_argument('-e', '--exponent', type=int, choices=RSA.DEFAULT_PUBLIC_EXPONENTS, default=RSA.DEFAULT_PUBLIC_EXPONENTS[-1], help=f"Открытая экспонента зашифрования ({', '.join(str(e) for e in RSA.DEFAULT_PUBLIC_EXPONENTS)})")
    gen_parser.add_argument('-pub', '--public_key', type=str, default="public.key", help='Файл для публичного ключа (по умолчанию public.key)')
    gen_parser.add_argument('-priv', '--private_key', type=str, default="private.key", help='Файл для приватного ключа (по умолчанию private.key)')

    # зашифрование
    encrypt_command = 'encrypt'
    enc_parser = subparsers.add_parser(encrypt_command, help='Зашифрование данных')
    input_group = enc_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-t', '--text', type=str, help="Текст для зашифрования (в читаемом формате)")
    input_group.add_argument('-f', '--file', type=str, nargs='?', const="decrypted_data.bin", default="decrypted_data.txt", help="Входной файл с данными (в текстовом формате)")
    enc_parser.add_argument('-k', '--key', type=str, default="public.key", help='Файл к публичному ключу (в PEM-формате)')
    enc_parser.add_argument('-o', '--output', type=str, nargs='?', default="encrypted_data.bin", help="Выходной файл с шифротекстом (в бинарном формате)")

    # расшифрование
    decrypt_command = 'decrypt'
    dec_parser = subparsers.add_parser(decrypt_command, help='Расшифрование данных')
    input_group = dec_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-t', '--text', type=str, help="Текст для расшифрования (в Base64 формате)")
    input_group.add_argument('-f', '--file', type=str, nargs='?', const="encrypted_data.bin", default="encrypted_data.bin", help="Входной файл с шифротекстом (в бинарном формате)")
    dec_parser.add_argument('-k', '--key', type=str, default="private.key", help='Файл к приватному ключу')
    dec_parser.add_argument('-o', '--output', type=str, nargs='?', default="decrypted_data.txt", help="Выходной файл с расшифрованными данными (в текстовом формате)")

    args = parser.parse_args()

    try:
        # Инициализация алгоритма
        rsa = RSA()

        # Генерация ключей
        if args.command == genkeys_command:
            # Размер ключа
            if args.key_size < RSA.MIN_KEY_SIZE:
                raise ValueError(f"Минимально допустимый размер ключа: {RSA.MIN_KEY_SIZE} бит")

            # Экспонента зашифрования
            if args.exponent not in RSA.DEFAULT_PUBLIC_EXPONENTS:
                raise ValueError(f"Экспонента зашифрования должна быть выбрана из указанного списка допустимых экспонент ({', '.join(str(e) for e in RSA.DEFAULT_PUBLIC_EXPONENTS)})")

            # Генерация ключевой пары
            pub_key, priv_key = rsa.generate_keys(args.key_size, args.exponent)

            # Публичный ключ
            with open(args.public_key, 'w') as file:
                file.write(rsa.key_to_pem(pub_key, RSA.PUBLIC_TYPE))

            # Приватный ключ
            with open(args.private_key, 'w') as file:
                file.write(rsa.key_to_pem(priv_key, RSA.PRIVATE_TYPE))

            print(f"Ключевая пара успешно сгенерирована (PUBLIC: '{args.public_key}', PRIVATE: '{args.private_key}'")

        # Зашифрование/Расшифрование
        else:
            is_encrypt_operation = args.command == encrypt_command

            # Получение входных данных
            if args.file is not None:
                if not os.path.exists(args.file):
                    raise ValueError(f"Файл с данными '{args.file}' не найден")
                file_read_mode = "r" if is_encrypt_operation else "rb"
                file_encoding = rsa.encoding if is_encrypt_operation else None
                with open(args.file, mode=file_read_mode, encoding=file_encoding) as file:
                    data = file.read()
            else:
                print(args)
                if not args.text:
                    raise ValueError("Текст для обработки не указан!")
                data = args.text if is_encrypt_operation else base64.b64decode(args.text)

            # Определение ключа
            if not os.path.exists(args.key):
                raise ValueError(f"Файл {'публичного' if is_encrypt_operation else 'приватного'} ключа '{args.key}' не найден")
            with open(args.key, mode='r', encoding=rsa.encoding) as file:
                key = rsa.pem_to_key(file.read())

            # Обработка данных
            result_data = rsa.encrypt(data, key) if is_encrypt_operation else rsa.decrypt(data, key)

            # Вывод результата
            if args.output:
                file_write_mode = "wb" if is_encrypt_operation else "w"
                file_encoding = None if is_encrypt_operation else "utf8"
                with open(args.output, mode=file_write_mode, encoding=file_encoding) as file:
                    file.write(result_data)
                print(f"Записано в файл [{file.name}]: {len(result_data)} байт")
            else:
                print(f"{'Зашифрованные данные (в Base64 формате)' if is_encrypt_operation else 'Расшифрованные данные'}:")
                print(base64.b64encode(result_data).decode() if is_encrypt_operation else result_data)
    except Exception as ex:
        print(f"Ошибка: {ex}", file=sys.stderr, end='\n\n')
        sys.exit(1)


# ТОЧКА ВХОДА
# ---------------------------------------------

def main():
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        arguments_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрервано пользователем...")