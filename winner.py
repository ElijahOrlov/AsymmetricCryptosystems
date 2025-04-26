# from sympy import mod_inverse
from fractions import Fraction
import math
#
# # Параметры RSA
# p = 379
# q = 329
# n = p * q
# phi = (p - 1) * (q - 1)
#
# # Задаем малый приватный ключ d
# d_aprox = (1/3) * n**(1/4)
# d_real = 5
# print(f"d (предположительный) = {d_aprox}")
#
# # Вычисляем открытый ключ e
# e = mod_inverse(d_real, phi)
#
# print(f"n = {n}")
# print(f"phi(n) = {phi}")
# print(f"e = {e}")
# print(f"d (реальный) = {d_real}")

# === Атака Винера ===

# 1. Цепная дробь e / n
def continued_fraction(n, d):
    cf = []
    while d:
        q = n // d
        cf.append(q)
        n, d = d, n % d
    return cf

# 2. Получаем приближения (convergents)
def convergents(cf):
    result = []
    for i in range(1, len(cf)+1):
        frac = Fraction(0)
        for q in reversed(cf[:i]):
            frac = 1 / (frac + q) if frac else Fraction(q)
        result.append((frac.numerator, frac.denominator))
    return result

# 3. Попытка найти d
def wiener_attack(e, n):
    cf = continued_fraction(e, n)
    convs = convergents(cf)

    for k, d in convs:
        if k == 0:
            continue
        # Проверка: (ed - 1) % k == 0
        if (e * d - 1) % k != 0:
            continue
        phi_guess = (e * d - 1) // k
        # Решаем квадратное уравнение x^2 - (n - phi + 1)x + n = 0
        a = 1
        b = -(n - phi_guess + 1)
        c = n
        discr = b * b - 4 * a * c
        if discr >= 0:
            sqrtd = math.isqrt(discr)
            if sqrtd * sqrtd == discr:
                print(f"\n✅ Найден приватный ключ: d = {d}")
                return d
    print("❌ Атака Винера не удалась")
    return None

if __name__ == "__main__":
    e = 24797
    n = 124691
    wiener_attack(e, n)
