using System;
using System.Numerics;
using System.Security.Cryptography;

namespace BlindSignatureLibrary
{
    /// <summary>
    /// Класс математических операций для криптографии.
    /// </summary>
    public class MathCrypto
    {
        /// <summary>
        /// Вычисляет минимальное простое число заданного количества бит (3 бита и больше).
        /// </summary>
        /// <param name="bits">Размерность минимального вычисляемого простого числа в битах.</param>
        /// <returns>Возвращае минимальное простое число заданного количества бит.</returns>
        public byte[] GetLowestPrimeNumber(int bits)
        {
            if (bits < 3) throw new ArgumentException("Количетсво бит должно быть 3 и больше.", nameof(bits));

            BigInteger primeNumber;
            BigInteger one = 1;

            // Перебор чисел с помощью алгоритма "Решето Аткина"
            for (primeNumber = (one << (bits - 1)) + 1; primeNumber < one << bits; primeNumber++)
            {
                if (primeNumber % 2 == 0) continue;
                if (primeNumber % 3 == 0) continue;
                if (primeNumber % 5 == 0) continue;

                BigInteger x = 0;
                for (BigInteger i = 1; i * i < primeNumber; i++)
                {
                    x += 2 * i - 1;
                    BigInteger y = 0;
                    for (BigInteger j = 1; j * j < primeNumber; j++)
                    {
                        y += 2 * j - 1;

                        BigInteger n = 4 * x + y;
                        if (n < (one << bits) && n % 4 == 1)
                            return primeNumber.ToByteArray();
                        // n = 3 * x2 + y2; 
                        n -= x; // Оптимизация

                        if (n < (one << bits) && n % 6 == 1)
                            return primeNumber.ToByteArray();
                        // n = 3 * x2 - y2;
                        n -= 2 * y; // Оптимизация

                        if ((i > j) && (n < (one << bits)) && (n % 12 == 11))
                            return primeNumber.ToByteArray();
                    }
                }
            }
            return primeNumber.ToByteArray();
        }

        /// <summary>
        /// Вычисляет криптостойкое случайное число от 1 до upperBound.
        /// </summary>
        /// <param name="upperBound">Верхняя граница случайного числа.</param>
        /// <returns>Возвращает криптостойкое случайное число от 1 до upperBound.</returns>
        internal BigInteger Get_RandomNumber(BigInteger upperBound)
        {
            if (upperBound < 2) throw new ArgumentException("Верхняя граница не может быть меньше двух.", nameof(upperBound));

            Random rand = new Random();
            // Массив байтов случайного числа
            byte[] randomArray = new byte[rand.Next(1, (upperBound - 1).ToByteArray().Length)];
            BigInteger randomNumber;
            RNGCryptoServiceProvider randomCrypto = new RNGCryptoServiceProvider();
            // Вычисление случайного числа в границе чисел
            do
            {
                randomCrypto.GetBytes(randomArray);
                randomNumber = new BigInteger(randomArray);
            } while (randomNumber <= 0 || randomNumber >= upperBound);

            return randomNumber;
        }

        /// <summary>
        /// Находит обратный элемент кольца по модулю.
        /// </summary>
        /// <param name="a">Элемент, которому ищем обратный по модулю.</param>
        /// <param name="m">Модуль.</param>
        /// <returns>Возвращает обратный элемент кольца по модулю.</returns>
        public byte[] Get_ReverseMod(byte[] a, byte[] m)
        {
            BigInteger g = GCD(new BigInteger(a), new BigInteger(m), out var x, out _);

            if (g != 1) throw new ArgumentException("Нельзя найти обратный элемент по модулю к данному.", nameof(a));

            return ((x % new BigInteger(m) + new BigInteger(m)) % new BigInteger(m)).ToByteArray();
        }

        /// <summary>
        /// Алгоритм Евклида. Уравнение ax + my = 1.
        /// </summary>
        /// <param name="a">Число a данного уравнения.</param>
        /// <param name="b">Число b данного уравнения.</param>
        /// <param name="x">Число x данного уравнения.</param>
        /// <param name="y">Число y данного уравнения.</param>
        /// <returns>Возвращает модуль решения уравнения.</returns>
        private BigInteger GCD(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
        {
            if (a == 0)
            {
                x = 0;
                y = 1;
                return b;
            }
            BigInteger d = GCD(b % a, a, out var x1, out var y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return d;
        }

        /// <summary>
        /// Нахождение НОД по алгоритму Евклида.
        /// </summary>
        /// <param name="a">Первое число.</param>
        /// <param name="b">Второе число.</param>
        /// <returns>Возвращает НОД двух чисел.</returns>
        private BigInteger GCD(BigInteger a, BigInteger b)
        {
            if (a == 0)
                return b;
            BigInteger d = GCD(b % a, a);
            return d;
        }
    }
}