using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace BlindSignatureLibrary
{
    /// <summary>
    /// Класс для нахождения криптографических элементов по ГОСТ Р 34.10-94.
    /// </summary>
    public class GOSTR341094
    {
        private MathCrypto maths;

        /// <summary>
        /// Базовый конструктор класса для инициализации переменных.
        /// </summary>
        public GOSTR341094()
        {
            maths = new MathCrypto();
        }

        /// <summary>
        /// Вычисляет хэш-функцию sha256 от указанного файла.
        /// </summary>
        /// <param name="pathToFile">Путь до файла.</param>
        /// <returns>Возвращает хэш-функцию sha256 от указанного файла.</returns>
        internal byte[] GetHash(string pathToFile)
        {
            byte[] hash;

            using (FileStream stream = new FileStream(pathToFile, FileMode.Open))
            {
                SHA256 sha256 = new SHA256CryptoServiceProvider();
                BigInteger hashed = new BigInteger(sha256.ComputeHash(stream));

                if (hashed < 0)
                    hashed *= -1;

                hash = hashed.ToByteArray();
            }

            return hash;
        }

        /// <summary>
        /// Находит числа p,q,a.
        /// </summary>
        /// <param name="bits">Размерность числа p.</param>
        /// <param name="p">Возвращает число p.</param>
        /// <param name="q">Возвращает число q.</param>
        /// <param name="a">Возвращает число a.</param>
        public void Find_pqa(int bits, out byte[] p, out byte[] q, out byte[] a)
        {
            // Все имена переменных соответствуют
            // именам алгоритма нахождения чисел p,q,a
            // по GOST Р 34.10-94

            if (bits < 64) throw new ArgumentException("Числа p,q,a не будут являться криптостойкими.", nameof(bits));

            #region Нахождение p, q.

            int m;
            Random rand = new Random();
            const int _2pow16 = 1 << 16;
            int _bits = bits;
            int countBits = 0;

            // Ищем элементы для массива битов
            while (_bits >= 17)
            {
                _bits >>= 1;
                ++countBits;
            }
            int s = 0;

            // Массив битов
            int[] ts = new int[countBits + 1];
            ts[0] = bits;

            for (int i = 0; i < ts.Length; i++)
            {
                if (ts[i] >= 17)
                    ts[i + 1] = ts[i] >> 1;
                else
                    s = i;
            }
            m = s - 1;

            // Массив элементов, откуда найдем p и q
            BigInteger[] masP;

            do
            {
                int rm = ts[m + 1] % 16 == 0 ? ts[m + 1] >> 4 : ts[m + 1] >> 4 + 1;
                BigInteger c;

                do c = rand.Next(1, _2pow16);
                while (c % 2 != 1);

                BigInteger[] mas = new BigInteger[rm];
                mas[0] = rand.Next(1, _2pow16);

                for (int i = 1; i < mas.Length; i++)
                    mas[i] = (19381 * mas[i - 1] + c) % _2pow16;

                BigInteger one = 1;
                BigInteger ym = 0;

                for (int i = 0; i < rm; i++)
                    ym += mas[i] * (one << 161);
                mas[0] = ym;

                // Заполняем массив элементов
                masP = new BigInteger[ts.Length];

                for (int i = 0; i < masP.Length; i++)
                    masP[i] = new BigInteger(maths.GetLowestPrimeNumber(ts[i]));

                BigInteger n = ((one << (ts[m] - 1)) / masP[m + 1]) % 2 == 0
                    ? ((one << (ts[m] - 1)) / masP[m + 1])
                    : ((one << (ts[m] - 1)) / masP[m + 1] + 1) +
                      (one << (ts[m] - 1)) * ym / (masP[m + 1] * (one << (rm << 4)));

                if (n % 2 != 0)
                    ++n;

                BigInteger k = 0;
                while (true)
                {
                    masP[m] = masP[m + 1] * (n + k) + 1;
                    if (BigInteger.ModPow(2, masP[m + 1] * (n + k), masP[m]) == 1 &&
                        BigInteger.ModPow(2, (n + k), masP[m]) != 1)
                    {
                        --m;
                        break;
                    }
                    k += 2;
                }
            } while (m >= 0);

            // Искомое p
            p = masP[0].ToByteArray();
            // Искомое q
            q = masP[1].ToByteArray();

            #endregion

            #region Нахождение a.

            BigInteger f;
            do f = BigInteger.ModPow(maths.Get_RandomNumber(new BigInteger(p)),
                   (new BigInteger(p) - 1) / new BigInteger(q), new BigInteger(p));
            while (f == 1);

            // Искомое a
            a = f.ToByteArray();

            #endregion
        }
    }
}