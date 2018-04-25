using System;
using System.Security.Cryptography;
using System.IO;
using System.Numerics;

namespace BlindSignatureLibrary
{
    /// <summary>
    /// Класс для создания подписей к файлам.
    /// </summary>
    public class BlindSign
    {
        private readonly GOSTR341094 _gost;
        private readonly MathCrypto _maths;
        private BigInteger _p, _q, _a;

        /// <summary>
        /// Инициализация чисел p, q, a.
        /// </summary>
        /// <param name="bits">Размерность числа p.</param>
        public BlindSign(int bits)
        {
            _maths = new MathCrypto();
            _gost = new GOSTR341094();

            _gost.Find_pqa(bits, out var p, out var q, out var a);

            _p = new BigInteger(p);
            _q = new BigInteger(q);
            _a = new BigInteger(a);
        }

        /// <summary>
        /// Выдает закрытый ключ.
        /// </summary>
        /// <returns>Возвращает закрытый ключ.</returns>
        private BigInteger GetPrivateKey()
        {
            BigInteger privateKey;

            do
            {
                RNGCryptoServiceProvider l = new RNGCryptoServiceProvider();
                byte[] privateKeyBytes = new byte[128];
                l.GetBytes(privateKeyBytes);
                privateKey = new BigInteger(privateKeyBytes);
            }
            while (privateKey <= 0);

            return privateKey;
        }

        /// <summary>
        /// Выдает открытый ключ.
        /// </summary>
        /// <param name="privateKey">Закрытый ключ, на основе которого будет считаться открытый ключ.</param>
        /// <param name="a">Число a.</param>
        /// <param name="p">Число p.</param>
        /// <returns>Возвращает открытый ключ.</returns>
        private BigInteger GetPublicKey(BigInteger privateKey, BigInteger a, BigInteger p)
        {
            return BigInteger.ModPow(a, privateKey, p);
        }

        /// <summary>
        /// Выдает пару: закрытый и открытый ключ.
        /// </summary>
        /// <param name="privateKey">Возвращает закрытый ключ.</param>
        /// <param name="publicKey">Возвращает открытый ключ.</param>
        public void GetKeyPair(out byte[] privateKey, out byte[] publicKey)
        {
            privateKey = GetPrivateKey().ToByteArray();
            publicKey = GetPublicKey(new BigInteger(privateKey), _a, _p).ToByteArray();
        }

        /// <summary>
        /// Создает подпись к указанному файлу.
        /// </summary>
        /// <param name="usersCount">Количество пользователей, желающих подписать документ.</param>
        /// <param name="pathToFile">Путь до подписываемого файла.</param>
        /// <param name="pathToSaveSignature">Путь к сохранению подписи.</param>
        /// <param name="pathToSaveDetails">Путь к сохранению открытых ключей.</param>
        public void MakeSignature(int usersCount, string pathToFile, string pathToSaveSignature, string pathToSaveDetails)
        {
            // Все имена переменных соответствуют именам
            // алгоритма формирования коллективной слепой подписи
            // Расширение функциональности стандартов Электронной цифровой подписи

            if (usersCount < 1) throw new ArgumentException("Количество пользователей должно быть больше одного.", nameof(usersCount));

            #region Раздача закрытых ключей.
            BigInteger[] privateKeys = new BigInteger[usersCount];

            for (int i = 0; i < privateKeys.Length; i++)
                privateKeys[i] = GetPrivateKey();
            #endregion

            #region Раздача открытых ключей.
            BigInteger[] publicKeys = new BigInteger[usersCount];

            for (int i = 0; i < publicKeys.Length; i++)
                publicKeys[i] = GetPublicKey(privateKeys[i], _a, _p);
            #endregion

            #region Нахождение первого элемента подписи.
            BigInteger y = 1;
            // Ищем число y
            foreach (var pubKey in publicKeys)
                y *= pubKey;
            y %= _p;

            // Ищем числa k
            BigInteger[] ks = new BigInteger[usersCount];
            for (int i = 0; i < usersCount; i++)
                ks[i] = _maths.Get_RandomNumber(_q);

            // Индивидуальные значения
            BigInteger[] ros = new BigInteger[usersCount];
            for (int i = 0; i < usersCount; i++)
                ros[i] = BigInteger.ModPow(_a, ks[i], _p);

            // Ro
            BigInteger ro = 1;
            for (int i = 0; i < ros.Length; i++)
            {
                ro *= ros[i];
                ro %= _p;
            }

            // u & eps
            BigInteger u = _maths.Get_RandomNumber(_q);
            BigInteger eps = _maths.Get_RandomNumber(_q);

            // Ro'
            BigInteger roshtrih = (((ro * BigInteger.ModPow(y, u, _p)) % _p) * BigInteger.ModPow(_a, eps, _p)) % _p;

            // Первый элемент подписи
            BigInteger firstPart = roshtrih % _q;
            #endregion

            #region Нахождение второго элемента подписи.
            // H
            BigInteger h = new BigInteger(_gost.GetHash(pathToFile));

            // R
            BigInteger r = (firstPart * new BigInteger(_maths.Get_ReverseMod(h.ToByteArray(), _q.ToByteArray())) + u) % _q;

            // Массив значений S[i]
            BigInteger[] ss = new BigInteger[usersCount];

            for (int i = 0; i < usersCount; i++)
                ss[i] = (ks[i] + ((privateKeys[i] * r) % _q)) % _q;

            // S
            BigInteger s = 0;

            for (int i = 0; i < usersCount; i++)
            {
                s += ss[i];
                s %= _q;
            }

            // Второй элемент подписи
            BigInteger secondPart = ((h % _q) * ((s + eps) % _q)) % _q;
            #endregion;

            #region Создание подписи к файлу.
            using (new FileStream(pathToSaveSignature + ".sgn", FileMode.CreateNew)) { }

            // Записываем части подписи в файл
            File.AppendAllLines(pathToSaveSignature + ".sgn", new[] { firstPart.ToString(), secondPart.ToString() });
            #endregion

            #region Сохранение открытых ключей и других деталей формирования подписи.
            string[] details = new string[usersCount + 4];
            details[0] = "y " + y;
            details[1] = "a " + _a;
            details[2] = "p " + _p;
            details[3] = "q " + _q;

            for (int i = 4; i < details.Length; i++)
                details[i] = i - 3 + " " + publicKeys[i - 4];

            using (new FileStream(pathToSaveDetails + ".dat", FileMode.CreateNew)) { }
            // Записываем открытые ключи в файл
            File.WriteAllLines(pathToSaveDetails + ".dat", details);
            #endregion
        }

        /// <summary>
        /// Проверяет подлинность подписи у указанному файлу.
        /// </summary>
        /// <param name="pathToFile">Файл, к которому принадлежит подпись.</param>
        /// <param name="pathToSignature">Подпись.</param>
        /// <param name="pathToDetails">Файл с деталями формирования подписи.</param>
        /// <returns>Возвращает подлинность подписи.</returns>
        public static bool Verify_Signature(string pathToFile, string pathToSignature, string pathToDetails)
        {
            #region Считывание данных.
            BigInteger y, a, p, q;
            GOSTR341094 gost = new GOSTR341094();
            MathCrypto maths = new MathCrypto();

            string[] details = File.ReadAllLines(pathToDetails);

            try
            {
                y = BigInteger.Parse(details[0].Substring(2, details[0].Length - 2));
                a = BigInteger.Parse(details[1].Substring(2, details[1].Length - 2));
                p = BigInteger.Parse(details[2].Substring(2, details[2].Length - 2));
                q = BigInteger.Parse(details[3].Substring(2, details[3].Length - 2));
            }
            catch (Exception)
            {
                return false;
            }

            // Вычисляем значение хэш-функции от указанного файла
            BigInteger h = new BigInteger(gost.GetHash(pathToFile));

            BigInteger r, s;
            string[] signParts = File.ReadAllLines(pathToSignature);

            try
            {
                r = BigInteger.Parse(signParts[0]);
                s = BigInteger.Parse(signParts[1]);
            }
            catch (Exception)
            {
                return false;
            }
            #endregion

            #region Проверка подписи.
            if (r >= q || s >= q) return false;

            #region Дополнительный способ проверки (не оптимизированный).
            /*if (maths.GCD(H, p - 1) == 1)
                return BigInteger.ModPow(
                new BigInteger(maths.Get_ReverseMod(y.ToByteArray(), p.ToByteArray())),
                R * new BigInteger(maths.Get_ReverseMod(H.ToByteArray(), (p - 1).ToByteArray())), p) *
                BigInteger.ModPow(a, S * new BigInteger(maths.Get_ReverseMod(H.ToByteArray(), (p - 1).ToByteArray())), p) % p % q
                == R;
            else*/
            #endregion

            return BigInteger.ModPow(
                new BigInteger(maths.Get_ReverseMod(y.ToByteArray(), p.ToByteArray())),
                r * new BigInteger(maths.Get_ReverseMod(h.ToByteArray(), q.ToByteArray())), p) *
                BigInteger.ModPow(a, s * new BigInteger(maths.Get_ReverseMod(h.ToByteArray(), q.ToByteArray())), p) % p % q
                == r;
            #endregion
        }
    }
}
