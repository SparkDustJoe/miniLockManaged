using System;
using System.Numerics;
using System.Linq;

namespace System
{
    public static class miniLockExtenstions
    {
        public static string ToBase64String(this byte[] data)
        {
            return Convert.ToBase64String(data);
        }

        public static byte[] ToBytesFromBase64(this string data)
        {
            if (!data.IsValidBase64())
                throw new InvalidOperationException("Source string is not valid Base64!");
            return Convert.FromBase64String(data);
        }

        #region Thanks to CodesInChaos for Base58 implementations (originally used for BitCoin addresses);
        public static string ToBase58String(this byte[] data)
        {

            const string Digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

            // Decode byte[] to BigInteger
            BigInteger intData = 0;
            for (int i = 0; i < data.Length; i++)
            {
                intData = intData * 256 + data[i];
            }

            // Encode BigInteger to Base58 string
            string result = "";
            while (intData > 0)
            {
                int remainder = (int)(intData % 58);
                intData /= 58;
                result = Digits[remainder] + result;
            }

            // Append `1` for each leading 0 byte
            for (int i = 0; i < data.Length && data[i] == 0; i++)
            {
                result = '1' + result;
            }
            return result;
        }

        public static byte[] ToBytesFromBase58(this string data)
        {
            if (string.IsNullOrWhiteSpace(data))
                return new byte[] { };
            const string Digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            if (!data.IsValidBase58())
                throw new InvalidOperationException("Source string is not a valid Base58 string!");

            // Decode Base58 string to BigInteger
            BigInteger intData = 0;
            for (int i = 0; i < data.Length; i++)
            {
                int digit = Digits.IndexOf(data[i]); //Slow
                if (digit < 0)
                    throw new FormatException(string.Format("Invalid Base58 character '{0}' at position {1}", data[i], i));
                intData = intData * 58 + digit;
            }

            // Encode BigInteger to byte[]
            // Leading zero bytes get encoded as leading '1' characters
            int leadingZeroCount = data.TakeWhile(c => c == '1').Count();
            var leadingZeros = Enumerable.Repeat((byte)0, leadingZeroCount);
            var bytesWithoutLeadingZeros =
            intData.ToByteArray()
                .Reverse()// to big endian
                .SkipWhile(b => b == 0);//strip sign byte
            var result = leadingZeros.Concat(bytesWithoutLeadingZeros).ToArray();
            return result;
        }
        #endregion

        #region Regular expression testing from miniLock project and adapted here
        public static bool IsValidBase64(this string data)
        {
            if (string.IsNullOrEmpty(data))
                return false;
            var base64Match = new System.Text.RegularExpressions.Regex
                (@"^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$");
            if (base64Match.IsMatch(data))
                return true;
            else
                return false;
        }

        public static bool IsValidBase58(this string data)
        {
            if (string.IsNullOrEmpty(data))
                return false;
            var base58Match = new System.Text.RegularExpressions.Regex
                ("^[1-9ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$");
            return base58Match.IsMatch(data);
        }
        #endregion

    }
}
