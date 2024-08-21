using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.IO.Compression;

namespace ArtemisSecurity
{
    public static class ArtemisObfuscation
    {
        private static readonly int KeyRotationInterval = 24; // hours
        private static DateTime lastKeyRotation = DateTime.MinValue;
        private static string currentKey = "InitialKey";

        public static string Encrypt(string plainText)
        {
            RotateKeyIfNeeded();
            using var aes = Aes.Create();
            aes.Key = DeriveKey(currentKey);
            aes.GenerateIV();

            using var msEncrypt = new MemoryStream();
            using (var csEncrypt = new CryptoStream(msEncrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(csEncrypt))
            {
                var compressedData = Compress(Encoding.UTF8.GetBytes(plainText));
                writer.Write(compressedData.Length);
                writer.Write(compressedData);
            }

            var cipherText = msEncrypt.ToArray();
            var result = new byte[aes.IV.Length + cipherText.Length];
            Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
            Buffer.BlockCopy(cipherText, 0, result, aes.IV.Length, cipherText.Length);

            return Convert.ToBase64String(result);
        }

        public static string Decrypt(string cipherText)
        {
            var fullCipher = Convert.FromBase64String(cipherText);
            using var aes = Aes.Create();
            var iv = new byte[aes.BlockSize / 8];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);

            aes.Key = DeriveKey(currentKey);
            aes.IV = iv;

            using var msDecrypt = new MemoryStream(cipher);
            using var csDecrypt = new CryptoStream(msDecrypt, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var reader = new BinaryReader(csDecrypt);
            var length = reader.ReadInt32();
            var compressedData = reader.ReadBytes(length);
            var decompressedData = Decompress(compressedData);
            return Encoding.UTF8.GetString(decompressedData);
        }

        private static void RotateKeyIfNeeded()
        {
            if (DateTime.UtcNow - lastKeyRotation > TimeSpan.FromHours(KeyRotationInterval))
            {
                currentKey = GenerateNewKey();
                lastKeyRotation = DateTime.UtcNow;
            }
        }

        private static string GenerateNewKey()
        {
            using var rng = new RNGCryptoServiceProvider();
            var keyBytes = new byte[32];
            rng.GetBytes(keyBytes);
            return Convert.ToBase64String(keyBytes);
        }

        private static byte[] DeriveKey(string key)
        {
            using var deriveBytes = new Rfc2898DeriveBytes(key, Encoding.UTF8.GetBytes("ArtemisObfuscationSalt"), 10000);
            return deriveBytes.GetBytes(32);
        }

        private static byte[] Compress(byte[] data)
        {
            using var output = new MemoryStream();
            using (var gzip = new GZipStream(output, CompressionMode.Compress))
            {
                gzip.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }

        private static byte[] Decompress(byte[] data)
        {
            using var input = new MemoryStream(data);
            using var output = new MemoryStream();
            using (var gzip = new GZipStream(input, CompressionMode.Decompress))
            {
                gzip.CopyTo(output);
            }
            return output.ToArray();
        }
    }
}