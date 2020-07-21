using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecureEncryption
{
    public class HybridEncryption
    {        
        private readonly AESEncryption _aesEncryption = new AESEncryption();        
        public EncryptedPacket EncryptData(string original, RSAEncryption rsaEncryption)
        {
            //Bug 1: Hard coded key and initialization vector should not be used
            byte[] key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            byte[] iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            using (SymmetricAlgorithm aes = SymmetricAlgorithm.Create("AES"))
            {
                aes.Key = key;
                aes.IV = iv;

                EncryptedPacket encryptedPacket = new EncryptedPacket { Iv = aes.IV };

                encryptedPacket.EncryptedData = _aesEncryption.EncryptStringToBytes_Aes(original, key, encryptedPacket.Iv);

                encryptedPacket.EncryptedSessionKey = rsaEncryption.EncryptData(aes.Key);

                //Bug 2: Weak hashing technique used
                using(KeyedHashAlgorithm hmac = KeyedHashAlgorithm.Create("HMACSHA1"))
                {                    
                    hmac.Key = aes.Key;
                    encryptedPacket.Hmac = hmac.ComputeHash(encryptedPacket.EncryptedData);
                }
                

                return encryptedPacket;
            }            
            
        }

        public string DecryptData(EncryptedPacket encryptedPacket, RSAEncryption rsaEncryption)
        {
            var decryptedSessionKey = rsaEncryption.DecryptData(encryptedPacket.EncryptedSessionKey);

            using (KeyedHashAlgorithm hmac = KeyedHashAlgorithm.Create("HMACSHA1"))
            {               
                hmac.Key = decryptedSessionKey;
                var decryptedHmac = hmac.ComputeHash(encryptedPacket.EncryptedData);           

                if (!CompareHashes(decryptedHmac, encryptedPacket.Hmac))
                {
                    throw new CryptographicException("The message has been modified during transit. Dropping message");
                }
            }

            var decryptedData = _aesEncryption.DecryptStringFromBytes_Aes(encryptedPacket.EncryptedData, decryptedSessionKey, encryptedPacket.Iv);

            return decryptedData;
        }

        public static bool CompareHashes(byte[] hash1, byte[] hash2)
        {
            bool result = hash1.Length == hash2.Length;

            for (int i = 0; i < hash1.Length && i < hash2.Length; i++)
            {
                result &= hash1[i] == hash2[i];

            }

            return result;
        }
    }
}
