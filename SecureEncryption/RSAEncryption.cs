using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecureEncryption
{
    public class RSAEncryption
    {
        private RSAParameters _publicKey;
        private RSAParameters _privateKey;

        public void AssignNewKey()
        {
            using(RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                _publicKey = rsa.ExportParameters(false);
                _privateKey = rsa.ExportParameters(true);
                
            }
        }

        public byte[] EncryptData(byte[] dataToEncrypt)
        {
            byte[] cipherBytes;

            using(RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_publicKey);

                cipherBytes = rsa.Encrypt(dataToEncrypt, false);
            }

            return cipherBytes;
        }

        public byte[] DecryptData(byte[] dataToDecrypt)
        {
            byte[] plainText;

            using(RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                rsa.ImportParameters(_privateKey);
                plainText = rsa.Decrypt(dataToDecrypt, false);
            }

            return plainText;
        }

    }
}
