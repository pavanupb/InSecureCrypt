using System;
using System.Text;

namespace SecureEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Please enter a message to be encrypted");

            string secretText = Console.ReadLine();

            RSAEncryption rsaEncryption = new RSAEncryption();

            rsaEncryption.AssignNewKey();

            HybridEncryption hybridEncryption = new HybridEncryption();

            var encryptedData = hybridEncryption.EncryptData(secretText, rsaEncryption);

            var decryptedData = hybridEncryption.DecryptData(encryptedData, rsaEncryption);

            Console.WriteLine($"Original String is {secretText}");

            Console.Write($"Decrypted String is {decryptedData}");
        }
    }
}
