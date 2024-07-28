using System;
using System.Security;
using System.Windows.Navigation;
using mRemoteNG.Security.SymmetricEncryption;
using Org.BouncyCastle.Security;

// ReSharper disable ArrangeAccessorOwnerBody

namespace mRemoteNG.Security
{
    public class EncryptedSecureString : IDisposable
    {
        private static SecureString _machineKey;
        private SecureString _secureString;
        private readonly ICryptographyProvider _cryptographyProvider;

        private static SecureString MachineKey
        {
            get { return _machineKey ?? (_machineKey = GenerateNewMachineKey(32)); }
        }

        public EncryptedSecureString()
        {
            _secureString = new SecureString();
            _cryptographyProvider = new AeadCryptographyProvider();
        }

        public EncryptedSecureString(string unencryptedValue) : this()
        {
            SetValue(unencryptedValue);
        }

        public EncryptedSecureString(ICryptographyProvider cryptographyProvider)
        {
            _secureString = new SecureString();
            _cryptographyProvider = cryptographyProvider;
        }

        public string GetClearTextValue()
        {
            string encryptedText = _secureString.ConvertToUnsecureString();
            string clearText = _cryptographyProvider.Decrypt(encryptedText, MachineKey);
            return clearText;
        }

        public string GetEncryptedValue()
        {
            return _secureString.ConvertToUnsecureString();
        }

        public SecureString GetClearTextSecureValue()
        {
            var secure = _cryptographyProvider.Decrypt(_secureString, MachineKey);
            return secure;
        }

        public EncryptedSecureString SetEncryptedValue(string value)
        {
            _secureString = value.ConvertToSecureString();
            return this;
        }

        public EncryptedSecureString SetValue(string value)
        {
            string cipherText = _cryptographyProvider.Encrypt(value, MachineKey);
            _secureString = cipherText.ConvertToSecureString();
            return this;
        }

        private static SecureString GenerateNewMachineKey(int keySize)
        {
            SecureRandom random = new();
            random.SetSeed(random.GenerateSeed(128));

            string machineKeyString = "";
            for (int x = 0; x < keySize; x++)
            {
                machineKeyString += (char)random.Next(33, 126);
            }

            return machineKeyString.ConvertToSecureString();
        }

        private void Dispose(bool disposing)
        {
            if (!disposing) return;

            _machineKey?.Dispose();
            _secureString?.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}