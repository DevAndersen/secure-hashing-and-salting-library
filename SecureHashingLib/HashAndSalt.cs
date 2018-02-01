using System;

namespace SecureHashingLib
{
    /// <summary>
    /// DTO, containing read-only properties for storing a hash and an associated salt.
    /// </summary>
    [Serializable]
    public class HashAndSalt
    {
        public byte[] Hash { get; }
        public byte[] Salt { get; }

        public HashAndSalt(byte[] hash, byte[] salt)
        {
            Hash = hash;
            Salt = salt;
        }
    }
}
