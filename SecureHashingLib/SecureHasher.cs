using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureHashingLib
{
    /// <summary>
    /// Provides flexible logic for securely hashing (and salting) a serializable object, or a byte array.
    /// </summary>
    public class SecureHasher
    {
        /// <summary>
        /// The logic for salting the bytes that are to be hashed.
        /// The default logic is byte[].Concat(saltBytes).
        /// Different logic should be used if it is faster than the default, for the given use case.
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public delegate byte[] SaltingDelegate(byte[] bytes, byte[] salt);

        /// <summary>
        /// Contains the salts that have already been used, in order to avoid salt collisions.
        /// </summary>
        public List<byte[]> ExistingSalts { get; set; }

        private Random rand = new Random();

        private HashAlgorithm hashAlgorithm;
        private int hashingRounds;
        private int saltBytesLength;
        private int saltRetryCap;
        private SaltingDelegate saltingDelegate;
        private bool autoUpdateExistingSaltsInternally;

        /// <summary>
        /// SecureHasher constructor. All parameters, except for hashAlgorithm, are optional.
        /// This is to ensure the hashing algorithm is always chosen based on system development requirements, and timely security practices.
        /// </summary>
        /// <param name="hashAlgorithm">The hashing algorithm (in the form of a child of System.Security.Cryptography.HashAlgorithm) to be used.</param>
        /// <param name="hashingRounds">The number of rounds of hashing and salting.</param>
        /// <param name="saltBytesLength">The length of the salt in bytes. Defaults to 8.</param>
        /// <param name="saltingDelegate">The logic for salting the bytes that are to be hashed. The default logic (null) is byte[].Concat(saltBytes). Different logic should be used if it is faster than the default, for the given use case.</param>
        /// <param name="existingSalts">A list of salts already used. Used to avoid salt collisions. Defaults to an empty list.</param>
        /// <param name="autoUpdateExistingSaltsInternally">Determines if the list of existing salts should dynamically update when a new salt is succesfully used. Defaults to true.</param>
        /// <param name="saltRetryCap">The number of times to try a new salt, in case a salt collision is encountered. If this limit is hit, a TimeoutException exception will be thrown, suggesting that the saltBytesLength parameter might be too small. Defaults to 1000.</param>
        public SecureHasher(HashAlgorithm hashAlgorithm, int hashingRounds, int saltBytesLength = 8, SaltingDelegate saltingDelegate = null, List<byte[]> existingSalts = null, bool autoUpdateExistingSaltsInternally = true, int saltRetryCap = 1000)
        {
            this.hashAlgorithm = hashAlgorithm;
            this.hashingRounds = hashingRounds;
            this.saltBytesLength = saltBytesLength;
            ExistingSalts = existingSalts ?? new List<byte[]>();
            this.saltingDelegate = saltingDelegate ?? DefaultSaltingLogic;
            this.autoUpdateExistingSaltsInternally = autoUpdateExistingSaltsInternally;
            this.saltRetryCap = saltRetryCap;
        }

        /// <summary>
        /// Salts and hashes the bytes parameter according to the specifications described in the SecureHasher constructor.
        /// Returns a HashAndSalt object, containing the hash and salt as properties.
        /// </summary>
        /// <param name="bytes">The bytes to be hashed and salted.</param>
        /// <returns></returns>
        public HashAndSalt Hash(byte[] bytes)
        {
            byte[] salt = GenerateSalt();
            byte[] saltedBytes = saltingDelegate(bytes, salt);

            byte[] hash = saltedBytes;

            for (int round = 0; round < hashingRounds; round++)
            {
                hash = hashAlgorithm.ComputeHash(hash);
            }

            HashAndSalt hashAndSalt = new HashAndSalt(hash, salt);
            if (autoUpdateExistingSaltsInternally)
            {
                ExistingSalts.Add(salt);
            }
            return hashAndSalt;
        }

        /// <summary>
        /// Deserializes the obj parameter to a byte array, then hashes and salts those bytes according to the specifications described in the SecureHasher constructor.
        /// Returns a HashAndSalt object, containing the hash and salt as properties.
        /// </summary>
        /// <param name="obj">The object to be deserialized, then hashed and salted.</param>
        /// <returns></returns>
        public HashAndSalt Hash(object obj)
        {
            byte[] bytes = SerializeObjectToBytes(obj);
            return Hash(bytes);
        }

        /// <summary>
        /// Updates the list of existing salts, by replacing the current list with the newly provided list in the existingSalts parameter.
        /// Should be used if external sources can modify salts.
        /// </summary>
        /// <param name="existingSalts">The full, updated list of salts.</param>
        public void UpdateExistingSalts(List<byte[]> existingSalts)
        {
            ExistingSalts = existingSalts;
        }

        /// <summary>
        /// Generates a random, unique salt of the length specified in the SecureHasher constructor.
        /// </summary>
        /// <returns></returns>
        private byte[] GenerateSalt()
        {
            byte[] salt = new byte[saltBytesLength];
            int retryCounter = 0;
            bool hasGeneratedUniqueSalt = false;
            while (!hasGeneratedUniqueSalt)
            {
                rand.NextBytes(salt);
                if (ExistingSalts.Count == 0 || IsSaltUnique(salt))
                {
                    hasGeneratedUniqueSalt = true;
                }
                else
                {
                    if (retryCounter > saltRetryCap)
                    {
                        throw new TimeoutException("Salting retry cap reached, did not manage to generate a unique salt. The salt size might be too small.");
                    }
                    retryCounter++;
                }
            }
            return salt;
        }

        /// <summary>
        /// Determines if a given salt has already been used.
        /// </summary>
        /// <param name="salt">The salt to be checked for uniqueness.</param>
        /// <returns></returns>
        private bool IsSaltUnique(byte[] salt)
        {
            foreach (byte[] existingSalt in ExistingSalts)
            {
                if (existingSalt.SequenceEqual(salt))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// The default logic for applying the salt to the bytes that are to be hashed.
        /// Can be overridden if the saltingDelegate parameter is specified in the SecureHasher constructor.
        /// </summary>
        /// <param name="bytes">Unhashed bytes.</param>
        /// <param name="salt">Salt bytes.</param>
        /// <returns></returns>
        private byte[] DefaultSaltingLogic(byte[] bytes, byte[] salt)
        {
            return bytes.Concat(salt).ToArray();
        }

        /// <summary>
        /// Serializes an object to a byte array.
        /// Throws an ArgumentNullException if the obj paramenter is null.
        /// Throws a SerializationException if the obj parameter refers to an object of a type that does not implement the Serializable marker interface.
        /// </summary>
        /// <param name="obj">The object to be serialized.</param>
        /// <returns></returns>
        private static byte[] SerializeObjectToBytes(object obj)
        {
            if (obj == null)
                throw new ArgumentNullException("Object is null.");

            if (!obj.GetType().IsSerializable)
                throw new SerializationException("Type of object is not serializable.");

            BinaryFormatter binaryFormatter = new BinaryFormatter();
            using (MemoryStream memoryStream = new MemoryStream())
            {
                binaryFormatter.Serialize(memoryStream, obj);
                return memoryStream.ToArray();
            }
        }
    }
}
