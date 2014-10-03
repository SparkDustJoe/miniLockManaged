using System;
using System.Text;
using Blake2sCSharp;
using CryptSharp.Utility; //SCRYPT
using System.Security.Cryptography;
using MFZ = Zxcvbn;
using mlZ = miniLockManaged.ZXCVBN;
using Chaos.NaCl; //XSalsa20Poly1305, Montgomery25519

namespace miniLockManaged
{
    public class Keys
    {
        internal byte[] _Secret = null;
        internal byte? _SecretChecksum = null;
        private byte[] _Public = null;
        private byte _PublicChecksum = 0;
        private string _PublicID = null;

        public bool Initialized { get { return _Secret != null; } }

        public string PublicID { get { return _PublicID; } }
        public byte[] PublicKey { get { return (byte[])_Public.Clone(); } }

        internal byte[] Secret // internal in an attempt to prevent leakage.
        {
            get
            {
                if (!Initialized)
                    throw new NullReferenceException("Keys object not initilized with an e-mail address and passphrase.");
                ProtectedMemory.Unprotect(_Secret, MemoryProtectionScope.SameProcess);
                byte[] stuff = (byte[])_Secret.Clone();
                ProtectedMemory.Protect(_Secret, MemoryProtectionScope.SameProcess);
                return stuff;
            }
        }

        public Keys() { }

        // force user to do Initialize so that process fails gracefully, not forcefully
        //public Keys(string EMail, string Passphrase)
        //{
        //    if (!Initialize(EMail, Passphrase))
        //        throw new InvalidOperationException(
        //            "Failed to initialize.  Passphrase didn't meet complexity requirements. " +
        //            "Use ScorePassphrase first to determine quality of Passphrase before passing to new() or Initialize() methods");
        //}

        internal Keys(bool ephemeral)
        {
            if (ephemeral == false)
                throw new InvalidOperationException();

            _Secret = Utilities.GenerateRandomBytes(32);
            _SecretChecksum = ComputeChecksum(_Secret);

            _PublicID = GeneratePublicIDFromSecret(_Secret, out _PublicChecksum);
            //PROTECT MEMORY AFTER LAST USE OF _Secret
            ProtectedMemory.Protect(_Secret, MemoryProtectionScope.SameProcess);
            _Public = GetBytesFromPublicKey(_PublicID);
        }

        /// <summary>
        /// Initializes the state of Key Pair assuming the given Passphrase includes a higher then 100-bit
        /// entropy score using ZXCVBN analysis.  Returns false if the Passphrase does not pass this test, and the
        /// object is not initialized as a result.  Returns true with the Key Pair is ready for use.
        /// </summary>
        /// <param name="EMail"></param>
        /// <param name="Passphrase"></param>
        /// <returns>true if OK/Initialized, false if BAD PASSPHRASE</returns>
        public bool Initialize(string EMail, string Passphrase)
        {    
            if (string.IsNullOrWhiteSpace(EMail))
                throw new ArgumentNullException("EMail");
            if (string.IsNullOrWhiteSpace(Passphrase))
                throw new ArgumentNullException("Passphrase");
            if ((int)ScorePotentialPassphrase(Passphrase).Entropy < 100)
                return false;

            byte[] mangledPWD = Blake2S.ComputeHash(new UTF8Encoding().GetBytes(Passphrase.Trim()));
            _Secret = SCrypt.ComputeDerivedKey(mangledPWD, new UTF8Encoding().GetBytes(EMail.Trim()), 131072, 8, 1, 1, 32);
            _SecretChecksum = ComputeChecksum(_Secret);

            _PublicID = GeneratePublicIDFromSecret(_Secret, out _PublicChecksum);
            //PROTECT MEMORY AFTER LAST USE OF _Secret
            ProtectedMemory.Protect(_Secret, MemoryProtectionScope.SameProcess);
            _Public = GetBytesFromPublicKey(_PublicID);
            return true;
        }

        /// <summary>
        /// Get the Curve25519 Shared Key from a senders Public Key byte array.
        /// </summary>
        /// <param name="PartnerPublicKey"></param>
        /// <returns></returns>
        public byte[] GetShared(byte[] PartnerPublicKey)
        {
            if (!Initialized)
                throw new NullReferenceException("Keys object not initilized with an e-mail address and passphrase.");
            return MontgomeryCurve25519.KeyExchange(PartnerPublicKey, Secret);
        }

        /// <summary>
        /// Get the Curve25519 Shared Key from a senders Public miniLock ID.
        /// </summary>
        /// <param name="PartnerPublicKey"></param>
        /// <returns></returns>
        public byte[] GetShared(string PartnerPublicID, bool PartnerPublicIDIsBase64Encoded = false)
        {
            if (string.IsNullOrWhiteSpace(PartnerPublicID))
                throw new ArgumentNullException("PartnerPublicID");
            if (!Initialized)
                throw new NullReferenceException("Keys object not initilized with an e-mail address and passphrase.");
            if (!PartnerPublicIDIsBase64Encoded)
            {
                PartnerPublicID = PartnerPublicID.Trim();
                if (!ValidatePublicKey(PartnerPublicID))
                    throw new ArgumentException("PartnerPublicID not a valid miniLock ID");
                return MontgomeryCurve25519.KeyExchange(Keys.GetBytesFromPublicKey(PartnerPublicID), Secret);
            }
            else
            {
                return MontgomeryCurve25519.KeyExchange(PartnerPublicID.ToBytesFromBase64(), Secret);
            }
        }

        /// <summary>
        /// Attempt to decrypt a byte array using the Secret key.
        /// </summary>
        /// <param name="Payload"></param>
        /// <param name="OriginalNonce"></param>
        /// <returns>Null if authenticated decrypt fails.</returns>
        public byte[] TryDecrypt(byte[] Payload, byte[] OriginalNonce)
        {
            if (!Initialized)
                throw new NullReferenceException("Keys object not initilized with an e-mail address and passphrase.");
            return XSalsa20Poly1305.TryDecrypt(Payload, Secret, OriginalNonce);
        }

        /// <summary>
        /// Attempt to decrypt a byte array using the Shared key between a sender's Public Key byte array and the Secret key.
        /// </summary>
        /// <param name="SenderPublicKey"></param>
        /// <param name="Payload"></param>
        /// <param name="OriginalNonce"></param>
        /// <returns>Null if authenticated decrypt fails.</returns>
        public byte[] TryDecrypt(byte[] SenderPublicKey, byte[] Payload, byte[] OriginalNonce)
        {
            if (!Initialized)
                throw new NullReferenceException("Keys object not initilized with an e-mail address and passphrase.");
            byte[] shared = GetShared(SenderPublicKey);
            return XSalsa20Poly1305.TryDecrypt(Payload, shared, OriginalNonce);
        }

        /// <summary>
        /// Attempt to decrypt a byte array using the Shared key between a sender's Public miniLock ID and the Secret key.
        /// </summary>
        /// <param name="SenderPublicKey"></param>
        /// <param name="Payload"></param>
        /// <param name="OriginalNonce"></param>
        /// <returns>Null if authenticated decrypt fails.</returns>
        public byte[] TryDecrypt(string SenderPublicID, byte[] Payload, byte[] OriginalNonce)
        {
            if (!Initialized)
                throw new NullReferenceException("Keys object not initilized with an e-mail address and passphrase.");
            if (!ValidatePublicKey(SenderPublicID))
                throw new ArgumentException("SenderPublicID not a valid miniLock ID");
            byte[] shared = GetShared(SenderPublicID);
            return Chaos.NaCl.XSalsa20Poly1305.TryDecrypt(Payload, shared, OriginalNonce);
        }

        /// <summary>
        /// Attempt to decrypt a byte array using the Shared key between a sender's Public miniLock ID and the Secret key.
        /// </summary>
        /// <param name="SenderPublicKey"></param>
        /// <param name="Payload"></param>
        /// <param name="OriginalNonce"></param>
        /// <returns>Null if authenticated decrypt fails.</returns>
        public byte[] TryDecrypt(string SenderPublicID, bool SenderPublicIDIsBase64Encoded, byte[] Payload, byte[] OriginalNonce)
        {
            if (!Initialized)
                throw new NullReferenceException("Keys object not initilized with an e-mail address and passphrase.");
            return XSalsa20Poly1305.TryDecrypt(Payload, GetShared(SenderPublicID, SenderPublicIDIsBase64Encoded), OriginalNonce);
        }

        public static string GeneratePublicIDFromSecret(byte[] secret)
        {
            byte throwAway;
            return GeneratePublicIDFromSecret(secret, out throwAway);
        }

        public static string GeneratePublicIDFromSecret(byte[] secret, out byte checkSum)
        {
            byte[] idwchk = new byte[33];
            byte[] thePublicKey = Chaos.NaCl.MontgomeryCurve25519.GetPublicKey(secret);
            Array.Copy(thePublicKey, 0, idwchk, 0, 32);
            checkSum = ComputeChecksum(thePublicKey);
            idwchk[32] = checkSum;
            return idwchk.ToBase58String();
        }

        public static bool ValidatePublicKey(string PublicKeyBase58Encoded)
        {
            if (string.IsNullOrWhiteSpace(PublicKeyBase58Encoded))
                return false;
            PublicKeyBase58Encoded = PublicKeyBase58Encoded.Trim();
            if (PublicKeyBase58Encoded.Length > 55 || PublicKeyBase58Encoded.Length < 40) // from original project
                return false;
            if (!PublicKeyBase58Encoded.IsValidBase58()) // see extension method in Extensions.cs
                return false;
            byte[] test = PublicKeyBase58Encoded.ToBytesFromBase58(); // see extension method in Extensions.cs
            if (test.Length != 33)
                return false;
            return ComputeChecksum(test) == test[32];
        }

        public static byte[] GetBytesFromPublicKey(string PublicKeyBase58Encoded)
        {
            if (!ValidatePublicKey(PublicKeyBase58Encoded))
                return null;
            byte[] result = new byte[32];
            Array.Copy(PublicKeyBase58Encoded.ToBytesFromBase58(), result, 32);
            return result;
        }

        public static string GetPublicIDFromKeyBytes(byte[] PublicKey)
        {
            if (PublicKey == null || PublicKey.Length != 32)
                throw new ArgumentOutOfRangeException("key", "key must be 32 bytes!");
            byte[] idwchk = new byte[33];
            Array.Copy(PublicKey, 0, idwchk, 0, 32);
            byte checkSum = ComputeChecksum(PublicKey);
            idwchk[32] = checkSum;
            return idwchk.ToBase58String();
        }

        internal static byte ComputeChecksum(byte[] key)
        {
            if (key == null || (key.Length != 32 && key.Length != 33))
            {
                throw new ArgumentOutOfRangeException("key must be 32 or 33 bytes");
            }
            return Blake2S.ComputeHash(
                key, 0, 32,
                new Blake2sConfig() { OutputSizeInBytes = 1 })[0];
        }

        public static mlZ.Result ScorePotentialPassphrase(string PotentialPassphrase)
        {
            // we're "boxing" the results in a local class derived from Michael Fords ZXCVBN
            //  Result class so that external users aren't required to include the ZXCVBN library
            mlZ.Result result = new mlZ.Result(MFZ.Zxcvbn.MatchPassword(
                PotentialPassphrase, 
                new string[] { "mini", "lock", "Lock", "minilock", "miniLock" }));
            return result;
        }

    }
}
