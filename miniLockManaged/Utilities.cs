using System;
using Blake2sCSharp;

namespace miniLockManaged
{
    public static class Utilities
    {   
        public static UInt32 BytesToUInt32(byte[] buf, int offset) //
        {
            return
                (((UInt32)buf[offset + 3] << 24) +  //
                 ((UInt32)buf[offset + 2] << 16) + //
                 ((UInt32)buf[offset + 1] << 8) + //
                  (UInt32)buf[offset]
                                        ); //
        }

        public static void UInt32ToBytes(UInt32 value, byte[] buf, int offset) //
        {
            buf[offset + 3] = (byte)(value >> 24); 
            buf[offset + 2] = (byte)(value >> 16); 
            buf[offset + 1] = (byte)(value >> 8); 
            buf[offset] = (byte)value;
        }
        
        public static byte[] UInt32ToBytes(UInt32 value) 
        {
            byte[] buf = new byte[4];
            buf[3] = (byte)(value >> 24); 
            buf[2] = (byte)(value >> 16); 
            buf[1] = (byte)(value >> 8); 
            buf[0] = (byte)value;
            return buf;
        }

        public static UInt64 BytesToUInt64(byte[] buf, int offset) 
        {
            return
                (((UInt32)buf[offset + 3] << 56) +
                 ((UInt32)buf[offset + 3] << 48) +
                 ((UInt32)buf[offset + 3] << 40) +
                 ((UInt32)buf[offset + 3] << 32) +
 
                 ((UInt32)buf[offset + 3] << 24) +
                 ((UInt32)buf[offset + 2] << 16) +
                 ((UInt32)buf[offset + 1] << 8) + 
                  (UInt32)buf[offset]
                                        ); 
        }

        public static void UInt64ToBytes(UInt64 value, byte[] buf, int offset)
        {
            buf[offset + 7] = (byte)(value >> 56); 
            buf[offset + 6] = (byte)(value >> 48); 
            buf[offset + 5] = (byte)(value >> 40); 
            buf[offset + 4] = (byte)(value >> 32); 
            
            buf[offset + 3] = (byte)(value >> 24); 
            buf[offset + 2] = (byte)(value >> 16); 
            buf[offset + 1] = (byte)(value >> 8); 
            buf[offset] = (byte)value;
        }

        public static byte[] UInt64ToBytes(UInt64 value) 
        {
            byte[] buf = new byte[8];
            buf[7] = (byte)(value >> 56); 
            buf[6] = (byte)(value >> 48); 
            buf[5] = (byte)(value >> 40); 
            buf[4] = (byte)(value >> 32); 

            buf[3] = (byte)(value >> 24); 
            buf[2] = (byte)(value >> 16); 
            buf[1] = (byte)(value >> 8); 
            buf[0] = (byte)value;
            return buf;
        }

        public static byte[] GenerateRandomBytes(int count)
        {
            if (count < 1 || count > 32)
                throw new ArgumentOutOfRangeException("count");
            // use secure random number generator
            System.Security.Cryptography.RNGCryptoServiceProvider rng =
                new System.Security.Cryptography.RNGCryptoServiceProvider();
            byte[] buffer = new byte[1024 + 1024 + 1]; // nice and big (but managable) buffer
            rng.GetBytes(buffer);
            // use blake to reduce any potential skew or bias
            Blake2sCSharp.Blake2sConfig bcfg = new Blake2sCSharp.Blake2sConfig(); 
            bcfg.OutputSizeInBytes = count;
            return Blake2sCSharp.Blake2S.ComputeHash(buffer, bcfg);
        }

        public static string CopyRightAndLicenseStatements()
        {
            return Properties.Resources.CopyRightAndLicenseStatements;
        }

    }
}
