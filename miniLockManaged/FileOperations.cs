using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Chaos.NaCl;
using Newtonsoft.Json;
using System.Runtime.InteropServices;

namespace miniLockManaged
{
    public partial class FileOperations
    {
        internal const int MAX_CHUNK_SIZE = 1048576;

        public class HeaderInfo // not a struct so that it can be null
        {
            public int version; //currently always 1
            public string ephemeral; // public ephemeral key used only for a single file, Base64, not Base58!
            // recipient iterates through ALL decryptInfo key/value pairs until his/her shared key decrypts one
            public Dictionary<string, string> decryptInfo; //<nonce, encrypted info in Base64>, use OuterShared

            public HeaderInfo() { } // need a blank contructor for Serialization/Deserialization

            internal HeaderInfo(int v, string e, Dictionary<string, string> di)
            {
                version = v; ephemeral = e; decryptInfo = di;
            }

            public string ToJSON()
            {
                return JsonConvert.SerializeObject(this, Formatting.None);
            }
            public static HeaderInfo FromJSON(string j)
            {
                return (HeaderInfo)JsonConvert.DeserializeObject(j, typeof(HeaderInfo));
            }
        }

        public class InnerHeaderInfo // not a struct so that it can be null
        {
            // buried under the decryptInfo of the HeaderInfo; only decryptable if recipient
            //  was listed during file encryption
            public string senderID;  // SenderPublicID 
            public string recipientID; // RecipientPulicID, must match Recipient when structure is decrypted using OuterShared key
            public string fileInfo; // encrypted, Base64, use InnerShared key

            public InnerHeaderInfo() { } // need a blank contructor for Serialization/Deserialization

            internal InnerHeaderInfo(string s, string r, string efi)
            {
                senderID = s; recipientID = r; fileInfo = efi;
            }

            public string ToJSON()
            {
                return JsonConvert.SerializeObject(this, Formatting.None);
            }
            public static InnerHeaderInfo FromJSON(string j)
            {
                return (InnerHeaderInfo)JsonConvert.DeserializeObject(j, typeof(InnerHeaderInfo));
            }
        }

        public class FileInfo // not a struct so that it can be null
        {
            //TODO:  since these are strings, how do we safely wipe/dispose them!?

            // inner most construct; only after a header has been decrypted down
            //  to the bottom-most level does this information get revealed
            public string fileKey; // random 32 bytes, Base64Encoded
            public string fileNonce; // random 16 bytes, Base64Encoded
            public string fileHash; // Blake2s hash of final ciphertext

            public FileInfo() { } // need a blank contructor for Serialization/Deserialization

            internal FileInfo(string k, string n, string h)
            {
                fileKey = k; fileNonce = n; fileHash = h;
            }

            public string ToJSON()
            {
                return JsonConvert.SerializeObject(this, Formatting.None);
            }
            public static FileInfo FromJSON(string j)
            {
                return (FileInfo)JsonConvert.DeserializeObject(j, typeof(FileInfo));
            }
        }

        internal struct FullHeader
        {
            // (not part of the spec, just used to transport information)
            // TODO: need a way to properly wipe this information when it's no longer needed (before garbage collection).
            //   Maybe store EVERYTHING as byte arrays and then use fixed positioning to expose a variable
            //   that is the entire structure in one array for wiping? (like classic C union?)

            public int version; // 4 bytes, but currenly always "1", so size is pretty arbitrary unless it becomes a Single or Float
            public byte[] ephemeralPublicKey; // 32 bytes without checksum
            public byte[] senderID; // 32 bytes without checksum 
            public byte[] recipientID; // 32 bytes without checksum
            public byte[] fileKey; // 32 bytes
            public byte[] fileNonce; // 16 bytes
            public byte[] ciphertextHash; // 32 bytes

            public void UpdateFromHeader(HeaderInfo h)
            {
                version = h.version;
                ephemeralPublicKey = h.ephemeral.ToBytesFromBase64();
            }
            public void UpdateFromInnerHeader(InnerHeaderInfo ih)
            {
                senderID = Keys.GetBytesFromPublicKey(ih.senderID);
                recipientID = Keys.GetBytesFromPublicKey(ih.recipientID);
            }
            public void UpdateFromFileInfo(FileInfo fi)
            {
                fileKey = fi.fileKey.ToBytesFromBase64();
                fileNonce = fi.fileNonce.ToBytesFromBase64();
                ciphertextHash = fi.fileHash.ToBytesFromBase64();
            }

            public void Clear()
            {
                this.ciphertextHash.Wipe();
                this.ephemeralPublicKey.Wipe();
                this.fileKey.Wipe();
                this.fileNonce.Wipe();
                this.recipientID.Wipe();
                this.senderID.Wipe();
            }
        }

        public class DecryptedFileDetails // not a struct so that it can be null
        {
            //(not part of the spec)
            public string SenderID;
            public string PlainTextBlake2sHash;
            public string StoredFilename;
            public string ActualDecryptedFilePath; // this is used if the file gets appended with a (1) or (2), etc.
        }

        internal static System.IO.FileStream GetTempFileStream(out string FullPath)
        {
            string rndpath = "";
            do
            {
                string guidFilePart = "x" + Guid.NewGuid().ToString("N").Substring(0, 8);
                rndpath = Path.Combine(
                    Path.GetTempPath(), guidFilePart);
            } while (Directory.Exists(rndpath));
            Directory.CreateDirectory(rndpath);
            rndpath += "\\";
            string rndfilename = "x" + Guid.NewGuid().ToString("N").Substring(0, 10) + ".dat";
            // since the path didn't exist prior to this, the filename didn't either.
            FullPath = rndpath + rndfilename;
            return new FileStream(FullPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Delete, 1024, false);
        }

        internal static void TrashTempFileStream(System.IO.FileStream fs, string FullPath)
        {
            fs.Position = 0;
            for (int i = 0; i < fs.Length; i++)
            {
                fs.WriteByte(0);
            }
            fs.Flush();
            fs.Close();
            fs.Dispose();
            // WARNING:  only do this if the path created in GetTempFileStream also creates a random subdir
            Directory.Delete(new System.IO.FileInfo(FullPath).DirectoryName, true); 
        }



        //Decryptor (see definition in Decryptor.cs)

        //Encryptor (see definition in Encryptor.cs)

    }
}
