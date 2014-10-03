using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Chaos.NaCl;
using Newtonsoft.Json;
namespace miniLockManaged
{
    public partial class FileOperations
    {
        public static byte[] EncryptFile(System.IO.FileInfo SourceFile, string[] Recipients, Keys SenderKeys)
        {
            // crypto variables
            // THESE SHOULD BE RANDOM!
            byte[] fileNonce = Utilities.GenerateRandomBytes(16);
            byte[] fileKey = Utilities.GenerateRandomBytes(32);
            Keys ephemeral = new Keys(true);

            // these are dependant on recipients
            byte[] sharedKey = null;
            // validate parameters

            //process chunks
            UTF8Encoding utf8 = new UTF8Encoding();
            MemoryStream ms = new MemoryStream(); // processed chunks go here
            FileStream fs = new FileStream(SourceFile.FullName, FileMode.Open, FileAccess.Read);
            long fileCursor = 0;
            byte[] chunk = null;
            UInt64 chunkCount = 0;
            byte[] chunkNonce = new byte[24]; // always a constant length
            // this part of the nonce doesn't change
            Array.Copy(fileNonce, chunkNonce, fileNonce.Length); // copy it once and be done with it
            do
            {
                if (chunkCount++ == 0) // first chunk is always '\0'-padded filename
                {
                    chunk = new byte[256];
                    Array.Copy(utf8.GetBytes(SourceFile.Name), chunk, SourceFile.Name.Length);
                }
                else
                {
                    if (fileCursor + MAX_CHUNK_SIZE >= SourceFile.Length)
                    {
                        // last chunk
                        chunkNonce[23] |= 0x80;
                        chunk = new byte[SourceFile.Length - fileCursor];
                    }
                    else
                    {
                        chunk = new byte[MAX_CHUNK_SIZE];
                    }
                    if (fs.Read(chunk, 0, chunk.Length) != chunk.Length)
                        throw new System.IO.IOException("Abrupt end of file");
                    fileCursor += chunk.Length;
                }
                byte[] outBuffer = XSalsa20Poly1305.Encrypt(chunk, fileKey, chunkNonce);
                ms.Write(Utilities.UInt32ToBytes((uint)chunk.Length), 0, 4);
                ms.Write(outBuffer, 0, outBuffer.Length);
                // since the first chunkNonce is just the fileNonce and a bunch of 0x00's, 
                //  it's safe to do this as a post-process update
                Utilities.UInt64ToBytes(chunkCount, chunkNonce, 16);
            } while (fileCursor < SourceFile.Length);

            //build header (fileInfo needed first, but same for all recipients...
            FileInfo fi = new FileInfo(
                fileKey.ToBase64String(),
                fileNonce.ToBase64String(),
                Blake2sCSharp.Blake2S.ComputeHash(ms.ToArray()).ToBase64String());
            byte[] fiBytes = utf8.GetBytes(fi.ToJSON()); // encrypt this to the recipients next...

            //build inner headers next (one for each recipient)
            Dictionary<string, string> innerHeaders = new Dictionary<string, string>(Recipients.Length);
            foreach (string recip in Recipients)
            {
                // each recipient is not identified in the outer header, only a random NONCE
                byte[] recipientNonce = Utilities.GenerateRandomBytes(24);
                sharedKey = SenderKeys.GetShared(recip); // INNER SHARED KEY (Sender Secret + Recipient Public)
                InnerHeaderInfo ih = new InnerHeaderInfo(
                    SenderKeys.PublicID,
                    recip,
                    XSalsa20Poly1305.Encrypt(fiBytes, sharedKey, recipientNonce).ToBase64String()); // fileInfo JSON object encrypted, Base64
                sharedKey = // OUTER SHARED KEY (Ephemeral Secret + Recipient Public)
                    ephemeral.GetShared(recip);
                string encryptedInnerHeader = ih.ToJSON();
                encryptedInnerHeader = XSalsa20Poly1305.Encrypt(utf8.GetBytes(encryptedInnerHeader), sharedKey, recipientNonce).ToBase64String();
                innerHeaders.Add(recipientNonce.ToBase64String(), encryptedInnerHeader);
            }
            // finally the outer header, ready for stuffing into the file
            HeaderInfo hi = new HeaderInfo(1, ephemeral.PublicKey.ToBase64String(), innerHeaders);
            string fileHeader = hi.ToJSON();

            MemoryStream output = new MemoryStream();
            output.Write(utf8.GetBytes("miniLock"), 0, 8); // file identifier (aka "magic bytes")
            output.Write(Utilities.UInt32ToBytes((uint)fileHeader.Length), 0, 4); // header length in 4 little endian bytes
            output.Write(utf8.GetBytes(fileHeader), 0, fileHeader.Length); // the full JSON header object
            output.Write(ms.ToArray(), 0, (int)ms.Length); // the ciphertext
            // since we're writing to a memory stream, nothing to flush BUT
            //  if we were writing to a file, there sould need to be some flushing HERE
            return output.ToArray();
        }
    }
}
