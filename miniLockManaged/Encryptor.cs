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
        public static long EncryptFile(System.IO.FileInfo SourceFile, FileStream DestinationFile, string[] Recipients, Keys SenderKeys)
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
            Blake2sCSharp.Hasher b2s = Blake2sCSharp.Blake2S.Create();
            UTF8Encoding utf8 = new UTF8Encoding();
            // use cache file instead of a memory stream to conserve used memory MemoryStream ms = new MemoryStream(); // processed chunks go here
            string tempFile = null;
            FileStream cacheFs = GetTempFileStream(out tempFile);
            FileStream fs = new FileStream(SourceFile.FullName, FileMode.Open, FileAccess.Read);
            long fileCursor = 0;
            byte[] chunk = null;
            UInt64 chunkCount = 0;
            byte[] chunkNonce = new byte[24]; // always a constant length
            // this part of the nonce doesn't change
            Array.Copy(fileNonce, chunkNonce, fileNonce.Length); // copy it once and be done with it
            do
            {
                if (chunkCount == 0) // first chunk is always '\0'-padded filename
                {
                    chunk = new byte[256];
                    byte[] filename = utf8.GetBytes(SourceFile.Name);
                    Array.Copy(filename, chunk, filename.Length);
                    filename.Wipe(); // DON'T LEAK!!!
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
                    {
                        // read error!
                        fs.Close();
                        fs.Dispose();
                        TrashTempFileStream(cacheFs, tempFile);
                        throw new System.IO.IOException("Abrupt end of file / read error from source.");
                    }
                    fileCursor += chunk.Length;
                }
                byte[] outBuffer = XSalsa20Poly1305.Encrypt(chunk, fileKey, chunkNonce);
                byte[] chunkLengthBytes = Utilities.UInt32ToBytes((uint)chunk.Length);
                cacheFs.Write(chunkLengthBytes, 0, 4);  // use cache file 
                b2s.Update(chunkLengthBytes); // hash as we go
                cacheFs.Write(outBuffer, 0, outBuffer.Length); // use cache file 
                b2s.Update(outBuffer); // hash as we go
                // since the first chunkNonce is just the fileNonce and a bunch of 0x00's, 
                //  it's safe to do the chunk counter as a post-process update
                Utilities.UInt64ToBytes(++chunkCount, chunkNonce, 16);
            } while (fileCursor < SourceFile.Length);
            
            cacheFs.Flush(true); // make sure everything is flushed to the disk cache
            cacheFs.Position = 0; // leave it open so that we can read it back into the destination
            // get the ciphertext hash for the header
            byte[] cipherTextHash = b2s.Finish();
            // done encrypting to the cache, now to build the header
            
            //build header (fileInfo needed first, but same for all recipients)...
            FileInfo fi = new FileInfo(
                fileKey.ToBase64String(),
                fileNonce.ToBase64String(),
                cipherTextHash.ToBase64String()); 

            byte[] fiBytes = utf8.GetBytes(fi.ToJSON()); // encrypt this to the recipients next...

            //build inner headers next (one for each recipient)
            Dictionary<string, string> innerHeaders = new Dictionary<string, string>(Recipients.Length);
            foreach (string recip in Recipients)
            {
                // each recipient is not identified in the outer header, only a random NONCE
                byte[] recipientNonce = Utilities.GenerateRandomBytes(24);
                sharedKey = // INNER SHARED KEY (Sender Secret + Recipient Public)
                    SenderKeys.GetShared(recip); 
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
            
            // build the final file...
            DestinationFile.Write(utf8.GetBytes("miniLock"), 0, 8); // file identifier (aka "magic bytes")
            DestinationFile.Write(Utilities.UInt32ToBytes((uint)fileHeader.Length), 0, 4); // header length in 4 little endian bytes
            DestinationFile.Write(utf8.GetBytes(fileHeader), 0, fileHeader.Length); // the full JSON header object
            // read back from the cache file into the destination file...
            byte[] buffer;
            for (int i = 0; i < cacheFs.Length; i += buffer.Length)
            {
                if (i + MAX_CHUNK_SIZE >= cacheFs.Length)
                    buffer = new byte[cacheFs.Length - i];
                else
                    buffer = new byte[MAX_CHUNK_SIZE];
                if (cacheFs.Read(buffer, 0, buffer.Length) != buffer.Length)
                    throw new System.IO.IOException("Abrupt end of cache file");
                DestinationFile.Write(buffer, 0, buffer.Length); // the ciphertext
            }
            // now flush and close, and grab length for reporting to caller
            DestinationFile.Flush();
            long tempOutputFileLength = DestinationFile.Length;
            DestinationFile.Close();
            DestinationFile.Dispose();
            // kill the cache and the directory created for it
            TrashTempFileStream(cacheFs, tempFile);
            
            return tempOutputFileLength;
        }
    }
}
