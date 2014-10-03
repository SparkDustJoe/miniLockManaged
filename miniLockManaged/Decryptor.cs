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
        private static bool IngestFile(System.IO.FileInfo file, out HeaderInfo header, out byte[] ciphertext, out string ciphertextHash)
        {
            header = null;
            ciphertext = null;
            ciphertextHash = null;
            UTF8Encoding utf8 = new UTF8Encoding();
            FileStream fs = new FileStream(file.FullName, FileMode.Open);
            byte[] buffer = new byte[8];
            if (fs.Read(buffer, 0, buffer.Length) != buffer.Length)
                return false; // read error
            string thing = utf8.GetString(buffer);
            if (thing != "miniLock")
                return false; // not a miniLock file
            buffer = new byte[4];
            if (fs.Read(buffer, 0, buffer.Length) != buffer.Length)
                return false; // read failure
            // a header length of less than 634 is unexpected.  
            // This is the minimun lengh of a JSON header for a single-recipient miniLock file
            Int32 headerLength = 0;
            headerLength = (Int32)Utilities.BytesToUInt32(buffer, 0);
            if (headerLength < 630)
                return false; // header too short
            buffer = new byte[headerLength];
            if (fs.Read(buffer, 0, buffer.Length) != buffer.Length)
                return false; // read failure
            string rawHeader = utf8.GetString(buffer);
            if (!rawHeader.Contains("\"version\":1,"))
            {
                fs.Close();
                fs.Dispose();
                return false; // wrong version... not sure what to do with this, but there are no other versions yet
            }
            HeaderInfo h = HeaderInfo.FromJSON(rawHeader);
            byte[] ct = null;
            if (h != null)
            {
                //System.Diagnostics.Debug.Print("_H OBJECT=" + h.ToJSON());
                ct = new byte[file.Length - (headerLength + 12)];
                if (fs.Read(ct, 0, ct.Length) != ct.Length)
                {
                    fs.Close();
                    fs.Dispose();
                    return false; // read failure
                }
                fs.Close();
                fs.Dispose();
                header = h;
                ciphertext = ct;
                ciphertextHash = Blake2sCSharp.Blake2S.ComputeHash(ciphertext).ToBase64String();
                return true;
            }
            else
            {
                fs.Close();
                fs.Dispose();
                return false; // not a HeaderInfo JSON object (deserialization failed)
            }

        }

        private static bool TryDecryptHeader(HeaderInfo header, string ciphertextHash, miniLockManaged.Keys RecipientKeys, out FullHeader Result)
        {
            Result = new FullHeader();
            Result.UpdateFromHeader(header);
            UTF8Encoding utf8 = new UTF8Encoding();
            foreach (string n in header.decryptInfo.Keys) // n is outer nonce
            {
                //System.Diagnostics.Debug.Print("decryptInfo Nonce: " + k);  // DON'T LEAK!!!
                string v = header.decryptInfo[n]; //payload
                byte[] buffer = RecipientKeys.TryDecrypt(header.ephemeral, true, v.ToBytesFromBase64(), n.ToBytesFromBase64());
                if (buffer != null) // looks like we're a recipient!  proceed!  if not just move on to the next one
                {
                    string stuff = utf8.GetString(buffer);
                    CryptoBytes.Wipe(buffer);
                    InnerHeaderInfo ih = InnerHeaderInfo.FromJSON(stuff);
                    stuff = null;
                    if (ih != null)
                    {
                        //System.Diagnostics.Debug.Print("_IH OBJECT=" + ih.ToJSON());  // DON'T LEAK!!!
                        if (ih.recipientID != RecipientKeys.PublicID)
                        {
                            Result.Clear();
                            return false;
                        }
                        if (!miniLockManaged.Keys.ValidatePublicKey(ih.senderID))
                        {
                            Result.Clear();
                            return false;
                        }
                        Result.UpdateFromInnerHeader(ih);
                        buffer = ih.fileInfo.ToBytesFromBase64();
                        // use same nonce from OUTER
                        buffer = RecipientKeys.TryDecrypt(ih.senderID, buffer, n.ToBytesFromBase64());
                        if (buffer != null)
                        {
                            stuff = utf8.GetString(buffer);
                            CryptoBytes.Wipe(buffer);
                            FileInfo fi = FileInfo.FromJSON(stuff);
                            if (fi != null && fi.fileHash == ciphertextHash)
                            {
                                Result.UpdateFromFileInfo(fi);
                                //System.Diagnostics.Debug.Print("_FI OBJECT=" + fi.ToJSON()); // DON'T LEAK!!!
                                return true;
                            }
                        }
                    }
                }
            }
            // either not a recipient, or something else went wrong
            Result.Clear();
            return false;
        }

        public static DecryptedFile DecryptFile(System.IO.FileInfo TheFile, miniLockManaged.Keys RecipientKeys)
        {
            if (TheFile == null)
                throw new ArgumentNullException("TheFile");
            FullHeader fileStuff = new FullHeader();
            HeaderInfo h;
            byte[] buffer = null;
            string ctHash = null;

            if (!IngestFile(TheFile, out h, out buffer, out ctHash))
            {
                return null;
            }
            if (!TryDecryptHeader(h, ctHash, RecipientKeys, out fileStuff))
            {
                fileStuff.Clear();
                return null;
            }

            DecryptedFile results = new DecryptedFile();
            MemoryStream ms = new MemoryStream(); // decrypted file spit out here
            int cursor = 0;
            UInt64 chunkNumber = 0;
            byte[] chunkNonce = new byte[24]; // always a constant length
            Array.Copy(fileStuff.fileNonce, chunkNonce, fileStuff.fileNonce.Length); // copy it once and be done with it
            do
            {
                // how big is this chunk? (32bit number, little endien)
                UInt32 chunkLength = Utilities.BytesToUInt32(buffer, cursor);
                if (chunkLength > MAX_CHUNK_SIZE)
                {
                    //something went wrong!
                    fileStuff.Clear();
                    return null;
                }
                cursor += 4; // move past the chunk length
                //the XSalsa20Poly1305 process, for whatever reason, always expands the plaintext by 16 bytes
                // (authentication maybe?), so read the plaintext chunk length, add 16 bytes to the
                // value, then read that many bytes out of the ciphertext buffer
                byte[] chunk = new byte[chunkLength + 16];
                Array.Copy(buffer, cursor,
                           chunk, 0,
                           chunk.Length);
                cursor += chunk.Length; // move the cursor past this chunk
                if (cursor >= buffer.Length) // this is the last chunk
                {
                    // set most significant bit of nonce 
                    chunkNonce[23] |= 0x80;
                }
                byte[] decryptBytes = XSalsa20Poly1305.TryDecrypt(chunk,  fileStuff.fileKey, chunkNonce);
                if (decryptBytes == null)
                {
                    // nonce or key incorrect, or chunk has been altered (truncated?)
                    buffer = null;
                    fileStuff.Clear();
                    return null;
                }
                if (chunkNumber++ == 0) // first chunk is always filename '\0' padded
                {
                    results.StoredFilename = new UTF8Encoding().GetString(decryptBytes).Replace("\0", "").Trim();
                }
                else
                {
                    ms.Write(decryptBytes, 0, decryptBytes.Length);
                }
                // since the first chunkNonce is just the fileNonce and a bunch of 0x00's, 
                //  it's safe to do this as a post-process update
                Utilities.UInt64ToBytes(chunkNumber, chunkNonce, 16);
            } while (cursor < buffer.Length);
            results.Contents = ms.ToArray();
            results.SenderID = Keys.GetPublicIDFromKeyBytes(fileStuff.senderID);
            fileStuff.Clear(); // wipe the sensitive stuff!
            ms.Dispose();
            //produce a handy hash for use by the end-user (not part of the spec)
            results.PlainTextBlake2sHash =
                Blake2sCSharp.Blake2S.ComputeHash(results.Contents).ToBase64String();
            CryptoBytes.Wipe(buffer); 
            buffer = null;
            return results;
        }
    }
}

