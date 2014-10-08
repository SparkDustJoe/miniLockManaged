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
        /// <summary>
        /// Ingest only the header from the miniLock file to determine if the file is in fact
        /// a miniLock file, and to scoop up the header JSON object for later decryption.
        /// This does NOT scoop up the ciphertext
        /// </summary>
        /// <param name="file">an already open filestream of the file to be decrypted</param>
        /// <param name="header">output: the scooped-up header object</param>
        /// <returns>the length in bytes of the read raw header (not including the "magic bytes"
        /// or the raw header length bytes themselves), or -1 on error</returns>
        private static int IngestHeader(ref FileStream file, out HeaderInfo header)
        {
            header = null;
            UTF8Encoding utf8 = new UTF8Encoding();
            file.Position = 0; // this will throw an error if the filestream is not random access
            byte[] buffer = new byte[8];
            if (file.Read(buffer, 0, buffer.Length) != buffer.Length)
                return -1; // read error
            string thing = utf8.GetString(buffer);
            if (thing != "miniLock")
                return -1; // not a miniLock file
            buffer = new byte[4];
            if (file.Read(buffer, 0, buffer.Length) != buffer.Length)
                return -1; // read failure
            // a header length of less than 634 is unexpected.  
            // This is the minimun lengh of a JSON header for a single-recipient miniLock file
            Int32 headerLength = 0;
            headerLength = (Int32)Utilities.BytesToUInt32(buffer, 0);
            if (headerLength < 630)
                return -1; // header too short
            buffer = new byte[headerLength];
            if (file.Read(buffer, 0, buffer.Length) != buffer.Length)
                return -1; // read failure
            string rawHeader = utf8.GetString(buffer);
            if (!rawHeader.Contains("\"version\":1,"))
            {
                file.Close();
                file.Dispose();
                return -1; // wrong version... not sure what to do with this, but there are no other versions yet
            }
            HeaderInfo h = HeaderInfo.FromJSON(rawHeader);
            if (h != null)
            {
                header = h;
                return headerLength;
            }
            else
            {
                file.Close();
                file.Dispose();
                return -1; // not a HeaderInfo JSON object (deserialization failed)
            }

        }

        /// <summary>
        /// Ingest the header and read the ciphertext in one shot.  Note: potentially memory intensive
        /// </summary>
        /// <param name="file">a System.IO.FileInfo object point to the source file to be decrypted</param>
        /// <param name="header">output: the scooped up header object</param>
        /// <param name="ciphertext">output: the ciphertext</param>
        /// <param name="ciphertextHash">output: the ciphertext hash in Base64 notation</param>
        /// <returns>true if header ok and other objects ingested, false on any error</returns>
        private static bool IngestFile(ref FileStream file, out HeaderInfo header, out byte[] ciphertext, out string ciphertextHash)
        {
            header = null;
            ciphertext = null;
            ciphertextHash = null;
            UTF8Encoding utf8 = new UTF8Encoding();
            int headerLength = IngestHeader(ref file, out header);
            if (headerLength < 0)
            {
                file.Close();
                file.Dispose();
                return false;
            }
            //System.Diagnostics.Debug.Print("_H OBJECT=" + h.ToJSON()); // DON'T LEAK!!!
            byte[] ct = new byte[file.Length - (headerLength + 12)];
            if (file.Read(ct, 0, ct.Length) != ct.Length)
            {
                file.Close();
                file.Dispose();
                return false; // read failure
            }
            file.Close();
            file.Dispose();
            ciphertext = ct;
            ciphertextHash = Blake2sCSharp.Blake2S.ComputeHash(ciphertext).ToBase64String();
            return true;
        }

        /// <summary>
        /// Attempts to find an Inner Header and File Info object using the supplied decryption Keys.
        /// If the decryption keys do not decrypt the header, then they were not listed as a recipient.
        /// </summary>
        /// <param name="header">the ingested header object from the file</param>
        /// <param name="RecipientKeys">the Keys object with the key pair to attempt for decryption</param>
        /// <param name="Result">output: a FullHeader object with the fully decrypted file header details</param>
        /// <returns>false on any error, including (but not limited to): bad ciphertext, not a recipient</returns>
        private static bool TryDecryptHeader(HeaderInfo header, miniLockManaged.Keys RecipientKeys, out FullHeader Result)
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
                    buffer.Wipe();
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
                            buffer.Wipe();
                            FileInfo fi = FileInfo.FromJSON(stuff);
                            if (fi != null)
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

        /// <summary>
        /// Decrypt a miniLock file using the specified Keys
        /// </summary>
        /// <param name="TheFile"></param>
        /// <param name="RecipientKeys"></param>
        /// <returns>null on any error, or a DecryptedFile object with the raw file contents, a plaintext hash,
        /// the SenderID, and the stored filename</returns>
        public static DecryptedFileDetails DecryptFile(FileStream SourceFile, string DestinationFileFullPath, bool OverWriteDestination, miniLockManaged.Keys RecipientKeys)
        {
            if (SourceFile == null)
                throw new ArgumentNullException("SourceFile");
            if (DestinationFileFullPath == null)
                throw new ArgumentNullException("DestinationFile");
            if (!SourceFile.CanRead)
                throw new InvalidOperationException("Source File not readable!");
            if (System.IO.File.Exists(DestinationFileFullPath) && !OverWriteDestination)
            {
                // be fault tolerant
                System.IO.FileInfo existing = new System.IO.FileInfo(DestinationFileFullPath);
                string newFilename = DestinationFileFullPath;
                int counter = 1;
                do
                {
                    newFilename = DestinationFileFullPath.Replace(existing.Extension, "");
                    newFilename += '(' + counter++.ToString() + ')' + existing.Extension;
                } while (File.Exists(newFilename));
                DestinationFileFullPath = newFilename;
                // this is not fault tolerant
                //throw new InvalidOperationException("Destination File already exists!  Set OverWriteDestination true or choose a different filename.");
            }

            FullHeader fileStuff = new FullHeader();
            HeaderInfo h;
            byte[] buffer = null;

            // after this call, the source file pointer should be positioned to the end of the header
            int hLen = IngestHeader(ref SourceFile, out h);  
            if (hLen < 0)
            {
                SourceFile.Close();
                SourceFile.Dispose();
                return null;
            }
            hLen += 12; // the 8 magic bytes and the 4 header length bytes and the length of the JSON header object
            long theCliff = SourceFile.Length - hLen; // this is the ADJUSTED point where the file cursor falls off the cliff
            if (!TryDecryptHeader(h, RecipientKeys, out fileStuff)) // ciphertext hash is compared later
            {
                fileStuff.Clear();
                SourceFile.Close();
                SourceFile.Dispose();
                return null;
            }

            Blake2sCSharp.Hasher b2sPlain = Blake2sCSharp.Blake2S.Create();  // a nice-to-have for the user
            Blake2sCSharp.Hasher b2sCipher = Blake2sCSharp.Blake2S.Create(); // a check to make sure the ciphertext wasn't altered
            //note:  in theory, if the ciphertext doesn't decrypt at any point, there is likely something wrong with it up to and
            //  including truncation/extension
            //  BUT the hash is included in the header, and should be checked.

            DecryptedFileDetails results = new DecryptedFileDetails();
            results.ActualDecryptedFilePath = DestinationFileFullPath; // if the filename got changed, it happened before this point
            string tempFile = null; // save the filename of the temp file so that the temp directory created with it is also killed
            System.IO.FileStream tempFS = GetTempFileStream(out tempFile);

            int cursor = 0;
            UInt64 chunkNumber = 0;
            byte[] chunkNonce = new byte[24]; // always a constant length
            Array.Copy(fileStuff.fileNonce, chunkNonce, fileStuff.fileNonce.Length); // copy it once and be done with it
            do
            {
                // how big is this chunk? (32bit number, little endien)
                buffer = new byte[4];
                if (SourceFile.Read(buffer, 0, buffer.Length) != buffer.Length)
                {
                    //read error
                    fileStuff.Clear();
                    SourceFile.Close();
                    SourceFile.Dispose();
                    TrashTempFileStream(tempFS, tempFile);
                    return null;
                }
                b2sCipher.Update(buffer);  // have to include ALL the bytes, even the chunk-length bytes
                UInt32 chunkLength = Utilities.BytesToUInt32(buffer);
                if (chunkLength > MAX_CHUNK_SIZE)
                {
                    //something went wrong!
                    fileStuff.Clear();
                    SourceFile.Close();
                    SourceFile.Dispose();
                    TrashTempFileStream(tempFS, tempFile);
                    return null;
                }
                cursor += 4; // move past the chunk length

                //the XSalsa20Poly1305 process, ALWAYS expands the plaintext by MacSizeInBytes
                // (authentication), so read the plaintext chunk length, add those bytes to the
                // value, then read that many bytes out of the ciphertext buffer
                byte[] chunk = new byte[chunkLength + XSalsa20Poly1305.MacSizeInBytes];
                //Array.Copy(buffer, cursor,
                //           chunk, 0,
                //           chunk.Length);
                if (SourceFile.Read(chunk, 0, chunk.Length) != chunk.Length)
                {
                    //read error
                    fileStuff.Clear();
                    SourceFile.Close();
                    SourceFile.Dispose();
                    TrashTempFileStream(tempFS, tempFile);
                    return null;
                }
                b2sCipher.Update(chunk); // get hash of cipher text to compare to stored File Info Object
                cursor += chunk.Length; // move the cursor past this chunk
                if (cursor >= theCliff) // this is the last chunk
                {
                    // set most significant bit of nonce 
                    chunkNonce[23] |= 0x80;
                }
                byte[] decryptBytes = XSalsa20Poly1305.TryDecrypt(chunk, fileStuff.fileKey, chunkNonce);
                if (decryptBytes == null)
                {
                    // nonce or key incorrect, or chunk has been altered (truncated?)
                    buffer = null;
                    fileStuff.Clear();
                    SourceFile.Close();
                    SourceFile.Dispose();
                    TrashTempFileStream(tempFS, tempFile);
                    return null;
                }
                if (chunkNumber == 0) // first chunk is always filename '\0' padded
                {
                    results.StoredFilename = new UTF8Encoding().GetString(decryptBytes).Replace("\0", "").Trim();
                }
                else
                {
                    b2sPlain.Update(decryptBytes); // give the user a nice PlainText hash
                    tempFS.Write(decryptBytes, 0, decryptBytes.Length); // start building the output file
                }
                decryptBytes.Wipe(); // DON'T LEAK!!!
                // since the first chunkNonce is just the fileNonce and a bunch of 0x00's, 
                //  it's safe to do the chunk number update as a post-process operation
                Utilities.UInt64ToBytes(++chunkNumber, chunkNonce, 16);
            } while (cursor < theCliff);
            SourceFile.Close();
            SourceFile.Dispose();
            byte[] ctActualHash = b2sCipher.Finish();
            if (!CryptoBytes.ConstantTimeEquals(ctActualHash, fileStuff.ciphertextHash))
            {
                // ciphertext was altered
                TrashTempFileStream(tempFS, tempFile);
                return null;
            }
            results.SenderID = Keys.GetPublicIDFromKeyBytes(fileStuff.senderID);
            fileStuff.Clear(); // wipe the sensitive stuff!
            tempFS.Flush();
            tempFS.Close();
            tempFS.Dispose();
            //produce a handy hash for use by the end-user (not part of the spec)
            results.PlainTextBlake2sHash = b2sPlain.Finish().ToBase64String();

            System.IO.File.Move(tempFile, DestinationFileFullPath);
            // WARNING:  only use if the method that created the temp file also created a random subdir!
            Directory.Delete(new System.IO.FileInfo(tempFile).DirectoryName, true); // this is done since we didn't use TrashTempfileStream

            return results;
        }
    }
}

