using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace miniLockTester
{
    public partial class frmMain : Form
    {
        const string TESTER1_E = "miliLock+test1@mailinator.com";
        const string TESTER1_P = "o8rS%kA33qHCh^mbbXn6d$eoq9dbAvZc";
        const string TESTER1_ID = "6ZLq23QX4NabaoF2VjXwcVY6gTtNPN6rss4duLs6pEqbb";
        const string TESTER2_E = "miliLock+test2@mailinator.com";
        const string TESTER2_P = "3B8x@3kySN@7ZrgET6m^5$GFX8NK8QR2";
        const string TESTER2_ID = "quBBtPHTtbutjz2NjibrjeWESMkYogrAx2v4eavyGSUAE";
        const string TESTER3_E = "miliLock+test3@mailinator.com";
        const string TESTER3_P = "BMV4PDemP#7&3K3j2H5GdxAntfWLJ^BL";
        const string TESTER3_ID = "26SwJcskBMuCCQSkc3T4RaQctLY3mze7THhi53cRc1vnXX";
        const string TESTER4_E = "miliLock+test4@mailinator.com";
        const string TESTER4_P = "3t2d29B7WJuQVAYpuRXwe9GwFui9FR4z";
        const string TESTER4_ID = "QE8bF6kyXtvghELSD7gZLXgLbZRGaXqCwvMwSgoMizywM";

        string SOURCE_PATH = System.Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        miniLockManaged.Keys keyPair = null; 

        public frmMain()
        {
            InitializeComponent();
        }

        private void frmMain_Load(object sender, EventArgs e)
        {
            txtE.Text = TESTER1_E;
            txtP.Text = TESTER1_P;
            lblTest.Text = "Tester 1's Public ID: " + TESTER1_ID;
            txtFilename.Text = SOURCE_PATH + "\\CopyRightAndLicenseStatements.txt";
            if (!System.IO.File.Exists(txtFilename.Text))
            {
                System.IO.File.WriteAllText(txtFilename.Text, miniLockManaged.Utilities.CopyRightAndLicenseStatements());
            }
            txtRecipients.Text = TESTER1_ID + "\r\n" + TESTER2_ID + "\r\n" + TESTER3_ID;
        }

        private void btnENCRYPT_Click(object sender, EventArgs e)
        {
            this.Enabled = false;
            //encrypt=======================================================================================================
            lblID.Text = keyPair.PublicID;

            string[] Rs = txtRecipients.Text.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
            byte[] theFile = miniLockManaged.FileOperations.EncryptFile(
                new System.IO.FileInfo(txtFilename.Text), Rs, keyPair);
            System.IO.FileStream fs = System.IO.File.Create(txtFilename.Text + ".minilock");
            fs.Write(theFile, 0, theFile.Length);
            fs.Flush(true);
            fs.Close();
            fs.Dispose();
            //end encrypt=========================================================================================================== 
            txtOutput.Text = "ENCRYPTED FILE: " + txtFilename.Text + ".minilock";
            this.Enabled = true;
        }

        private void btnDECRYPT_Click(object sender, EventArgs e)
        {
            this.Enabled = false;
             //decrypt=========================================================================================================== 
 
            miniLockManaged.FileOperations.DecryptedFile F = miniLockManaged.FileOperations.DecryptFile(
                new System.IO.FileInfo(txtFilename.Text.Replace(".minilock", "") + ".minilock"), keyPair);
            if (F != null)
            {
                txtOutput.Text = "Encrypted by: " + F.SenderID + "\r\n" +
                    F.StoredFilename + "\r\n" +
                    "Plaintext Blake2s HASH=" + F.PlainTextBlake2sHash + "\r\n"
                    + new UTF8Encoding().GetString(F.Contents);
            }
            else
                txtOutput.Text = "[null]";
            //*/
            //end decrypt=========================================================================================================== 
            this.Enabled = true;
        }

        private void btnLogIn_Click(object sender, EventArgs e)
        {
            this.Enabled = false;
            if (keyPair == null)
            {
                keyPair = new miniLockManaged.Keys();
                if (!keyPair.Initialize(txtE.Text, txtP.Text))
                {
                    txtOutput.Text = "!!!PASSPHRASE REJECTED!!!";
                    this.Enabled = true;
                    return;
                }
                else
                {
                    lblID.Text = "Your Public miniLock ID: " + keyPair.PublicID;
                    btnDECRYPT.Enabled = true;
                    btnENCRYPT.Enabled = true;
                }
            }
            this.Enabled = true;
        }

        private void txtP_TextChanged(object sender, EventArgs e)
        {
            lblPassphraseBits.Text = 
                "Bits: " + 
                miniLockManaged.Keys.ScorePotentialPassphrase(txtP.Text).Entropy.ToString();
        }

    }
}
