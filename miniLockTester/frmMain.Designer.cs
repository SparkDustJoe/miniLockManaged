namespace miniLockTester
{
    partial class frmMain
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(frmMain));
            this.txtE = new System.Windows.Forms.TextBox();
            this.txtP = new System.Windows.Forms.TextBox();
            this.btnENCRYPT = new System.Windows.Forms.Button();
            this.lblID = new System.Windows.Forms.Label();
            this.lblTest = new System.Windows.Forms.Label();
            this.txtOutput = new System.Windows.Forms.TextBox();
            this.txtFilename = new System.Windows.Forms.TextBox();
            this.btnDECRYPT = new System.Windows.Forms.Button();
            this.btnLogIn = new System.Windows.Forms.Button();
            this.lblPassphraseBits = new System.Windows.Forms.Label();
            this.txtRecipients = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // txtE
            // 
            this.txtE.Location = new System.Drawing.Point(102, 12);
            this.txtE.Name = "txtE";
            this.txtE.Size = new System.Drawing.Size(303, 23);
            this.txtE.TabIndex = 0;
            // 
            // txtP
            // 
            this.txtP.Location = new System.Drawing.Point(102, 41);
            this.txtP.Name = "txtP";
            this.txtP.Size = new System.Drawing.Size(303, 23);
            this.txtP.TabIndex = 1;
            this.txtP.TextChanged += new System.EventHandler(this.txtP_TextChanged);
            // 
            // btnENCRYPT
            // 
            this.btnENCRYPT.Enabled = false;
            this.btnENCRYPT.Location = new System.Drawing.Point(15, 153);
            this.btnENCRYPT.Name = "btnENCRYPT";
            this.btnENCRYPT.Size = new System.Drawing.Size(140, 27);
            this.btnENCRYPT.TabIndex = 2;
            this.btnENCRYPT.Text = "ENCRYPT";
            this.btnENCRYPT.UseVisualStyleBackColor = true;
            this.btnENCRYPT.Click += new System.EventHandler(this.btnENCRYPT_Click);
            // 
            // lblID
            // 
            this.lblID.AutoSize = true;
            this.lblID.Location = new System.Drawing.Point(99, 67);
            this.lblID.Name = "lblID";
            this.lblID.Size = new System.Drawing.Size(98, 15);
            this.lblID.TabIndex = 3;
            this.lblID.Text = "not logged in";
            // 
            // lblTest
            // 
            this.lblTest.AutoSize = true;
            this.lblTest.Location = new System.Drawing.Point(99, 82);
            this.lblTest.Name = "lblTest";
            this.lblTest.Size = new System.Drawing.Size(49, 15);
            this.lblTest.TabIndex = 4;
            this.lblTest.Text = "label1";
            // 
            // txtOutput
            // 
            this.txtOutput.Location = new System.Drawing.Point(15, 282);
            this.txtOutput.Multiline = true;
            this.txtOutput.Name = "txtOutput";
            this.txtOutput.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.txtOutput.Size = new System.Drawing.Size(710, 228);
            this.txtOutput.TabIndex = 5;
            this.txtOutput.WordWrap = false;
            // 
            // txtFilename
            // 
            this.txtFilename.Location = new System.Drawing.Point(15, 121);
            this.txtFilename.Name = "txtFilename";
            this.txtFilename.Size = new System.Drawing.Size(569, 23);
            this.txtFilename.TabIndex = 6;
            // 
            // btnDECRYPT
            // 
            this.btnDECRYPT.Enabled = false;
            this.btnDECRYPT.Location = new System.Drawing.Point(170, 153);
            this.btnDECRYPT.Name = "btnDECRYPT";
            this.btnDECRYPT.Size = new System.Drawing.Size(140, 27);
            this.btnDECRYPT.TabIndex = 7;
            this.btnDECRYPT.Text = "DECRYPT";
            this.btnDECRYPT.UseVisualStyleBackColor = true;
            this.btnDECRYPT.Click += new System.EventHandler(this.btnDECRYPT_Click);
            // 
            // btnLogIn
            // 
            this.btnLogIn.Location = new System.Drawing.Point(411, 12);
            this.btnLogIn.Name = "btnLogIn";
            this.btnLogIn.Size = new System.Drawing.Size(75, 23);
            this.btnLogIn.TabIndex = 8;
            this.btnLogIn.Text = "\"LOGIN\"";
            this.btnLogIn.UseVisualStyleBackColor = true;
            this.btnLogIn.Click += new System.EventHandler(this.btnLogIn_Click);
            // 
            // lblPassphraseBits
            // 
            this.lblPassphraseBits.AutoSize = true;
            this.lblPassphraseBits.Location = new System.Drawing.Point(411, 44);
            this.lblPassphraseBits.Name = "lblPassphraseBits";
            this.lblPassphraseBits.Size = new System.Drawing.Size(42, 15);
            this.lblPassphraseBits.TabIndex = 9;
            this.lblPassphraseBits.Text = "Bits:";
            // 
            // txtRecipients
            // 
            this.txtRecipients.Location = new System.Drawing.Point(15, 209);
            this.txtRecipients.Multiline = true;
            this.txtRecipients.Name = "txtRecipients";
            this.txtRecipients.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtRecipients.Size = new System.Drawing.Size(453, 67);
            this.txtRecipients.TabIndex = 10;
            this.txtRecipients.WordWrap = false;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 191);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(336, 15);
            this.label1.TabIndex = 11;
            this.label1.Text = "Recipients: (each recipient on a separate line)";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(47, 16);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(49, 15);
            this.label2.TabIndex = 12;
            this.label2.Text = "EMail:";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(12, 44);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(84, 15);
            this.label3.TabIndex = 13;
            this.label3.Text = "Passphrase:";
            // 
            // frmMain
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(739, 522);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.txtRecipients);
            this.Controls.Add(this.lblPassphraseBits);
            this.Controls.Add(this.btnLogIn);
            this.Controls.Add(this.btnDECRYPT);
            this.Controls.Add(this.txtFilename);
            this.Controls.Add(this.txtOutput);
            this.Controls.Add(this.lblTest);
            this.Controls.Add(this.lblID);
            this.Controls.Add(this.btnENCRYPT);
            this.Controls.Add(this.txtP);
            this.Controls.Add(this.txtE);
            this.Font = new System.Drawing.Font("Consolas", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "frmMain";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "miniLockC#Tester";
            this.Load += new System.EventHandler(this.frmMain_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox txtE;
        private System.Windows.Forms.TextBox txtP;
        private System.Windows.Forms.Button btnENCRYPT;
        private System.Windows.Forms.Label lblID;
        private System.Windows.Forms.Label lblTest;
        private System.Windows.Forms.TextBox txtOutput;
        private System.Windows.Forms.TextBox txtFilename;
        private System.Windows.Forms.Button btnDECRYPT;
        private System.Windows.Forms.Button btnLogIn;
        private System.Windows.Forms.Label lblPassphraseBits;
        private System.Windows.Forms.TextBox txtRecipients;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label3;
    }
}

