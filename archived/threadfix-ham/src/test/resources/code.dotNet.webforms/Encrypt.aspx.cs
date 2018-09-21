using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Security.Cryptography;
using System.Drawing;
using OWASP.WebGoat.NET.App_Code;
using System.Text;

namespace OWASP.WebGoat.NET
{
    public partial class EncryptVSEncode : System.Web.UI.Page
    {
        public string Password { get; set; }

        protected void btnGO_Click(object sender, EventArgs e)
        {
            //url encoded
            //base64
            //sha1
            //encryption with password

            string secret = txtString.Text;
            string key = String.IsNullOrEmpty(txtPassword.Text) ? hardCodedKey : txtPassword.Text;

            Table t = new Table();
            t.Width = new Unit("100%");

            t.Rows.Add(MakeRow("Custom Crypto", CustomCryptoEncrypt(secret)));
            t.Rows.Add(MakeRow("URL Encoded:", Server.UrlEncode(secret)));
            t.Rows.Add(MakeRow("Base64 Encoded:", Base64(secret)));
            t.Rows.Add(MakeRow("SHA1 Hashed:", SHA(secret, WG_Hash.Sha1)));
            t.Rows.Add(MakeRow("SHA256 Hashed:", SHA(secret, WG_Hash.Sha256)));
            t.Rows.Add(MakeRow("Rijndael Encrypted: ", Encypt(secret, key), Color.LightGreen));

            ContentPlaceHolder cph = (ContentPlaceHolder)this.Master.FindControl("BodyContentPlaceholder");
            cph.Controls.Add(new LiteralControl("<p/>"));
            cph.Controls.Add(t);


        }

        private string SHA(string s, WG_Hash hash)
        {
            byte[] bytes = System.Text.ASCIIEncoding.ASCII.GetBytes(s);
            byte[] result;
            HashAlgorithm sha = null;

            switch (hash)
            {
                case WG_Hash.Sha1:
                    sha = new SHA1Managed();
                    break;
                case WG_Hash.Sha256:
                    sha = new SHA256Managed();
                    break;
            }
            result = sha.ComputeHash(bytes);
            return System.Convert.ToBase64String(result);
        }
    }
}