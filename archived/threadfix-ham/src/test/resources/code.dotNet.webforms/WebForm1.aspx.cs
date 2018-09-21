using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace JSASPNETUserConsent
{
    public partial class WebForm1 : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            Label.Text = "Initial text";
            Response.AddHeader("X-XSS-Protection", "0");
        }

        protected void test_Click(object sender, EventArgs e)
        {
            Label.Text = newitem.Text;
        }
    }
}