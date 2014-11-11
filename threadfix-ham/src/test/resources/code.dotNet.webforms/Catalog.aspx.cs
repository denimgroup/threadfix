using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Data;
using OWASP.WebGoat.NET.App_Code.DB;
using OWASP.WebGoat.NET.App_Code;

namespace OWASP.WebGoat.NET.WebGoatCoins
{
    public partial class Catalog : System.Web.UI.Page
    {
        private IDbProvider du = Settings.CurrentDbProvider;

        protected void Page_Load(object sender, EventArgs e)
        {
            DataSet ds = du.GetProductsAndCategories();

            foreach (DataRow catRow in ds.Tables["categories"].Rows)
            {
                lblOutput.Text += "<p/><h2 class='title-regular-2 clearfix'>Category: " + catRow["catName"].ToString() + "</h2><hr/><p/>\n";
                foreach (DataRow prodRow in catRow.GetChildRows("cat_prods"))
                {
                    lblOutput.Text += "<div class='product' align='center'>\n";
                    lblOutput.Text += "<img src='./images/products/" + prodRow[3] + "'/><br/>\n";
                    lblOutput.Text += "" + prodRow[1] + "<br/>\n";
                    lblOutput.Text += "<a href=\"ProductDetails.aspx?productNumber=" + prodRow[0].ToString() + "\"><br/>\n";
                    lblOutput.Text += "<img src=\"../resources/images/moreinfo1.png\" onmouseover=\"this.src='../resources/images/moreinfo2.png';\" onmouseout=\"this.src='../resources/images/moreinfo1.png';\" />\n";
                    lblOutput.Text += "</a>\n";
                    lblOutput.Text += "</div>\n";
                }
            }

        }
    }
}