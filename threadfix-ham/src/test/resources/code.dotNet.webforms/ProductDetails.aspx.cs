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
    public partial class ProductDetails : System.Web.UI.Page
    {

        private IDbProvider du = Settings.CurrentDbProvider;

        protected void Page_Load(object sender, EventArgs e)
        {
            lblMessage.Visible = false;
            txtEmail.Enabled = true;
            if (!Page.IsPostBack)
                LoadComments();

            //TODO: broken
            if (!Page.IsPostBack)
            {

                DataSet ds = du.GetCatalogData();
                ddlItems.DataSource = ds.Tables[0];
                ddlItems.DataTextField = "productName";
                ddlItems.DataValueField = "productCode";
                ddlItems.DataBind();
            }
        }

        protected void btnSave_Click(object sender, EventArgs e)
        {
            try
            {
                string error_message = du.AddComment(hiddenFieldProductID.Value, txtEmail.Text, txtComment.Text);
                txtComment.Text = error_message;
                lblMessage.Visible = true;
                LoadComments();
            }
            catch(Exception ex)
            {
                lblMessage.Text = ex.Message;
                lblMessage.Visible = true;
            }
        }

        void LoadComments()
        {
            string id = Request["productNumber"];
            if (id == null) id = "S18_2795"; //this month's special
            DataSet ds = du.GetProductDetails(id);
            string output = string.Empty;
            string comments = string.Empty;
            foreach (DataRow prodRow in ds.Tables["products"].Rows)
            {
                output += "<div class='product2' align='center'>";
                output += "<img src='./images/products/" + prodRow["productImage"] + "'/><br/>";
                output += "<strong>" + prodRow["productName"].ToString() + "</strong><br/>";
                output += "<hr/>" + prodRow["productDescription"].ToString() + "<br/>";
                output += "</div>";

                hiddenFieldProductID.Value = prodRow["productCode"].ToString();

                DataRow[] childrows = prodRow.GetChildRows("prod_comments");
                if (childrows.Length > 0)
                    comments += "<h2 class='title-regular-2'>Comments:</h2>";

                foreach (DataRow commentRow in childrows)
                {
                    comments += "<strong>Email:</strong>" + commentRow["email"] + "<span style='font-size: x-small;color: #E47911;'> (Email Address Verified!) </span><br/>";
                    comments += "<strong>Comment:</strong><br/>" + commentRow["comment"] + "<br/><hr/>";
                }

            }

            lblOutput.Text = output;
            lblComments.Text = comments;


            //Fill in the email address of authenticated users
            if (Request.Cookies["customerNumber"] != null)
            {
                string customerNumber = Request.Cookies["customerNumber"].Value;

                string email = du.GetCustomerEmail(customerNumber);
                txtEmail.Text = email;
                txtEmail.ReadOnly = true;
            }
        }

        protected void ddlItems_SelectedIndexChanged(object sender, EventArgs e)
        {
            Response.Redirect("ProductDetails.aspx?productNumber=" + ddlItems.SelectedItem.Value);
        }

        protected void Button1_Click(object sender, EventArgs e)
        {
            Response.Redirect("ProductDetails.aspx?productNumber=" + ddlItems.SelectedItem.Value);
        }

    }
}