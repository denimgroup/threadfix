using System;
using System.Collections;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;

namespace OWASP.WebGoat.NET
{
	public partial class AddNewUser : System.Web.UI.Page
	{
		const string passwordQuestion = "What is your favorite color";

	    protected void Page_Load(object sender, EventArgs e)
	    {
	        if (!Page.IsPostBack)
	            SecurityQuestion.Text = passwordQuestion;
	    }

	    protected void CreateAccountButton_Click(object sender, EventArgs e)
	    {
	        MembershipCreateStatus createStatus;

	        MembershipUser newUser =
	             Membership.CreateUser(Username.Text, Password.Text,
	                                   Email.Text, passwordQuestion,
	                                   SecurityAnswer.Text, true,
	                                   out createStatus);

			if(newUser == null)
				Console.WriteLine("New User is null!");

	        switch (createStatus)
	        {
	            case MembershipCreateStatus.Success:
	                CreateAccountResults.Text = "The user account was successfully created!";
	                break;

	            case MembershipCreateStatus.DuplicateUserName:
	                CreateAccountResults.Text = "There already exists a user with this username.";
	                break;

	            case MembershipCreateStatus.DuplicateEmail:
	                CreateAccountResults.Text = "There already exists a user with this email address.";
	                break;

	            case MembershipCreateStatus.InvalidEmail:
	                CreateAccountResults.Text = "There email address you provided in invalid.";
	                break;

	            case MembershipCreateStatus.InvalidAnswer:
	                CreateAccountResults.Text = "There security answer was invalid.";
	                break;

	            case MembershipCreateStatus.InvalidPassword:
	                CreateAccountResults.Text = "The password you provided is invalid. It must be seven characters long and have at least one non-alphanumeric character.";
	                break;

	            default:
	                CreateAccountResults.Text = "There was an unknown error; the user account was NOT created.";
	                break;
	        }
	    }

	    protected void RegisterUser_CreatingUser(object sender, LoginCancelEventArgs e)
	    {
	    	/*
	        string trimmedUserName = RegisterUser.UserName.Trim();
	        if (RegisterUser.UserName.Length != trimmedUserName.Length)
	        {
	            // Show the error message
	            InvalidUserNameOrPasswordMessage.Text = "The username cannot contain leading or trailing spaces.";
	            InvalidUserNameOrPasswordMessage.Visible = true;

	            // Cancel the create user workflow
	            e.Cancel = true;
	        }
	        else
	        {
	            // Username is valid, make sure that the password does not contain the username
	            if (RegisterUser.Password.IndexOf(RegisterUser.UserName, StringComparison.OrdinalIgnoreCase) >= 0)
	            {
	                // Show the error message
	                InvalidUserNameOrPasswordMessage.Text = "The username may not appear anywhere in the password.";
	                InvalidUserNameOrPasswordMessage.Visible = true;

	                // Cancel the create user workflow
	                e.Cancel = true;
	            }
	        }
	        */
		}
	}
}

