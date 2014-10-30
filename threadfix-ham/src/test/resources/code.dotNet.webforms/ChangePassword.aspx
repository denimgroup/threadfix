<%@ Page Title="" Language="C#" MasterPageFile="~/Resources/Master-Pages/Site.Master" AutoEventWireup="true" CodeBehind="ChangePassword.aspx.cs" Inherits="OWASP.WebGoat.NET.WebGoatCoins.ChangePassword" %>
<asp:Content ID="Content1" ContentPlaceHolderID="HeadContentPlaceHolder" runat="server">
</asp:Content>
<asp:Content ID="Content2" ContentPlaceHolderID="HelpContentPlaceholder" runat="server">
</asp:Content>
<asp:Content ID="Content3" ContentPlaceHolderID="BodyContentPlaceholder" runat="server">


    <h1 class="title-regular-4 clearfix">Change Password</h1>
    <div class="notice">
    <asp:Literal runat="server" EnableViewState="False" ID="labelMessage">Change your password frequently to ensure your account is secure!</asp:Literal>
    </div>
    <p class="inline">
        <label for="name">Enter Password: </label>
        <br />
        <asp:TextBox ID="txtPassword1" runat="server" class="text" TextMode="Password"></asp:TextBox>
        <br />
        <label for="password">Re-Enter Password: </label><br />
        <asp:TextBox ID="txtPassword2" runat="server" class="text" TextMode="Password"></asp:TextBox>
        <p />
        <asp:Button ID="ButtonChangePassword" SkinID="Button" runat="server" Text="Change Password" OnClick="ButtonChangePassword_Click" />
    </p>

</asp:Content>
