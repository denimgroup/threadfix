<%@ Page Title="" Language="C#" ValidateRequest="false" MasterPageFile="~/Resources/Master-Pages/Site.Master" AutoEventWireup="true" CodeBehind="ProductDetails.aspx.cs" Inherits="OWASP.WebGoat.NET.WebGoatCoins.ProductDetails" %>
<asp:Content ID="Content1" ContentPlaceHolderID="HeadContentPlaceHolder" runat="server">
</asp:Content>
<asp:Content ID="Content2" ContentPlaceHolderID="HelpContentPlaceholder" runat="server">
</asp:Content>
<asp:Content ID="Content3" ContentPlaceHolderID="BodyContentPlaceholder" runat="server">

<script language="javascript" type="text/javascript">
        $(document).ready(function () {
            $("div.success").hide();
            setTimeout(function () {
                $("div.success").fadeIn("slow", function () {
                    $("div.success").show();
                });
            }, 500);
        });
 </script>

    <h1 class="title-regular-4 clearfix">Details for <%=(Request["productNumber"] == null ? "This Month's Special" : "Product #" + Request["productNumber"].ToString()) %></h1>
        <div class="notice">
        <asp:Literal runat="server" EnableViewState="False" ID="labelMessage">
        Here are the details we have in our database for this item!
        </asp:Literal>
    </div>
    View a different item:<br />
    <asp:DropDownList ID="ddlItems" runat="server"
        onselectedindexchanged="ddlItems_SelectedIndexChanged"
        CausesValidation="True" AutoPostBack="True">
</asp:DropDownList>


    <br />
    <asp:Button ID="Button1" runat="server" onclick="Button1_Click" Text="Go!" PostBackUrl="~/WebGoatCoins/ProductDetails.aspx"/>
    <br />


    <asp:Label ID="lblOutput" runat="server" Text=""></asp:Label>

    <asp:Label ID="lblMessage" runat="server">
    <div class="success">
    Comment Successfully Added!
    </div>
    </asp:Label>

    <asp:Label ID="lblComments" runat="server"></asp:Label>

    <h2 class='title-regular-2'>Leave a Comment</h2>




    <p>
        <asp:Table ID="Table1" runat="server" Width="100%">

            <asp:TableRow runat="server">
                <asp:TableCell runat="server" Width="10%">Email: </asp:TableCell>
                <asp:TableCell runat="server">
                    <asp:TextBox ID="txtEmail" runat="server" width="100%" CssClass="text"></asp:TextBox>

</asp:TableCell>
            </asp:TableRow>

            <asp:TableRow runat="server">
                <asp:TableCell runat="server" Width="10%" VerticalAlign="Top" style="vertical-align:middle">
                    Comment:
                </asp:TableCell>
                <asp:TableCell runat="server">
                    <asp:TextBox ID="txtComment" runat="server" width="100%" Rows="5" TextMode="MultiLine" CssClass="text">
                </asp:TextBox>
</asp:TableCell>
            </asp:TableRow>

            <asp:TableRow runat="server">
                <asp:TableCell runat="server">&nbsp;</asp:TableCell>
                <asp:TableCell runat="server">
                    <asp:Button ID="btnSave" runat="server" Text="Save Comment" onclick="btnSave_Click" />
                </asp:TableCell>
            </asp:TableRow>

        </asp:Table>
    </p>

    <p />
    <a href="Catalog.aspx">Return to Entire Catalog</a>
    <p />
        <asp:HiddenField ID="hiddenFieldProductID" runat="server" />

</asp:Content>
