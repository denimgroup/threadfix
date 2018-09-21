<%@ Page validateRequest="false" Language="C#" AutoEventWireup="true" CodeBehind="WebForm1.aspx.cs" Inherits="JSASPNETUserConsent.WebForm1" %>
<%@ Register Assembly="AjaxControlToolkit" Namespace="AjaxControlToolkit" TagPrefix="asp" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title></title>
    <script type="text/javascript" src="http://ajax.aspnetcdn.com/ajax/jquery/jquery-1.4.4.js"></script>  
    <script type="text/javascript" src="http://ajax.aspnetcdn.com/ajax/jquery.ui/1.8.7/jquery-ui.js"></script>
    <link type="text/css" rel="Stylesheet" href="http://ajax.aspnetcdn.com/ajax/jquery.ui/1.8.7/themes/redmond/jquery-ui.css" /> 
</head>
<body>
    <form id="form1" runat="server">
    <div>
        <asp:ToolkitScriptManager ID="ToolkitScriptManager1" runat="server">
        </asp:ToolkitScriptManager>
        <asp:DropDownList ID="ddl" runat="server">
            <asp:ListItem>Item 1</asp:ListItem>
            <asp:ListItem>Item 2</asp:ListItem>
            <asp:ListItem>Item 3</asp:ListItem>
        </asp:DropDownList>

        <asp:Label ID="Label" runat="server" Text="Initial Text">

        </asp:Label>

        <asp:TextBox ID="newitem" runat="server"></asp:TextBox>

        <asp:Button ID="byconfirm" runat="server" Text="Add by javascript's confirm()" onclientclick="return confirmation();"/>
        <asp:Button ID="bymodalpopup" runat="server" Text="Add by ModalPopupExtender" />
        <asp:Button ID="byjquery" runat="server" Text="Add by jQuery UI's Dialog" onclientclick="return jquerydialog()"/>
        <asp:Button ID="test" runat="server" Text="Set Value 1 to Value 2" onclick="test_Click"/>
        
        <asp:Panel ID="popup" runat="server" style="border: 1px #ccc solid; padding: 10px;">
            <p>Add new item to the DropDownList?</p>
            <asp:Button ID="ok" runat="server" Text="OK" />
            <asp:Button ID="cancel" runat="server" Text="Cancel" />
        </asp:Panel>
            
        <asp:ModalPopupExtender ID="ModalPopupExtender1" runat="server"
            TargetControlID="bymodalpopup"
            PopupControlID="popup"
            OkControlID="ok"
            CancelControlID="cancel"
            OnOkScript="add_top()">
        </asp:ModalPopupExtender>
        
        <script type="text/javascript">
            function confirmation() {

                if (confirm('Add new item to the DropDownList?')) {
                    add_top();
                }

                return false;
            }

            function add_top() {
                var item = document.getElementById('newitem').value;

                if (!item) {
                    alert("New item must not be empty.");
                    return false;
                }

                var ddl = document.getElementById('ddl');
                var option = document.createElement('option');

                option.text = option.value = item;
                ddl.add(option, ddl.options[0] /* IE 7 & below, 0 */);
                ddl.selectedIndex = 0;
            }

            function jquerydialog() {
                $('<div>Add new item to DropDownList?</div>').dialog({
                    buttons: {

                        "OK": function () {
                            add_top();
                            $(this).dialog("close");
                        },

                        "Cancel": function () {
                            $(this).dialog("close");
                        }
                    }
                });
                return false;
            }
        </script>
    </div>
    </form>
</body>
</html>
