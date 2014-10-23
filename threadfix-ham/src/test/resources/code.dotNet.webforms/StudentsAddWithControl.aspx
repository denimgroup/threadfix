<%@ Page Title="" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="StudentsAdd.aspx.cs" Inherits="ContosoUniversity.StudentsAdd" %>
<%@ Register TagPrefix="custom" TagName="WebUserControl1" Src="~/WebUserControl1.ascx" %>
<asp:Content ID="Content1" ContentPlaceHolderID="HeadContent" runat="server">
</asp:Content>
<asp:Content ID="Content2" ContentPlaceHolderID="MainContent" runat="server" ClientIDMode="Predictable">
    <h2>Add New Students 2</h2>
    <asp:EntityDataSource ID="StudentsEntityDataSource" runat="server"
        ContextTypeName="ContosoUniversity.DAL.SchoolEntities" EnableFlattening="False"
        EntitySetName="People" EntityTypeFilter="Student"
        EnableInsert="True" >
    </asp:EntityDataSource>
    <asp:DetailsView runat="server"
        DataSourceID="StudentsEntityDataSource" AutoGenerateRows="False"
        DefaultMode="Insert">
        <Fields>
            <asp:BoundField DataField="FirstMidName" HeaderText="First Name"
                SortExpression="FirstMidName"  />
            <asp:BoundField DataField="FirstMidName2" HeaderText="Test Name"
                SortExpression="FirstMidName"  />
            <asp:BoundField DataField="LastName" HeaderText="Last Name"
                SortExpression="LastName" />
            <asp:BoundField DataField="EnrollmentDate" HeaderText="Enrollment Date"
                SortExpression="EnrollmentDate" />
            <asp:CommandField ShowInsertButton="True" />
      </Fields>
    </asp:DetailsView>
    <custom:WebUserControl1 ID="WebUserControl1" runat="server"/>

</asp:Content>