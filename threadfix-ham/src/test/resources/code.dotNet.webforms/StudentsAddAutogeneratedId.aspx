<%@ Page Title="" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="StudentsAdd.aspx.cs" Inherits="ContosoUniversity.StudentsAdd" %>
<asp:Content ID="Content1" ContentPlaceHolderID="HeadContent" runat="server">
</asp:Content>
<asp:Content ID="Content2" ContentPlaceHolderID="MainContent" runat="server" ClientIDMode="Static">
    <h2>Add New Students</h2>
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
                SortExpression="FirstMidName" />
            <asp:BoundField DataField="FirstMidName2" HeaderText="Test Name" SortExpression="FirstMidName"/>
            <asp:BoundField DataField="LastName" HeaderText="Last Name"
                SortExpression="LastName" />
            <asp:BoundField DataField="EnrollmentDate" HeaderText="Enrollment Date"
                SortExpression="EnrollmentDate" />
            <asp:CommandField ShowInsertButton="True" />
       </Fields>
    </asp:DetailsView>
</asp:Content>