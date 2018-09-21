//////////////////////////////////////////////////////////////////////
//  Copyright (c) 2007-2010 Denim Group, Ltd.
//  All rights reserved
//////////////////////////////////////////////////////////////////////

using System;
using System.Data;
using System.Data.SqlClient;
using System.Configuration;
using System.Collections;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;

public partial class ViewStatement : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        string sql = "SELECT * FROM Statement WHERE StatementID = " + Request["StatementID"];
        SqlConnection con = DBUtil.GetConnection();
        SqlDataReader reader = DBUtil.ExecuteDataReader(con, sql);

        reader.Read();

        DateTime billingDate = (DateTime)reader["BillingDate"];
        lblTopDate.Text = billingDate.ToString("MMM dd, yyyy");
        lblTopNumber.Text = (string)reader["CustomerNumber"];

        lblName.Text = (string)reader["Name"];
        lblAddress.Text = (string)reader["Address"];
        lblBillingDate.Text = billingDate.ToString("MMM dd, yyyy");
        lblCustomerNumber.Text = (string)reader["CustomerNumber"];

        decimal balanceDue;
        decimal currentElectricity = (decimal)reader["CurrentElectricity"];
        decimal currentNaturalGas = (decimal)reader["CurrentNaturalGas"];
        decimal cityServices = (decimal)reader["CityServices"];
        decimal stateLocalTaxes = (decimal)reader["StateLocalTaxes"];
        balanceDue = currentElectricity + currentNaturalGas + cityServices + stateLocalTaxes;

        lblByDue.Text = String.Format("{0:c}", balanceDue);
        lblAfterDue.Text = String.Format("{0:c}", (balanceDue*1.05m));

        lblKilowatt.Text = (string)reader["KiloWattHourUsed"].ToString();
        lblCcf.Text = (string)reader["CcfUsed"].ToString();

        lblPrevious.Text = String.Format("{0:c}", (decimal)reader["PreviousBill"]);
        lblPayments.Text = String.Format("{0:c}", (decimal)reader["Payments"]);
        lblCurrentElectric.Text = String.Format("{0:c}", (decimal)reader["CurrentElectricity"]);
        lblCurrentGas.Text = String.Format("{0:c}", (decimal)reader["CurrentNaturalGas"]);
        lblCityServices.Text = String.Format("{0:c}", (decimal)reader["CityServices"]);
        lblStateLocalTaxes.Text = String.Format("{0:c}", (decimal)reader["StateLocalTaxes"]);
        lblBalance2.Text = String.Format("{0:c}", balanceDue);
    }
}
