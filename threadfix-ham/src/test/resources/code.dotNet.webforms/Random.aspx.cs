using System;
using OWASP.WebGoat.NET.App_Code;
using System.Collections.Generic;
using System.Text;

namespace OWASP.WebGoat.NET.Content
{
    public partial class Random : System.Web.UI.Page
    {
        private const uint MIN = 1;
        private const uint MAX = 1000;
        private const int INIT_NUMBERS = 5;

        public void Page_Load(object sender, EventArgs args)
        {
            if (Session["Random"] == null)
                Reset();

            IList<uint> numbers = (IList<uint>) Session["Numbers"];
            lblSequence.Text = "Sequence: " + Print(numbers);
        }

        public void btnOneMore_Click(object sender, EventArgs args)
        {
            WeakRandom rnd = (WeakRandom) Session["Random"];
            IList<uint> numbers = (IList<uint>) Session["Numbers"];

            numbers.Add(rnd.Next(MIN, MAX));

            lblSequence.Text = "Sequence: " + Print(numbers);
        }

        public void btnGo_Click(object sender, EventArgs args)
        {
            WeakRandom rnd = (WeakRandom) Session["Random"];

            uint next = rnd.Peek(MIN, MAX);

            if (txtNextNumber.Text == next.ToString())
                lblResult.Text = "You found it!";
            else
                lblResult.Text = "Sorry please try again.";
        }

        public void btnReset_Click(object sender, EventArgs args)
        {
            Reset();

            IList<uint> numbers = (IList<uint>) Session["Numbers"];
            lblSequence.Text = "Sequence: " + Print(numbers);
        }

        private string Print(IList<uint> numbers)
        {
            StringBuilder strBuilder = new StringBuilder();

            foreach(uint n in numbers)
                strBuilder.AppendFormat("{0}, ", n);

            return strBuilder.ToString();
        }

        public void Reset()
        {
            Session["Random"] = new WeakRandom();

            var rnd = (WeakRandom) Session["Random"];

            IList<uint> numbers = new List<uint>();

            for(int i=0; i<INIT_NUMBERS; i++)
                numbers.Add(rnd.Next(MIN, MAX));

            Session["Numbers"] = numbers;
        }
    }
}