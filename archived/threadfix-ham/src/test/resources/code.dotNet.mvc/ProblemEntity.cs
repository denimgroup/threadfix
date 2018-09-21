using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;

namespace Test.Namespace
{
    [Table("TestApplication")]
    public abstract class TestApplication : BaseEntity
    {
        public static TestApplication Create(Test targetTest)
        {
            switch (targetTest)
            {
                case Test.EnumOne:
                    return new TestApplication();
                default:
                    throw new ArgumentException(string.Format("targetTest({0}) is invalid", targetTest));
            }
        }

        [Past(AllowToday = true)]
        [DisplayName("Received Date")]
        [DisplayFormat(DataFormatString = "{0:MM/dd/yyyy}")]
        public DateTime? ReceivedDate { get; set; }

        [DisplayName("Description matches code")]
        public bool DescriptionMatchesCode { get; set; }

        public virtual ICollection<UniqueIdentifierValue> UniqueIds { get; set; }
    }

    public enum Test
    {
        abstractb = 1 << 0,
        b = 1 << 1,
        c = 1 << 2,
        d = 1 << 3,
    }
}
