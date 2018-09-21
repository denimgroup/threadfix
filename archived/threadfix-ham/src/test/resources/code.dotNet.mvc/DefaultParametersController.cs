using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Mvc;

namespace Test.Controllers
{
    public class ChatController : Controller
    {
        [HttpGet]
        public ActionResult DoAction(Guid? id, string type = null, DateTime? expires = null)
        {
            var thing = GetThingOrThrow(id);

            // init model
            var model = new PlaceThing(application, type);

            if (expires.HasValue) model.ExpiredOn = expires.Value.Date;
            return View("Test/Model", model);
        }
    }
}



