using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using System.Web.Security;
using System.Security.Principal;
using Edistrict.Controllers;
using Edistrict.Models.CustomAttribute;
using Edistrict.App_Start;
using System.Web.UI;
using Edistrict.Models.DataService;
using Edistrict.Models.ApplicationService;

namespace Edistrict
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            WebApiConfig.Register(GlobalConfiguration.Configuration);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            AuthConfig.RegisterAuth();
            RouteEngine.RegisterViewEngines(ViewEngines.Engines);

            Application["OnlineUsers"] = 0;
            MvcHandler.DisableMvcResponseHeader = true;
        }
        protected void Application_AuthenticateRequest(Object sender, EventArgs e)
        {
            ////temp process for stop https for digital signature process
            //var httpContext = ((MvcApplication)sender).Context;
            //var currentRouteData = RouteTable.Routes.GetRouteData(new HttpContextWrapper(httpContext));
            //if (currentRouteData != null)
            //{
            //    if (currentRouteData.Values["controller"] != null && !String.IsNullOrEmpty(currentRouteData.Values["controller"].ToString()))
            //    {
            //        if (currentRouteData.Values["controller"].ToString().ToLower() == "account" && currentRouteData.Values["action"].ToString().ToLower() == "employeedigitallogin")
            //        {
            //            if (Request.IsSecureConnection)
            //            {
            //                Response.Redirect("http://" + Request.ServerVariables["HTTP_HOST"] + Request.RawUrl);
            //            }
            //        }
            //        else if (currentRouteData.Values["controller"].ToString().ToLower() == "sign")
            //        {
            //            if (Request.IsSecureConnection)
            //            {
            //                Response.Redirect("http://" + Request.ServerVariables["HTTP_HOST"] + Request.RawUrl);
            //            }
            //        }
            //        else
            //        {
            //            if (!Request.IsSecureConnection)
            //            {
            //                Response.Redirect("https://" + Request.ServerVariables["HTTP_HOST"] + Request.RawUrl);
            //            }
            //        }
            //    }
            //}

            // check authentication token
            HttpCookie authCookie = Context.Request.Cookies[FormsAuthentication.FormsCookieName];
            if (authCookie == null || authCookie.Value == "") { return; }

            //// add mapping token in cookies
            //HttpCookie sessionToken = Context.Request.Cookies[ParamCookies.SessionToken];
            //if (sessionToken == null || sessionToken.Value == "") {
            //    string encryptAuthSession = RijndaelSimple.EncryptString((authCookie.Value + Context.Request.Cookies[ParamCookies.AspNetSessionId].Value), Constant._saltValue);
            //    Context.Response.Cookies.Add(new HttpCookie(ParamCookies.SessionToken, encryptAuthSession)); 
            //}

            // get user details from form authentication
            FormsAuthenticationTicket authTicket;
            try {
                authTicket = FormsAuthentication.Decrypt(authCookie.Value);
            } catch {
                return;
            }

            // retrieve roles from UserData 
            string[] roles = authTicket.UserData.Split(',');
            if (Context.User != null)
                Context.User = new GenericPrincipal(Context.User.Identity, roles);
        }
        protected void Application_Error(object sender, EventArgs e)
        {
            var httpContext = ((MvcApplication)sender).Context;
            var currentRouteData = RouteTable.Routes.GetRouteData(new HttpContextWrapper(httpContext));
            var currentController = " ";
            var currentAction = " ";

            if (currentRouteData != null)
            {
                if (currentRouteData.Values["controller"] != null && !String.IsNullOrEmpty(currentRouteData.Values["controller"].ToString()))
                {
                    currentController = currentRouteData.Values["controller"].ToString();
                }

                if (currentRouteData.Values["action"] != null && !String.IsNullOrEmpty(currentRouteData.Values["action"].ToString()))
                {
                    currentAction = currentRouteData.Values["action"].ToString();
                }
            }   

            var ex = Server.GetLastError();
            //Utility.ExceptionLogging(ex); //capture the log and save it to database
            var controller = new ErrorController();
            var routeData = new RouteData();
            var action = "Index";
            if (ex is HttpException)
            {
                var httpEx = ex as HttpException;
                var dd = httpEx.GetHttpCode();
                switch (httpEx.GetHttpCode())
                {
                    case 404:
                        action = "NotFound";
                        break;
                    case 500:
                        action = "InternalError";
                        break;
                    default:
                        action = "Index";
                        break;
                }
            }
            httpContext.ClearError();
            httpContext.Response.Clear();
            httpContext.Response.StatusCode = ex is HttpException ? ((HttpException)ex).GetHttpCode() : 500;
            httpContext.Response.TrySkipIisCustomErrors = true;
            routeData.Values["controller"] = "Error";
            routeData.Values["action"] = action;
            controller.ViewData.Model = new HandleErrorInfo(ex, currentController, currentAction);
            ((IController)controller).Execute(new RequestContext(new HttpContextWrapper(httpContext), routeData));
        }
        protected void Session_Start()
        {
            Session["VistorCount"] = Utility.GetApplicationVistorCount();

            Application.Lock();
            Application["OnlineUsers"] = (int)Application["OnlineUsers"] + 1;
            Session["OnlineUsers"] = Application["OnlineUsers"];
            Application.UnLock();
        }
        protected void Session_End(object sender, EventArgs e)
        {
            Application.Lock();
            Application["OnlineUsers"] = (int)Application["OnlineUsers"] - 1;
            Session["OnlineUsers"] = Application["OnlineUsers"];
            Application.UnLock();
        }
        //protected void Application_PreSendRequestHeaders()
        //{
        //    Response.Headers.Set("Server", "e-District Delhi");
        //    Response.Headers.Remove("X-AspNet-Version");
        //    Response.Headers.Remove("X-AspNetMvc-Version");
        //}
    }
}