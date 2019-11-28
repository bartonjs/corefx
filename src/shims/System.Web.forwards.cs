// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Configuration;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.WebSockets;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Caching;
using System.Web.Configuration;
using System.Web.Instrumentation;
using System.Web.Profile;
using System.Web.Routing;
using System.Web.SessionState;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.WebSockets;

// This file contains shim types to allow application platforms with
// ASP.NET lightup code to execute (and detect that they're not in ASP.NET)
//
namespace System.Web
{
    public delegate IAsyncResult BeginEventHandler(object sender, EventArgs e, AsyncCallback cb, object extraData);
    public delegate void EndEventHandler(IAsyncResult ar);
    public delegate void HttpCacheValidateHandler(HttpContext context, Object data, ref HttpValidationStatus validationStatus);
    public delegate String HttpResponseSubstitutionCallback(HttpContext context);
    public delegate void TraceContextEventHandler(object sender, TraceContextEventArgs e);
    
    public interface IHttpAsyncHandler : IHttpHandler
    {
        IAsyncResult BeginProcessRequest(HttpContext context, AsyncCallback cb, object extraData);
        void EndProcessRequest(IAsyncResult result);
    }
    
    public interface IHttpHandler
    {
        void ProcessRequest(HttpContext context);   
        bool IsReusable { get; }
    }

    public interface IHttpModule
    {
        void Init(HttpApplication context);
        void Dispose();
    }

    public interface ISubscriptionToken
    {
        bool IsActive { get; }
        void Unsubscribe();
    }

    public interface ITlsTokenBindingInfo
    {
        byte[] GetProvidedTokenBindingId();
        byte[] GetReferredTokenBindingId();
    }
    
    public enum ApplicationShutdownReason
    {
        None = 0,
        HostingEnvironment = 1,
        ChangeInGlobalAsax = 2,
        ConfigurationChange = 3,
        UnloadAppDomainCalled = 4,
        ChangeInSecurityPolicyFile = 5,
        BinDirChangeOrDirectoryRename = 6,
        BrowsersDirChangeOrDirectoryRename = 7,
        CodeDirChangeOrDirectoryRename = 8,
        ResourcesDirChangeOrDirectoryRename = 9,
        IdleTimeout = 10,
        PhysicalApplicationPathChanged = 11,
        HttpRuntimeClose = 12,
        InitializationError = 13,
        MaxRecompilationsReached = 14,
        BuildManagerChange = 15,
    }

    public class HttpApplication : IComponent, IHttpAsyncHandler
    {
        public HttpApplication()
        {
            throw new PlatformNotSupportedException();
        }

        public HttpContext Context => default;

#pragma warning disable CS0067
        public event EventHandler Disposed;
#pragma warning restore CS0067

        protected EventHandlerList Events => default;
        public HttpRequest Request => default;
        public HttpResponse Response => default;
        public HttpSessionState Session => default;
        public HttpApplicationState Application => default;
        public HttpServerUtility Server => default;
        public IPrincipal User => default;
        public HttpModuleCollection Modules => default;
        public void CompleteRequest() { }

#pragma warning disable CS0067
        public event EventHandler BeginRequest;
        public event EventHandler AuthenticateRequest;
        public event EventHandler PostAuthenticateRequest;
        public event EventHandler AuthorizeRequest;
        public event EventHandler PostAuthorizeRequest;
        public event EventHandler ResolveRequestCache;
        public event EventHandler PostResolveRequestCache;
        public event EventHandler MapRequestHandler;
        public event EventHandler PostMapRequestHandler;
        public event EventHandler AcquireRequestState;
        public event EventHandler PostAcquireRequestState;
        public event EventHandler PreRequestHandlerExecute;
        public event EventHandler PostRequestHandlerExecute;
        public event EventHandler ReleaseRequestState;
        public event EventHandler PostReleaseRequestState;
        public event EventHandler UpdateRequestCache;
        public event EventHandler PostUpdateRequestCache;
        public event EventHandler LogRequest;
        public event EventHandler PostLogRequest;
        public event EventHandler EndRequest;
        public event EventHandler Error;
        public event EventHandler RequestCompleted;
        public event EventHandler PreSendRequestHeaders;
        public event EventHandler PreSendRequestContent;
#pragma warning restore CS0067

        public void AddOnBeginRequestAsync(BeginEventHandler bh, EndEventHandler eh) {}
        public void AddOnBeginRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnAuthenticateRequestAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnAuthenticateRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnPostAuthenticateRequestAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnPostAuthenticateRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnAuthorizeRequestAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnAuthorizeRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnPostAuthorizeRequestAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnPostAuthorizeRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnResolveRequestCacheAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnResolveRequestCacheAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnPostResolveRequestCacheAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnPostResolveRequestCacheAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnMapRequestHandlerAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnMapRequestHandlerAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnPostMapRequestHandlerAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnPostMapRequestHandlerAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnAcquireRequestStateAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnAcquireRequestStateAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnPostAcquireRequestStateAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnPostAcquireRequestStateAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnPreRequestHandlerExecuteAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnPreRequestHandlerExecuteAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnPostRequestHandlerExecuteAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnPostRequestHandlerExecuteAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnReleaseRequestStateAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnReleaseRequestStateAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnPostReleaseRequestStateAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnPostReleaseRequestStateAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnUpdateRequestCacheAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnUpdateRequestCacheAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnPostUpdateRequestCacheAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnPostUpdateRequestCacheAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnLogRequestAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnLogRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnPostLogRequestAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnPostLogRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public void AddOnEndRequestAsync(BeginEventHandler bh, EndEventHandler eh) { }
        public void AddOnEndRequestAsync(BeginEventHandler beginHandler, EndEventHandler endHandler, object state) { }
        public virtual void Init() { }
        public virtual void Dispose() { }
        public virtual string GetVaryByCustomString(HttpContext context, string custom) => default;
        public virtual string GetOutputCacheProviderName(HttpContext context) => default;
        public ISite Site { get; set; }

        IAsyncResult IHttpAsyncHandler.BeginProcessRequest(HttpContext context, AsyncCallback cb, object extraData) => default;
        void IHttpAsyncHandler.EndProcessRequest(IAsyncResult result) { }
        void IHttpHandler.ProcessRequest(HttpContext context) { }
        bool IHttpHandler.IsReusable => true;
        
        public void OnExecuteRequestStep(Action<HttpContextBase, Action> callback) { }

        public static void RegisterModule(Type moduleType)
        {
            throw new PlatformNotSupportedException();
        }
    }

    public sealed class HttpApplicationState : NameObjectCollectionBase
    {
        internal HttpApplicationState()
        {
            throw new PlatformNotSupportedException();
        }

        public void Add(string name, object value) { }
        public void Set(string name, object value) { }
        public void Remove(string name) { }
        public void RemoveAt(int index) { }
        public void Clear() { }
        public void RemoveAll() { }
        public object Get(string name) => default;

        public object this[string name]
        {
            get { return Get(name);}
            set { Set(name, value);}
        }
 
        public object Get(int index) => default;
        public string GetKey(int index) => default;
        public object this[int index] => default;
        public string[] AllKeys => default;
        public HttpApplicationState Contents => default;
        public HttpStaticObjectsCollection StaticObjects => default;
        public void Lock() { }
        public void UnLock() { }
    }

    public abstract class HttpApplicationStateBase : NameObjectCollectionBase, ICollection
    {
        public virtual string[] AllKeys => throw new NotImplementedException();
        public virtual HttpApplicationStateBase Contents => throw new NotImplementedException();
        public override int Count => throw new NotImplementedException();
        public virtual bool IsSynchronized => throw new NotImplementedException();
        public virtual object SyncRoot => throw new NotImplementedException();
        public virtual object this[int index] => throw new NotImplementedException();
        public virtual object this[string name] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual HttpStaticObjectsCollectionBase StaticObjects => throw new NotImplementedException();
        public virtual void Add(string name, object value) => throw new NotImplementedException();
        public virtual void Clear() => throw new NotImplementedException();
        public virtual void CopyTo(Array array, int index) => throw new NotImplementedException();
        public virtual object Get(int index) => throw new NotImplementedException();
        public virtual object Get(string name) => throw new NotImplementedException();
        public override IEnumerator GetEnumerator() => throw new NotImplementedException();
        public virtual string GetKey(int index) => throw new NotImplementedException();
        public virtual void Lock() => throw new NotImplementedException();
        public virtual void Remove(string name) => throw new NotImplementedException();
        public virtual void RemoveAll() => throw new NotImplementedException();
        public virtual void RemoveAt(int index) => throw new NotImplementedException();
        public virtual void Set(string name, object value) => throw new NotImplementedException();
        public virtual void UnLock() => throw new NotImplementedException();
    }

    public class HttpBrowserCapabilities : HttpCapabilitiesBase
    {
    }

    public abstract class HttpBrowserCapabilitiesBase : IFilterResolutionService
    {
        public virtual bool ActiveXControls => throw new NotImplementedException();
        public virtual IDictionary Adapters => throw new NotImplementedException();
        public virtual bool AOL => throw new NotImplementedException();
        public virtual bool BackgroundSounds => throw new NotImplementedException();
        public virtual bool Beta => throw new NotImplementedException();
        public virtual string Browser => throw new NotImplementedException();
        public virtual ArrayList Browsers => throw new NotImplementedException();
        public virtual bool CanCombineFormsInDeck => throw new NotImplementedException();
        public virtual bool CanInitiateVoiceCall => throw new NotImplementedException();
        public virtual bool CanRenderAfterInputOrSelectElement => throw new NotImplementedException();
        public virtual bool CanRenderEmptySelects => throw new NotImplementedException();
        public virtual bool CanRenderInputAndSelectElementsTogether => throw new NotImplementedException();
        public virtual bool CanRenderMixedSelects => throw new NotImplementedException();
        public virtual bool CanRenderOneventAndPrevElementsTogether => throw new NotImplementedException();
        public virtual bool CanRenderPostBackCards => throw new NotImplementedException();
        public virtual bool CanRenderSetvarZeroWithMultiSelectionList => throw new NotImplementedException();
        public virtual bool CanSendMail => throw new NotImplementedException();
        public virtual IDictionary Capabilities { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual bool CDF => throw new NotImplementedException();
        public virtual Version ClrVersion => throw new NotImplementedException();
        public virtual bool Cookies => throw new NotImplementedException();
        public virtual bool Crawler => throw new NotImplementedException();
        public virtual int DefaultSubmitButtonLimit => throw new NotImplementedException();
        public virtual Version EcmaScriptVersion => throw new NotImplementedException();
        public virtual bool Frames => throw new NotImplementedException();
        public virtual int GatewayMajorVersion => throw new NotImplementedException();
        public virtual double GatewayMinorVersion => throw new NotImplementedException();
        public virtual string GatewayVersion => throw new NotImplementedException();
        public virtual bool HasBackButton => throw new NotImplementedException();
        public virtual bool HidesRightAlignedMultiselectScrollbars => throw new NotImplementedException();
        public virtual string HtmlTextWriter { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual string Id => throw new NotImplementedException();
        public virtual string InputType => throw new NotImplementedException();
        public virtual bool IsColor => throw new NotImplementedException();
        public virtual bool IsMobileDevice => throw new NotImplementedException();
        public virtual bool JavaApplets => throw new NotImplementedException();
        public virtual Version JScriptVersion => throw new NotImplementedException();
        public virtual int MajorVersion => throw new NotImplementedException();
        public virtual int MaximumHrefLength => throw new NotImplementedException();
        public virtual int MaximumRenderedPageSize => throw new NotImplementedException();
        public virtual int MaximumSoftkeyLabelLength => throw new NotImplementedException();
        public virtual double MinorVersion => throw new NotImplementedException();
        public virtual string MinorVersionString => throw new NotImplementedException();
        public virtual string MobileDeviceManufacturer => throw new NotImplementedException();
        public virtual string MobileDeviceModel => throw new NotImplementedException();
        public virtual Version MSDomVersion => throw new NotImplementedException();
        public virtual int NumberOfSoftkeys => throw new NotImplementedException();
        public virtual string Platform => throw new NotImplementedException();
        public virtual string PreferredImageMime => throw new NotImplementedException();
        public virtual string PreferredRenderingMime => throw new NotImplementedException();
        public virtual string PreferredRenderingType => throw new NotImplementedException();
        public virtual string PreferredRequestEncoding => throw new NotImplementedException();
        public virtual string PreferredResponseEncoding => throw new NotImplementedException();
        public virtual bool RendersBreakBeforeWmlSelectAndInput => throw new NotImplementedException();
        public virtual bool RendersBreaksAfterHtmlLists => throw new NotImplementedException();
        public virtual bool RendersBreaksAfterWmlAnchor => throw new NotImplementedException();
        public virtual bool RendersBreaksAfterWmlInput => throw new NotImplementedException();
        public virtual bool RendersWmlDoAcceptsInline => throw new NotImplementedException();
        public virtual bool RendersWmlSelectsAsMenuCards => throw new NotImplementedException();
        public virtual string RequiredMetaTagNameValue => throw new NotImplementedException();
        public virtual bool RequiresAttributeColonSubstitution => throw new NotImplementedException();
        public virtual bool RequiresContentTypeMetaTag => throw new NotImplementedException();
        public virtual bool RequiresControlStateInSession => throw new NotImplementedException();
        public virtual bool RequiresDBCSCharacter => throw new NotImplementedException();
        public virtual bool RequiresHtmlAdaptiveErrorReporting => throw new NotImplementedException();
        public virtual bool RequiresLeadingPageBreak => throw new NotImplementedException();
        public virtual bool RequiresNoBreakInFormatting => throw new NotImplementedException();
        public virtual bool RequiresOutputOptimization => throw new NotImplementedException();
        public virtual bool RequiresPhoneNumbersAsPlainText => throw new NotImplementedException();
        public virtual bool RequiresSpecialViewStateEncoding => throw new NotImplementedException();
        public virtual bool RequiresUniqueFilePathSuffix => throw new NotImplementedException();
        public virtual bool RequiresUniqueHtmlCheckboxNames => throw new NotImplementedException();
        public virtual bool RequiresUniqueHtmlInputNames => throw new NotImplementedException();
        public virtual bool RequiresUrlEncodedPostfieldValues => throw new NotImplementedException();
        public virtual int ScreenBitDepth => throw new NotImplementedException();
        public virtual int ScreenCharactersHeight => throw new NotImplementedException();
        public virtual int ScreenCharactersWidth => throw new NotImplementedException();
        public virtual int ScreenPixelsHeight => throw new NotImplementedException();
        public virtual int ScreenPixelsWidth => throw new NotImplementedException();
        public virtual bool SupportsAccesskeyAttribute => throw new NotImplementedException();
        public virtual bool SupportsBodyColor => throw new NotImplementedException();
        public virtual bool SupportsBold => throw new NotImplementedException();
        public virtual bool SupportsCacheControlMetaTag => throw new NotImplementedException();
        public virtual bool SupportsCallback => throw new NotImplementedException();
        public virtual bool SupportsCss => throw new NotImplementedException();
        public virtual bool SupportsDivAlign => throw new NotImplementedException();
        public virtual bool SupportsDivNoWrap => throw new NotImplementedException();
        public virtual bool SupportsEmptyStringInCookieValue => throw new NotImplementedException();
        public virtual bool SupportsFontColor => throw new NotImplementedException();
        public virtual bool SupportsFontName => throw new NotImplementedException();
        public virtual bool SupportsFontSize => throw new NotImplementedException();
        public virtual bool SupportsImageSubmit => throw new NotImplementedException();
        public virtual bool SupportsIModeSymbols => throw new NotImplementedException();
        public virtual bool SupportsInputIStyle => throw new NotImplementedException();
        public virtual bool SupportsInputMode => throw new NotImplementedException();
        public virtual bool SupportsItalic => throw new NotImplementedException();
        public virtual bool SupportsJPhoneMultiMediaAttributes => throw new NotImplementedException();
        public virtual bool SupportsJPhoneSymbols => throw new NotImplementedException();
        public virtual bool SupportsQueryStringInFormAction => throw new NotImplementedException();
        public virtual bool SupportsRedirectWithCookie => throw new NotImplementedException();
        public virtual bool SupportsSelectMultiple => throw new NotImplementedException();
        public virtual bool SupportsUncheck => throw new NotImplementedException();
        public virtual bool SupportsXmlHttp => throw new NotImplementedException();
        public virtual bool Tables => throw new NotImplementedException();
        public virtual Type TagWriter => throw new NotImplementedException();
        public virtual string Type => throw new NotImplementedException();
        public virtual bool UseOptimizedCacheKey => throw new NotImplementedException();
        public virtual bool VBScript => throw new NotImplementedException();
        public virtual string Version => throw new NotImplementedException();
        public virtual Version W3CDomVersion => throw new NotImplementedException();
        public virtual bool Win16 => throw new NotImplementedException();
        public virtual bool Win32 => throw new NotImplementedException();
        public virtual string this[string key] => throw new NotImplementedException();
        public virtual void AddBrowser(string browserName) => throw new NotImplementedException();
        public virtual HtmlTextWriter CreateHtmlTextWriter(TextWriter w) => throw new NotImplementedException();
        public virtual void DisableOptimizedCacheKey() => throw new NotImplementedException();
        public virtual Version[] GetClrVersions() => throw new NotImplementedException();
        public virtual bool IsBrowser(string browserName) => throw new NotImplementedException();
        public virtual int CompareFilters(string filter1, string filter2) => throw new NotImplementedException();
        public virtual bool EvaluateFilter(string filterName) => throw new NotImplementedException();
    }

    public enum HttpCacheability
    {
        NoCache = 1,
        Private,
        Server,
        ServerAndNoCache = Server,
        Public,
        ServerAndPrivate,
    }
    
    public sealed class HttpCachePolicy
    {
        internal HttpCachePolicy()
        {
            throw new PlatformNotSupportedException();
        }

        public bool IsModified() => default;
        public void SetNoServerCaching() { }
        public bool GetNoServerCaching() => default;
        public void SetVaryByCustom(string custom) { }
        public string GetVaryByCustom() => default;
        public void AppendCacheExtension(String extension) { }
        public string GetCacheExtensions() => default;
        public void SetNoTransforms() { }
        public bool GetNoTransforms() => default;
        public bool GetIgnoreRangeRequests() => default;
        public HttpCacheVaryByContentEncodings VaryByContentEncodings => default;
        public HttpCacheVaryByHeaders VaryByHeaders => default;
        public HttpCacheVaryByParams VaryByParams => default;
        public void SetCacheability(HttpCacheability cacheability) { }
        public HttpCacheability GetCacheability() => default;
        public void SetCacheability(HttpCacheability cacheability, String field) { }
        public void SetNoStore() { }
        public bool GetNoStore() => default;
        public void SetExpires(DateTime date) { }
        public DateTime GetExpires() => default;
        public void SetMaxAge(TimeSpan delta) { }
        public TimeSpan GetMaxAge() => default;
        public void SetProxyMaxAge(TimeSpan delta) { }
        public TimeSpan GetProxyMaxAge() => default;
        public void SetSlidingExpiration(bool slide) { }
        public bool HasSlidingExpiration() => default;
        public void SetValidUntilExpires(bool validUntilExpires) { }
        public bool IsValidUntilExpires() => default;
        public void SetAllowResponseInBrowserHistory(bool allow) { }
        public void SetRevalidation(HttpCacheRevalidation revalidation) { }
        public HttpCacheRevalidation GetRevalidation() => default;
        public void SetETag(String etag) { }
        public string GetETag() => default;
        public void SetLastModified(DateTime date) { }
        public DateTime GetUtcLastModified() => default;
        public void SetLastModifiedFromFileDependencies() { }
        public bool GetLastModifiedFromFileDependencies() => default;
        public void SetETagFromFileDependencies() { }
        public bool GetETagFromFileDependencies() => default;
        public void SetOmitVaryStar(bool omit) { }
        public int GetOmitVaryStar() => default;
        public void AddValidationCallback(HttpCacheValidateHandler handler, Object data) { }
        public DateTime UtcTimestampCreated { get; set; }
    }

    public abstract class HttpCachePolicyBase
    {
        public virtual HttpCacheVaryByContentEncodings VaryByContentEncodings => throw new NotImplementedException();
        public virtual HttpCacheVaryByHeaders VaryByHeaders => throw new NotImplementedException();
        public virtual HttpCacheVaryByParams VaryByParams => throw new NotImplementedException();
        public virtual void AddValidationCallback(HttpCacheValidateHandler handler, object data) => throw new NotImplementedException();
        public virtual void AppendCacheExtension(string extension) => throw new NotImplementedException();
        public virtual void SetAllowResponseInBrowserHistory(bool allow) => throw new NotImplementedException();
        public virtual void SetCacheability(HttpCacheability cacheability) => throw new NotImplementedException();
        public virtual void SetCacheability(HttpCacheability cacheability, string field) => throw new NotImplementedException();
        public virtual void SetETag(string etag) => throw new NotImplementedException();
        public virtual void SetETagFromFileDependencies() => throw new NotImplementedException();
        public virtual void SetExpires(DateTime date) => throw new NotImplementedException();
        public virtual void SetLastModified(DateTime date) => throw new NotImplementedException();
        public virtual void SetLastModifiedFromFileDependencies() => throw new NotImplementedException();
        public virtual void SetMaxAge(TimeSpan delta) => throw new NotImplementedException();
        public virtual void SetNoServerCaching() => throw new NotImplementedException();
        public virtual void SetNoStore() => throw new NotImplementedException();
        public virtual void SetNoTransforms() => throw new NotImplementedException();
        public virtual void SetOmitVaryStar(bool omit) => throw new NotImplementedException();
        public virtual void SetProxyMaxAge(TimeSpan delta) => throw new NotImplementedException();
        public virtual void SetRevalidation(HttpCacheRevalidation revalidation) => throw new NotImplementedException();
        public virtual void SetSlidingExpiration(bool slide) => throw new NotImplementedException();
        public virtual void SetValidUntilExpires(bool validUntilExpires) => throw new NotImplementedException();
        public virtual void SetVaryByCustom(string custom) => throw new NotImplementedException();
    }

    public enum HttpCacheRevalidation
    {
        AllCaches = 1,
        ProxyCaches = 2,
        None = 3,
    }
    
    public sealed class HttpCacheVaryByContentEncodings
    {
        public HttpCacheVaryByContentEncodings()
        {
            throw new PlatformNotSupportedException();
        }
 
        public void SetContentEncodings(string[] contentEncodings) { }
        public string[] GetContentEncodings() => default;
        public bool this[String contentEncoding] { get => throw new PlatformNotSupportedException(); set => throw new PlatformNotSupportedException(); }
    }

    public sealed class HttpCacheVaryByHeaders
    {
        public HttpCacheVaryByHeaders()
        {
            throw new PlatformNotSupportedException();
        }
 
        public void SetHeaders(string[] headers) { }
        public string[] GetHeaders() => default;
        public void VaryByUnspecifiedParameters() { }
        public bool AcceptTypes { get; set; }
        public bool UserLanguage { get; set; }
        public bool UserAgent { get; set; }
        public bool UserCharSet { get; set; }
        public bool this[String header] { get => throw new PlatformNotSupportedException(); set => throw new PlatformNotSupportedException(); }
    }

    public sealed class HttpCacheVaryByParams
    {
        public HttpCacheVaryByParams()
        {
            throw new PlatformNotSupportedException();
        }
 
        public void SetParams(string[] parameters) { }
        public string[] GetParams() => default;
        public bool this[String header] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public bool IgnoreParams { get; set; }
    }

    public class HttpClientCertificate  : NameValueCollection
    {
        public string Cookie => default;
        public byte[] Certificate => default;
        public int Flags => default;
        public int KeySize => default;
        public int SecretKeySize => default;
        public string Issuer => default;
        public string ServerIssuer => default;
        public string Subject => default;
        public string ServerSubject => default;
        public string SerialNumber => default;
        public DateTime ValidFrom => default;
        public DateTime ValidUntil => default;
        public int CertEncoding => default;
        public byte[] PublicKey => default;
        public byte[] BinaryIssuer => default;
        public bool IsPresent => default;
        public bool IsValid => default;
 
        internal HttpClientCertificate(HttpContext context)
        {
            throw new PlatformNotSupportedException();
        }

        public override string Get(string field) => default;
    }

    public sealed class HttpContext : IServiceProvider
    {
        public bool IsWebSocketRequest => default;
        public bool IsWebSocketRequestUpgrading => default;
        public IList<string> WebSocketRequestedProtocols => default;
        public string WebSocketNegotiatedProtocol => default;
        public void AcceptWebSocketRequest(Func<AspNetWebSocketContext, Task> userFunc) { }
        public void AcceptWebSocketRequest(Func<AspNetWebSocketContext, Task> userFunc, AspNetWebSocketOptions options) { }

        public HttpContext(HttpRequest request, HttpResponse response)
        {
            throw new PlatformNotSupportedException();
        }
 
        public HttpContext(HttpWorkerRequest wr)
        {
            throw new PlatformNotSupportedException();
        }
 
        public static HttpContext Current => null;
        public ISubscriptionToken AddOnRequestCompleted(Action<HttpContext> callback) => default;
        public ISubscriptionToken DisposeOnPipelineCompleted(IDisposable target) => default;
        object IServiceProvider.GetService(Type service) => default;

        public AsyncPreloadModeFlags AsyncPreloadMode
        {
            get { return default; } set {}
        }

        public bool AllowAsyncDuringSyncStages
        {
            get { return default; } set {}
        }

        public HttpApplication ApplicationInstance
        {
            get { return default; } set {}
        }

        public HttpApplicationState Application => default;

        public IHttpHandler Handler
        {
            get { return default; } set {}
        }
        
        public IHttpHandler PreviousHandler => default;
        public IHttpHandler CurrentHandler => default;
        public void RemapHandler(IHttpHandler handler) { }
        public HttpRequest Request => default;
        public HttpResponse Response => default;
        public TraceContext Trace => default;
        public IDictionary Items => default;
        public HttpSessionState Session => default;
        public HttpServerUtility Server => default;
        public Exception Error => default;
        public Exception[] AllErrors => default;
        public void AddError(Exception errorInfo) { }
        public void ClearError() { }

        public IPrincipal User
        {
            get { return default; } set {}
        }

        public ProfileBase Profile => default;
        public void SetSessionStateBehavior(SessionStateBehavior sessionStateBehavior) { }

        public bool SkipAuthorization
        {
            get { return default; } set {}
        }
        
        public bool IsDebuggingEnabled => default;
        public bool IsCustomErrorEnabled => default;
        public DateTime Timestamp => default;
        public Cache Cache => default;
        public PageInstrumentationService PageInstrumentation => default;
        public object GetConfig(string name) => default;
        public object GetSection(string sectionName) => default;
        public void RewritePath(string path) { }
        public void RewritePath(string path, bool rebaseClientPath) { }
        public void RewritePath(string filePath, string pathInfo, string queryString) { }
        public void RewritePath(string filePath, string pathInfo, string queryString, bool setClientFilePath) { }

        public static object GetAppConfig(string name) => ConfigurationManager.GetSection(name);

        // These could probably be made to work, if there's a scenario where non-ASP.NET contexts can sensibly call them.
        public static object GetGlobalResourceObject(string classKey, string resourceKey) => throw new PlatformNotSupportedException();
        public static object GetGlobalResourceObject(string classKey, string resourceKey, CultureInfo culture) => throw new PlatformNotSupportedException();
        public static object GetLocalResourceObject(string virtualPath, string resourceKey) => throw new PlatformNotSupportedException();
        public static object GetLocalResourceObject(string virtualPath, string resourceKey, CultureInfo culture) => throw new PlatformNotSupportedException();
        
        public bool ThreadAbortOnTimeout
        {
            get { return default; } set {}
        }

        public RequestNotification CurrentNotification => default;
        public bool IsPostNotification => default;
    }

    public abstract class HttpContextBase : IServiceProvider
    {
        public virtual ISubscriptionToken AddOnRequestCompleted(Action<HttpContextBase> callback) => throw new NotImplementedException();
        public virtual Exception[] AllErrors => throw new NotImplementedException();
        public virtual bool AllowAsyncDuringSyncStages { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual HttpApplicationStateBase Application => throw new NotImplementedException();
        public virtual HttpApplication ApplicationInstance { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual AsyncPreloadModeFlags AsyncPreloadMode { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual Cache Cache => throw new NotImplementedException();
        public virtual IHttpHandler CurrentHandler => throw new NotImplementedException();
        public virtual RequestNotification CurrentNotification => throw new NotImplementedException();
        public virtual Exception Error => throw new NotImplementedException();
        public virtual IHttpHandler Handler { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual bool IsCustomErrorEnabled => throw new NotImplementedException();
        public virtual bool IsDebuggingEnabled => throw new NotImplementedException();
        public virtual bool IsPostNotification => throw new NotImplementedException();
        public virtual bool IsWebSocketRequest => throw new NotImplementedException();
        public virtual bool IsWebSocketRequestUpgrading => throw new NotImplementedException();
        public virtual IDictionary Items => throw new NotImplementedException();
        public virtual PageInstrumentationService PageInstrumentation => throw new NotImplementedException();
        public virtual IHttpHandler PreviousHandler => throw new NotImplementedException();
        public virtual ProfileBase Profile => throw new NotImplementedException();
        public virtual HttpRequestBase Request => throw new NotImplementedException();
        public virtual HttpResponseBase Response => throw new NotImplementedException();
        public virtual HttpServerUtilityBase Server => throw new NotImplementedException();
        public virtual HttpSessionStateBase Session => throw new NotImplementedException();
        public virtual bool SkipAuthorization { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual DateTime Timestamp => throw new NotImplementedException();
        public virtual bool ThreadAbortOnTimeout { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual TraceContext Trace => throw new NotImplementedException();
        public virtual IPrincipal User { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual string WebSocketNegotiatedProtocol => throw new NotImplementedException();
        public virtual IList<string> WebSocketRequestedProtocols => throw new NotImplementedException();
        public virtual void AcceptWebSocketRequest(Func<AspNetWebSocketContext, Task> userFunc) => throw new NotImplementedException();
        public virtual void AcceptWebSocketRequest(Func<AspNetWebSocketContext, Task> userFunc, AspNetWebSocketOptions options) => throw new NotImplementedException();
        public virtual void AddError(Exception errorInfo) => throw new NotImplementedException();
        public virtual void ClearError() => throw new NotImplementedException();
        public virtual ISubscriptionToken DisposeOnPipelineCompleted(IDisposable target) => throw new NotImplementedException();
        public virtual object GetGlobalResourceObject(string classKey, string resourceKey) => throw new NotImplementedException();
        public virtual object GetGlobalResourceObject(string classKey, string resourceKey, CultureInfo culture) => throw new NotImplementedException();
        public virtual object GetLocalResourceObject(string virtualPath, string resourceKey) => throw new NotImplementedException();
        public virtual object GetLocalResourceObject(string virtualPath, string resourceKey, CultureInfo culture) => throw new NotImplementedException();
        public virtual object GetSection(string sectionName) => throw new NotImplementedException();
        public virtual void RemapHandler(IHttpHandler handler) => throw new NotImplementedException();
        public virtual void RewritePath(string path) => throw new NotImplementedException();
        public virtual void RewritePath(string path, bool rebaseClientPath) => throw new NotImplementedException();
        public virtual void RewritePath(string filePath, string pathInfo, string queryString) => throw new NotImplementedException();
        public virtual void RewritePath(string filePath, string pathInfo, string queryString, bool setClientFilePath) => throw new NotImplementedException();
        public virtual void SetSessionStateBehavior(SessionStateBehavior sessionStateBehavior) => throw new NotImplementedException();
        public virtual object GetService(Type serviceType) => throw new NotImplementedException();
    }

    public sealed class HttpCookie
    {
        public HttpCookie(string name)
        {
            throw new PlatformNotSupportedException();
        }
 
        public HttpCookie(string name, string value)
        {
            throw new PlatformNotSupportedException();
        }
 
        public string Name { get; set; }
        public string Path { get; set; } 
        public bool Secure { get; set; }
        public bool Sharable { get; set; }
        public bool HttpOnly { get; set; }
        public string Domain { get; set; }
        public DateTime Expires { get; set; }
        public string Value { get; set; }
        public SameSiteMode SameSite { get; set; }
        public bool HasKeys => default;
        public NameValueCollection Values => default;
        public string this[string key]
        {
            get
            {
                return Values[key];
            }
            set
            {
                Values[key] = value;
            }
        }
 
        public static bool TryParse(string input, out HttpCookie result)
        {
            throw new PlatformNotSupportedException();
        }
    }
 
    public sealed class HttpCookieCollection : NameObjectCollectionBase
    {
        public HttpCookieCollection() : base(StringComparer.OrdinalIgnoreCase)
        {
            throw new PlatformNotSupportedException();
        }
 
        public void Add(HttpCookie cookie) { }
        public void CopyTo(Array dest, int index) { }
        public void Set(HttpCookie cookie) { }
        public void Remove(string name) { }
        public void Clear() { }
        public HttpCookie Get(string name) => default;
        public HttpCookie this[string name] => default;
        public HttpCookie Get(int index) => default;
        public string GetKey(int index) => default;
        public HttpCookie this[int index] => default;
        public string[] AllKeys => default;
    }

    public enum HttpCookieMode
    {
        UseUri,
        UseCookies,
        AutoDetect,
        UseDeviceProfile,
    }

    public sealed class HttpFileCollection : NameObjectCollectionBase
    {
        internal HttpFileCollection() : base(StringComparer.InvariantCultureIgnoreCase)
        {
            throw new PlatformNotSupportedException();
        }
 
        public void CopyTo(Array dest, int index) { }
        public HttpPostedFile Get(string name) => default;
        public IList<HttpPostedFile> GetMultiple(string name) => default;
        public HttpPostedFile this[string name] => default;
        public HttpPostedFile Get(int index) => default;
        public string GetKey(int index) => default;
        public HttpPostedFile this[int index] => default;
        public string[] AllKeys => default;
    }

    public abstract class HttpFileCollectionBase : NameObjectCollectionBase, ICollection
    {
        public virtual string[] AllKeys => throw new NotImplementedException();
        public override int Count => throw new NotImplementedException();
        public virtual bool IsSynchronized => throw new NotImplementedException();
        public virtual object SyncRoot => throw new NotImplementedException();
        public virtual HttpPostedFileBase this[string name] => throw new NotImplementedException();
        public virtual HttpPostedFileBase this[int index] => throw new NotImplementedException();
        public virtual void CopyTo(Array dest, int index) => throw new NotImplementedException();
        public virtual HttpPostedFileBase Get(int index) => throw new NotImplementedException();
        public virtual HttpPostedFileBase Get(string name) => throw new NotImplementedException();
        public virtual IList<HttpPostedFileBase> GetMultiple(string name) => throw new NotImplementedException();
        public override IEnumerator GetEnumerator() => throw new NotImplementedException();
        public virtual string GetKey(int index) => throw new NotImplementedException();
    }

    public sealed class HttpModuleCollection : NameObjectCollectionBase
    {
        internal HttpModuleCollection()
        {
            throw new PlatformNotSupportedException();
        }
 
        public void CopyTo(Array dest, int index) { }
        public IHttpModule Get(String name) => default;
        public IHttpModule this[String name] => default;
        public IHttpModule Get(int index) => default;
        public String GetKey(int index) => default;
        public IHttpModule this[int index] => default;
        public String[] AllKeys => default;
    }
    
    public sealed class HttpPostedFile
    {
        internal HttpPostedFile()
        {
            throw new PlatformNotSupportedException();
        }
 
        public string FileName => default;
        public string ContentType => default;
        public int ContentLength => default;
        public Stream InputStream => default;
        public void SaveAs(string filename) { }
    }

    public abstract class HttpPostedFileBase
    {
        public virtual int ContentLength => throw new NotImplementedException();
        public virtual string ContentType => throw new NotImplementedException();
        public virtual string FileName => throw new NotImplementedException();
        public virtual Stream InputStream => throw new NotImplementedException();
        public virtual void SaveAs(string filename) => throw new NotImplementedException();
    }

    public sealed class HttpRequest
    {
        public HttpRequest(string filename, string url, string queryString)
        {
            throw new PlatformNotSupportedException();
        }
 
        public RequestContext RequestContext { get; set; }
        public bool IsLocal => default;
        public string HttpMethod => default;
        public string RequestType { get; set; }
        public string ContentType { get; set; }
        public int ContentLength => default;
        public Encoding ContentEncoding { get; set; }
        public string[] AcceptTypes => default;
        public bool IsAuthenticated => default;
        public bool IsSecureConnection => default;
        public string Path => default;
        public string AnonymousID => default;
        public string FilePath => default;
        public string CurrentExecutionFilePath => default;
        public string CurrentExecutionFilePathExtension => default;
        public string AppRelativeCurrentExecutionFilePath => default;
        public string PathInfo => default;
        public string PhysicalPath => default;
        public string ApplicationPath => default;
        public string PhysicalApplicationPath => default;
        public string UserAgent => default;
        public string[] UserLanguages => default;
        public HttpBrowserCapabilities Browser { get; set; }
        public string UserHostName => default;
        public string UserHostAddress => default;
        public string RawUrl => default;
        public Uri Url => default;
        public Uri UrlReferrer => default;
        public NameValueCollection Params => default;
        public string this[string key] => default;
        public NameValueCollection QueryString => default;
        public NameValueCollection Form => default;
        public NameValueCollection Headers => default;
        public UnvalidatedRequestValues Unvalidated => default;
        public NameValueCollection ServerVariables => default;
        public HttpCookieCollection Cookies => default;
        public HttpFileCollection Files => default;
        public Stream InputStream => default;
        public int TotalBytes => default;
        public byte[] BinaryRead(int count) => default;
        public Stream Filter { get; set; }
        public HttpClientCertificate ClientCertificate => default;
        public WindowsIdentity LogonUserIdentity => default;
        public void ValidateInput() { }
        public int[] MapImageCoordinates(string imageFieldName) => default;
        public double[] MapRawImageCoordinates(string imageFieldName) => default;
        public void SaveAs(string filename, bool includeHeaders) { }
        public string MapPath(string virtualPath) => default;
        public string MapPath(string virtualPath, string baseVirtualDir, bool allowCrossAppMapping) => default;
        public ChannelBinding HttpChannelBinding => default;
        public ITlsTokenBindingInfo TlsTokenBindingInfo => default;
        public void InsertEntityBody(byte[] buffer, int offset, int count) { }
        public void InsertEntityBody() { }
        public ReadEntityBodyMode ReadEntityBodyMode => default;
        public Stream GetBufferlessInputStream() => default;
        public Stream GetBufferlessInputStream(bool disableMaxRequestLength) => default;
        public Stream GetBufferedInputStream() => default;
        public void Abort() { }
        public CancellationToken TimedOutToken => default;
    }

    public abstract class HttpRequestBase
    {
        public virtual String[] AcceptTypes => throw new NotImplementedException();
        public virtual String ApplicationPath => throw new NotImplementedException();
        public virtual String AnonymousID => throw new NotImplementedException();
        public virtual String AppRelativeCurrentExecutionFilePath => throw new NotImplementedException();
        public virtual HttpBrowserCapabilitiesBase Browser => throw new NotImplementedException();
        public virtual ChannelBinding HttpChannelBinding => throw new NotImplementedException();
        public virtual HttpClientCertificate ClientCertificate => throw new NotImplementedException();
        public virtual Encoding ContentEncoding { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual int ContentLength => throw new NotImplementedException();
        public virtual String ContentType { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual HttpCookieCollection Cookies => throw new NotImplementedException();
        public virtual String CurrentExecutionFilePath => throw new NotImplementedException();
        public virtual string CurrentExecutionFilePathExtension => throw new NotImplementedException();
        public virtual String FilePath => throw new NotImplementedException();
        public virtual HttpFileCollectionBase Files => throw new NotImplementedException();
        public virtual Stream Filter { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual NameValueCollection Form => throw new NotImplementedException();
        public virtual String HttpMethod => throw new NotImplementedException();
        public virtual Stream InputStream => throw new NotImplementedException();
        public virtual bool IsAuthenticated => throw new NotImplementedException();
        public virtual bool IsLocal => throw new NotImplementedException();
        public virtual bool IsSecureConnection => throw new NotImplementedException();
        public virtual WindowsIdentity LogonUserIdentity => throw new NotImplementedException();
        public virtual NameValueCollection Params => throw new NotImplementedException();
        public virtual String Path => throw new NotImplementedException();
        public virtual String PathInfo => throw new NotImplementedException();
        public virtual String PhysicalApplicationPath => throw new NotImplementedException();
        public virtual String PhysicalPath => throw new NotImplementedException();
        public virtual String RawUrl => throw new NotImplementedException();
        public virtual ReadEntityBodyMode ReadEntityBodyMode => throw new NotImplementedException();
        public virtual RequestContext RequestContext { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual String RequestType { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual NameValueCollection ServerVariables => throw new NotImplementedException();
        public virtual CancellationToken TimedOutToken => throw new NotImplementedException();
        public virtual ITlsTokenBindingInfo TlsTokenBindingInfo => throw new NotImplementedException();
        public virtual int TotalBytes => throw new NotImplementedException();
        public virtual UnvalidatedRequestValuesBase Unvalidated => throw new NotImplementedException();
        public virtual Uri Url => throw new NotImplementedException();
        public virtual Uri UrlReferrer => throw new NotImplementedException();
        public virtual String UserAgent => throw new NotImplementedException();
        public virtual String[] UserLanguages => throw new NotImplementedException();
        public virtual String UserHostAddress => throw new NotImplementedException();
        public virtual String UserHostName => throw new NotImplementedException();
        public virtual NameValueCollection Headers => throw new NotImplementedException();
        public virtual NameValueCollection QueryString => throw new NotImplementedException();
        public virtual String this[String key] => throw new NotImplementedException();
        public virtual void Abort() => throw new NotImplementedException();
        public virtual byte[] BinaryRead(int count) => throw new NotImplementedException();
        public virtual Stream GetBufferedInputStream() => throw new NotImplementedException();
        public virtual Stream GetBufferlessInputStream() => throw new NotImplementedException();
        public virtual Stream GetBufferlessInputStream(bool disableMaxRequestLength) => throw new NotImplementedException();
        public virtual void InsertEntityBody() => throw new NotImplementedException();
        public virtual void InsertEntityBody(byte[] buffer, int offset, int count) => throw new NotImplementedException();
        public virtual int[] MapImageCoordinates(String imageFieldName) => throw new NotImplementedException();
        public virtual double[] MapRawImageCoordinates(String imageFieldName) => throw new NotImplementedException();
        public virtual String MapPath(String virtualPath) => throw new NotImplementedException();
        public virtual String MapPath(string virtualPath, string baseVirtualDir, bool allowCrossAppMapping) => throw new NotImplementedException();
        public virtual void ValidateInput() => throw new NotImplementedException();
        public virtual void SaveAs(String filename, bool includeHeaders) => throw new NotImplementedException();
    }

    public sealed class HttpResponse
    {
        public HttpResponse(TextWriter writer)
        {
            throw new PlatformNotSupportedException();
        }
 
        public bool HeadersWritten => default;
        public bool SupportsAsyncFlush => default;
        public IAsyncResult BeginFlush(AsyncCallback callback, object state) => default;
        public void EndFlush(IAsyncResult asyncResult) { }
        public Task FlushAsync() => default;
        public void DisableKernelCache() { }
        public void DisableUserCache() { }
        public HttpCookieCollection Cookies => default;
        public NameValueCollection Headers => default;
        public void AddFileDependency(string filename) { }
        public void AddFileDependencies(ArrayList filenames) { }
        public void AddFileDependencies(string[] filenames) { }
        public void AddCacheItemDependency(string cacheKey) { }
        public void AddCacheItemDependencies(ArrayList cacheKeys) { }
        public void AddCacheItemDependencies(string[] cacheKeys) { }
        public void AddCacheDependency(params CacheDependency[] dependencies) { }

        public static void RemoveOutputCacheItem(string path)
        {
            throw new PlatformNotSupportedException();
        }
 
        public static void RemoveOutputCacheItem(string path, string providerName)
        {
            throw new PlatformNotSupportedException();
        }
 
        public int StatusCode { get; set; }
        public int SubStatusCode { get; set; }
        public string StatusDescription { get; set; }
        public bool TrySkipIisCustomErrors { get; set; }
        public bool SuppressFormsAuthenticationRedirect { get; set; }
        public bool SuppressDefaultCacheControlHeader { get; set; }
        public bool BufferOutput { get; set; }
        public string ContentType { get; set; }
        public string Charset { get; set; }
        public Encoding ContentEncoding { get; set; }
        public Encoding HeaderEncoding { get; set; }
        public HttpCachePolicy Cache => default;
        public bool IsClientConnected => default;
        public CancellationToken ClientDisconnectedToken => default;
        public bool IsRequestBeingRedirected => default;
        public string RedirectLocation { get; set; }
        public void Close() { }
        public TextWriter Output { get; set; }
        public Stream OutputStream => default;
        public void BinaryWrite(byte[] buffer) { }
        public void Pics(string value) { }
        public Stream Filter { get; set; }
        public bool SuppressContent { get; set; }
        public void AppendHeader(string name, string value) { }
        public void AppendCookie(HttpCookie cookie) { }
        public void SetCookie(HttpCookie cookie) { }
        public void ClearHeaders() { }
        public void ClearContent() { }
        public void Clear() { }
        public void Flush() { }
        public ISubscriptionToken AddOnSendingHeaders(Action<HttpContext> callback) => default;
        public void AppendToLog(string param) { }
        public void Redirect(string url) { }
        public void Redirect(string url, bool endResponse) { }
        public void RedirectToRoute(object routeValues) { }
        public void RedirectToRoute(string routeName) { }
        public void RedirectToRoute(RouteValueDictionary routeValues) { }
        public void RedirectToRoute(string routeName, object routeValues) { }
        public void RedirectToRoute(string routeName, RouteValueDictionary routeValues) { }
        public void RedirectToRoutePermanent(object routeValues) { }
        public void RedirectToRoutePermanent(string routeName) { }
        public void RedirectToRoutePermanent(RouteValueDictionary routeValues) { }
        public void RedirectToRoutePermanent(string routeName, object routeValues) { }
        public void RedirectToRoutePermanent(string routeName, RouteValueDictionary routeValues) { }
        public void RedirectPermanent(string url) { }
        public void RedirectPermanent(string url, bool endResponse) { }
        public void Write(string s) { }
        public void Write(object obj) { }
        public void Write(char ch) { }
        public void Write(char[] buffer, int index, int count) { }
        public void WriteSubstitution(HttpResponseSubstitutionCallback callback) { }
        public void WriteFile(string filename) { }
        public void WriteFile(string filename, bool readIntoMemory) { }
        public void TransmitFile(string filename) { }
        public void TransmitFile(string filename, long offset, long length) { }
        public void WriteFile(string filename, long offset, long size) { }
        public void WriteFile(IntPtr fileHandle, long offset, long size) { }
        public void PushPromise(string path) { }
        public void PushPromise(string path, string method, NameValueCollection headers) { }
        public string Status { get; set; }
        public bool Buffer { get; set; }
        public void AddHeader(string name, string value) { }
        public void End() { }
        public int Expires { get; set; }
        public DateTime ExpiresAbsolute { get; set; }
        public string CacheControl { get; set; }
        public string ApplyAppPathModifier(string virtualPath) => default;
    }

    public abstract class HttpResponseBase
    {
        public virtual bool Buffer { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual bool BufferOutput { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual HttpCachePolicyBase Cache => throw new NotImplementedException();
        public virtual string CacheControl { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual String Charset { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual CancellationToken ClientDisconnectedToken => throw new NotImplementedException();
        public virtual Encoding ContentEncoding { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual string ContentType { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual HttpCookieCollection Cookies => throw new NotImplementedException();
        public virtual int Expires { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual DateTime ExpiresAbsolute { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual Stream Filter { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual NameValueCollection Headers => throw new NotImplementedException();
        public virtual bool HeadersWritten => throw new NotImplementedException();
        public virtual Encoding HeaderEncoding { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual bool IsClientConnected => throw new NotImplementedException();
        public virtual bool IsRequestBeingRedirected => throw new NotImplementedException();
        public virtual TextWriter Output { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual Stream OutputStream => throw new NotImplementedException();
        public virtual String RedirectLocation { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual string Status { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual int StatusCode { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual String StatusDescription { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual int SubStatusCode { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual bool SupportsAsyncFlush => throw new NotImplementedException();
        public virtual bool SuppressContent { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual bool SuppressDefaultCacheControlHeader { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual bool SuppressFormsAuthenticationRedirect { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual bool TrySkipIisCustomErrors { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual void AddCacheItemDependency(string cacheKey) => throw new NotImplementedException();
        public virtual void AddCacheItemDependencies(ArrayList cacheKeys) => throw new NotImplementedException();
        public virtual void AddCacheItemDependencies(string[] cacheKeys) => throw new NotImplementedException();
        public virtual void AddCacheDependency(params CacheDependency[] dependencies) => throw new NotImplementedException();
        public virtual void AddFileDependency(String filename) => throw new NotImplementedException();
        public virtual void AddFileDependencies(ArrayList filenames) => throw new NotImplementedException();
        public virtual void AddFileDependencies(string[] filenames) => throw new NotImplementedException();
        public virtual void AddHeader(String name, String value) => throw new NotImplementedException();
        public virtual ISubscriptionToken AddOnSendingHeaders(Action<HttpContextBase> callback) => throw new NotImplementedException();
        public virtual void AppendCookie(HttpCookie cookie) => throw new NotImplementedException();
        public virtual void AppendHeader(String name, String value) => throw new NotImplementedException();
        public virtual void AppendToLog(String param) => throw new NotImplementedException();
        public virtual string ApplyAppPathModifier(string virtualPath) => throw new NotImplementedException();
        public virtual IAsyncResult BeginFlush(AsyncCallback callback, Object state) => throw new NotImplementedException();
        public virtual void BinaryWrite(byte[] buffer) => throw new NotImplementedException();
        public virtual void Clear() => throw new NotImplementedException();
        public virtual void ClearContent() => throw new NotImplementedException();
        public virtual void ClearHeaders() => throw new NotImplementedException();
        public virtual void Close() => throw new NotImplementedException();
        public virtual void DisableKernelCache() => throw new NotImplementedException();
        public virtual void DisableUserCache() => throw new NotImplementedException();
        public virtual void End() => throw new NotImplementedException();
        public virtual void EndFlush(IAsyncResult asyncResult) => throw new NotImplementedException();
        public virtual void Flush() => throw new NotImplementedException();
        public virtual Task FlushAsync() => throw new NotImplementedException();
        public virtual void Pics(String value) => throw new NotImplementedException();
        public virtual void Redirect(String url) => throw new NotImplementedException();
        public virtual void Redirect(String url, bool endResponse) => throw new NotImplementedException();
        public virtual void RedirectToRoute(object routeValues) => throw new NotImplementedException();
        public virtual void RedirectToRoute(string routeName) => throw new NotImplementedException();
        public virtual void RedirectToRoute(RouteValueDictionary routeValues) => throw new NotImplementedException();
        public virtual void RedirectToRoute(string routeName, object routeValues) => throw new NotImplementedException();
        public virtual void RedirectToRoute(string routeName, RouteValueDictionary routeValues) => throw new NotImplementedException();
        public virtual void RedirectToRoutePermanent(object routeValues) => throw new NotImplementedException();
        public virtual void RedirectToRoutePermanent(string routeName) => throw new NotImplementedException();
        public virtual void RedirectToRoutePermanent(RouteValueDictionary routeValues) => throw new NotImplementedException();
        public virtual void RedirectToRoutePermanent(string routeName, object routeValues) => throw new NotImplementedException();
        public virtual void RedirectToRoutePermanent(string routeName, RouteValueDictionary routeValues) => throw new NotImplementedException();
        public virtual void RedirectPermanent(String url) => throw new NotImplementedException();
        public virtual void RedirectPermanent(String url, bool endResponse) => throw new NotImplementedException();
        public virtual void RemoveOutputCacheItem(string path) => throw new NotImplementedException();
        public virtual void RemoveOutputCacheItem(string path, string providerName) => throw new NotImplementedException();
        public virtual void SetCookie(HttpCookie cookie) => throw new NotImplementedException();
        public virtual void TransmitFile(string filename) => throw new NotImplementedException();
        public virtual void TransmitFile(string filename, long offset, long length) => throw new NotImplementedException();
        public virtual void Write(char ch) => throw new NotImplementedException();
        public virtual void Write(char[] buffer, int index, int count) => throw new NotImplementedException();
        public virtual void Write(Object obj) => throw new NotImplementedException();
        public virtual void Write(string s) => throw new NotImplementedException();
        public virtual void WriteFile(String filename) => throw new NotImplementedException();
        public virtual void WriteFile(String filename, bool readIntoMemory) => throw new NotImplementedException();
        public virtual void WriteFile(String filename, long offset, long size) => throw new NotImplementedException();
        public virtual void WriteFile(IntPtr fileHandle, long offset, long size) => throw new NotImplementedException();
        public virtual void WriteSubstitution(HttpResponseSubstitutionCallback callback) => throw new NotImplementedException();
        public virtual void PushPromise(string path) => throw new NotImplementedException();
        public virtual void PushPromise(string path, string method, NameValueCollection headers) => throw new NotImplementedException();
    }
    
    public sealed class HttpServerUtility
    {
        internal HttpServerUtility(HttpContext context)
        {
            throw new PlatformNotSupportedException();
        }
 
        internal HttpServerUtility(HttpApplication application)
        {
            throw new PlatformNotSupportedException();
        }
 
        public object CreateObject(string progID) => default;
        public object CreateObject(Type type) => default;
        public object CreateObjectFromClsid(string clsid) => default;
        public string MapPath(string path) => default;
        public Exception GetLastError() => default;
        public void ClearError() { }
        public void Execute(string path) { }
        public void Execute(string path, TextWriter writer) { }
        public void Execute(string path, bool preserveForm) { }
        public void Execute(string path, TextWriter writer, bool preserveForm) { }
        public void Execute(IHttpHandler handler, TextWriter writer, bool preserveForm) { }
        public void Transfer(string path, bool preserveForm) { }
        public void Transfer(string path) { }
        public void Transfer(IHttpHandler handler, bool preserveForm) { }
        public void TransferRequest(string path) { }
        public void TransferRequest(string path, bool preserveForm) { }
        public void TransferRequest(string path, bool preserveForm, string method, NameValueCollection headers) { }
        public void TransferRequest(string path, bool preserveForm, string method, NameValueCollection headers, bool preserveUser) { }
        public string MachineName => default;
        public int ScriptTimeout { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string HtmlDecode(string s) => default;
        public void HtmlDecode(string s, TextWriter output) { }
        public string HtmlEncode(string s) => default;
        public void HtmlEncode(string s, TextWriter output) { }
        public string UrlEncode(string s) => default;
        public string UrlPathEncode(string s) => default;
        public void UrlEncode(string s, TextWriter output) { }
        public string UrlDecode(string s) => default;
        public void UrlDecode(string s, TextWriter output) { }

        public static string UrlTokenEncode(byte [] input)
        {
            throw new PlatformNotSupportedException();
        }
 
        public static byte[] UrlTokenDecode(string input)
        {
            throw new PlatformNotSupportedException();
        }
    }
 
    public abstract class HttpServerUtilityBase
    {
        public virtual string MachineName => throw new NotImplementedException();
        public virtual int ScriptTimeout { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual void ClearError() => throw new NotImplementedException();
        public virtual object CreateObject(string progID) => throw new NotImplementedException();
        public virtual object CreateObject(Type type) => throw new NotImplementedException();
        public virtual object CreateObjectFromClsid(string clsid) => throw new NotImplementedException();
        public virtual void Execute(string path) => throw new NotImplementedException();
        public virtual void Execute(string path, TextWriter writer) => throw new NotImplementedException();
        public virtual void Execute(string path, bool preserveForm) => throw new NotImplementedException();
        public virtual void Execute(string path, TextWriter writer, bool preserveForm) => throw new NotImplementedException();
        public virtual void Execute(IHttpHandler handler, TextWriter writer, bool preserveForm) => throw new NotImplementedException();
        public virtual Exception GetLastError() => throw new NotImplementedException();
        public virtual string HtmlDecode(string s) => throw new NotImplementedException();
        public virtual void HtmlDecode(string s, TextWriter output) => throw new NotImplementedException();
        public virtual string HtmlEncode(string s) => throw new NotImplementedException();
        public virtual void HtmlEncode(string s, TextWriter output) => throw new NotImplementedException();
        public virtual string MapPath(string path) => throw new NotImplementedException();
        public virtual void Transfer(string path, bool preserveForm) => throw new NotImplementedException();
        public virtual void Transfer(string path) => throw new NotImplementedException();
        public virtual void Transfer(IHttpHandler handler, bool preserveForm) => throw new NotImplementedException();
        public virtual void TransferRequest(string path) => throw new NotImplementedException();
        public virtual void TransferRequest(string path, bool preserveForm) => throw new NotImplementedException();
        public virtual void TransferRequest(string path, bool preserveForm, string method, NameValueCollection headers) => throw new NotImplementedException();
        public virtual void TransferRequest(string path, bool preserveForm, string method, NameValueCollection headers, bool preserveUser) => throw new NotImplementedException();
        public virtual string UrlDecode(string s) => throw new NotImplementedException();
        public virtual void UrlDecode(string s, TextWriter output) => throw new NotImplementedException();
        public virtual string UrlEncode(string s) => throw new NotImplementedException();
        public virtual void UrlEncode(string s, TextWriter output) => throw new NotImplementedException();
        public virtual string UrlPathEncode(string s) => throw new NotImplementedException();
        public virtual byte[] UrlTokenDecode(string input) => throw new NotImplementedException();
        public virtual string UrlTokenEncode(byte[] input) => throw new NotImplementedException();
    }
    
    public abstract class HttpSessionStateBase : ICollection, IEnumerable
    {
        public virtual int CodePage { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual HttpSessionStateBase Contents => throw new NotImplementedException();
        public virtual HttpCookieMode CookieMode => throw new NotImplementedException();
        public virtual bool IsCookieless => throw new NotImplementedException();
        public virtual bool IsNewSession => throw new NotImplementedException();
        public virtual bool IsReadOnly => throw new NotImplementedException();
        public virtual NameObjectCollectionBase.KeysCollection Keys => throw new NotImplementedException();
        public virtual int LCID { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual SessionStateMode Mode => throw new NotImplementedException();
        public virtual string SessionID => throw new NotImplementedException();
        public virtual HttpStaticObjectsCollectionBase StaticObjects => throw new NotImplementedException();
        public virtual int Timeout { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual object this[int index] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual object this[string name] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual void Abandon() => throw new NotImplementedException();
        public virtual void Add(string name, object value) => throw new NotImplementedException();
        public virtual void Clear() => throw new NotImplementedException();
        public virtual void Remove(string name) => throw new NotImplementedException();
        public virtual void RemoveAll() => throw new NotImplementedException();
        public virtual void RemoveAt(int index) => throw new NotImplementedException();
        public virtual void CopyTo(Array array, int index) => throw new NotImplementedException();
        public virtual int Count => throw new NotImplementedException();
        public virtual bool IsSynchronized => throw new NotImplementedException();
        public virtual object SyncRoot => throw new NotImplementedException();
        public virtual IEnumerator GetEnumerator() => throw new NotImplementedException();
    }
    
    public sealed class HttpStaticObjectsCollection : ICollection
    {
        public HttpStaticObjectsCollection()
        {
            throw new PlatformNotSupportedException();
        }
 
        public bool NeverAccessed => default;
        public object this[string name] => default;
        public object GetObject(string name) => default;
        public int Count => default;
        public IEnumerator GetEnumerator() => default;
        public void CopyTo(Array array, int index) { }
        public object SyncRoot => default;
        public bool IsReadOnly => default;
        public bool IsSynchronized => default;
        public void Serialize(BinaryWriter writer) { }

        public static HttpStaticObjectsCollection Deserialize(BinaryReader reader)
        {
            throw new PlatformNotSupportedException();
        }
    }

    public abstract class HttpStaticObjectsCollectionBase : ICollection, IEnumerable
    {
        public virtual int Count => throw new NotImplementedException();
        public virtual bool IsReadOnly => throw new NotImplementedException();
        public virtual bool IsSynchronized => throw new NotImplementedException();
        public virtual object this[string name] => throw new NotImplementedException();
        public virtual bool NeverAccessed => throw new NotImplementedException();
        public virtual object SyncRoot => throw new NotImplementedException();
        public virtual void CopyTo(Array array, int index) => throw new NotImplementedException();
        public virtual IEnumerator GetEnumerator() => throw new NotImplementedException();
        public virtual object GetObject(string name) => throw new NotImplementedException();
        public virtual void Serialize(BinaryWriter writer) => throw new NotImplementedException();
    }

    public enum HttpValidationStatus
    {
        Invalid = 1,
        IgnoreThisRequest = 2,
        Valid = 3,
    }

    public abstract class HttpWorkerRequest
    {
        protected HttpWorkerRequest()
        {
            throw new PlatformNotSupportedException();
        }
 
        public const int HeaderCacheControl  = 0;
        public const int HeaderConnection  = 1;
        public const int HeaderDate   = 2;
        public const int HeaderKeepAlive  = 3;
        public const int HeaderPragma  = 4;
        public const int HeaderTrailer  = 5; 
        public const int HeaderTransferEncoding = 6;
        public const int HeaderUpgrade  = 7;
        public const int HeaderVia   = 8;
        public const int HeaderWarning  = 9;
        public const int HeaderAllow   = 10;
        public const int HeaderContentLength  = 11;
        public const int HeaderContentType  = 12;
        public const int HeaderContentEncoding = 13;
        public const int HeaderContentLanguage = 14;
        public const int HeaderContentLocation = 15;
        public const int HeaderContentMd5  = 16;
        public const int HeaderContentRange  = 17;
        public const int HeaderExpires  = 18;
        public const int HeaderLastModified  = 19;
        public const int HeaderAccept  = 20;
        public const int HeaderAcceptCharset  = 21;
        public const int HeaderAcceptEncoding = 22;
        public const int HeaderAcceptLanguage = 23;
        public const int HeaderAuthorization  = 24;
        public const int HeaderCookie  = 25;
        public const int HeaderExpect  = 26;
        public const int HeaderFrom   = 27;
        public const int HeaderHost   = 28;
        public const int HeaderIfMatch  = 29;
        public const int HeaderIfModifiedSince = 30;
        public const int HeaderIfNoneMatch  = 31;
        public const int HeaderIfRange  = 32;
        public const int HeaderIfUnmodifiedSince = 33;
        public const int HeaderMaxForwards  = 34;
        public const int HeaderProxyAuthorization = 35;
        public const int HeaderReferer  = 36;
        public const int HeaderRange   = 37;
        public const int HeaderTe   = 38;
        public const int HeaderUserAgent  = 39;
        public const int RequestHeaderMaximum = 40;
        public const int HeaderAcceptRanges  = 20;
        public const int HeaderAge   = 21;
        public const int HeaderEtag   = 22;
        public const int HeaderLocation  = 23;
        public const int HeaderProxyAuthenticate = 24;
        public const int HeaderRetryAfter  = 25;
        public const int HeaderServer  = 26;
        public const int HeaderSetCookie  = 27;
        public const int HeaderVary   = 28;
        public const int HeaderWwwAuthenticate = 29;
        public const int ResponseHeaderMaximum = 30;
        public const int ReasonResponseCacheMiss = 0;
        public const int ReasonFileHandleCacheMiss = 1;
        public const int ReasonCachePolicy  = 2;
        public const int ReasonCacheSecurity  = 3;
        public const int ReasonClientDisconnect = 4;
        public const int ReasonDefault  = ReasonResponseCacheMiss;

        public abstract String GetUriPath();
        public abstract String GetQueryString();
        public abstract String GetRawUrl(); 
        public abstract String GetHttpVerbName();
        public abstract String GetHttpVersion();
        public abstract String GetRemoteAddress();
        public abstract int GetRemotePort();
        public abstract String GetLocalAddress();
        public abstract int GetLocalPort(); 

        public virtual byte[] GetQueryStringRawBytes() => default;
        public virtual String GetRemoteName() => default;
        public virtual String GetServerName() => default;
        public virtual long GetConnectionID() => default;
        public virtual long GetUrlContextID() => default;
        public virtual String GetAppPoolID() => default;
        public virtual int GetRequestReason() => default;
        public virtual IntPtr GetUserToken() => default;
        public virtual IntPtr GetVirtualPathToken() => default;
        public virtual bool IsSecure() => default;
        public virtual String GetProtocol() => default;
        public virtual String GetFilePath() => default;
        public virtual String GetFilePathTranslated() => default;
        public virtual String GetPathInfo() => default;
        public virtual String GetAppPath() => default;
        public virtual String GetAppPathTranslated() => default;
        public virtual int GetPreloadedEntityBodyLength() => default;
        public virtual int GetPreloadedEntityBody(byte[] buffer, int offset) => default;
        public virtual byte[] GetPreloadedEntityBody() => default;
        public virtual bool IsEntireEntityBodyIsPreloaded() => default;
        public virtual int GetTotalEntityBodyLength() => default;
        public virtual int ReadEntityBody(byte[] buffer, int size) => default;
        public virtual int ReadEntityBody(byte[] buffer, int offset, int size) => default;
        public virtual bool SupportsAsyncFlush => default;
        public virtual IAsyncResult BeginFlush(AsyncCallback callback, Object state) => default;
        public virtual void EndFlush(IAsyncResult asyncResult) { }
        public virtual bool SupportsAsyncRead => default;
        public virtual IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, Object state) => default;
        public virtual int EndRead(IAsyncResult asyncResult) => default;
        public virtual String GetKnownRequestHeader(int index) => default;
        public virtual String GetUnknownRequestHeader(String name) => default;
        public virtual String[][] GetUnknownRequestHeaders() => default;
        public virtual String GetServerVariable(String name) => default;
        public virtual long GetBytesRead() => default;
        public virtual String MapPath(String virtualPath) => default;
        public virtual String MachineConfigPath => default;
        public virtual String RootWebConfigPath => default;
        public virtual String MachineInstallDirectory => default;
        public virtual Guid RequestTraceIdentifier => default;
        public abstract void SendStatus(int statusCode, String statusDescription);
        public abstract void SendKnownResponseHeader(int index, String value);
        public abstract void SendUnknownResponseHeader(String name, String value);
        public abstract void SendResponseFromMemory(byte[] data, int length);
        public virtual void SendResponseFromMemory(IntPtr data, int length) { }
        public abstract void SendResponseFromFile(String filename, long offset, long length);
        public abstract void SendResponseFromFile(IntPtr handle, long offset, long length);
        public abstract void FlushResponse(bool finalFlush);
        public abstract void EndOfRequest();
        public delegate void EndOfSendNotification(HttpWorkerRequest wr, Object extraData);
        public virtual void SetEndOfSendNotification(EndOfSendNotification callback, Object extraData) { }
        public virtual void SendCalculatedContentLength(int contentLength) { }
        public virtual void SendCalculatedContentLength(long contentLength) { }
        public virtual bool HeadersSent() => default;
        public virtual bool IsClientConnected() => default;
        public virtual void CloseConnection() { }
        public virtual byte[] GetClientCertificate() => default;
        public virtual DateTime GetClientCertificateValidFrom() => default;
        public virtual DateTime GetClientCertificateValidUntil() => default;
        public virtual byte[] GetClientCertificateBinaryIssuer() => default;
        public virtual int GetClientCertificateEncoding() => default;
        public virtual byte[] GetClientCertificatePublicKey() => default;
        public bool HasEntityBody() => default;

        public static String GetStatusDescription(int code)
        {
            throw new PlatformNotSupportedException();
        }
 
        public static int GetKnownRequestHeaderIndex(String header)
        {
            throw new PlatformNotSupportedException();
        }

        public static String GetKnownRequestHeaderName(int index)
        {
            throw new PlatformNotSupportedException();
        }
 
        public static int GetKnownResponseHeaderIndex(String header)
        {
            throw new PlatformNotSupportedException();
        }
 
        public static String GetKnownResponseHeaderName(int index)
        {
            throw new PlatformNotSupportedException();
        }
    }
    
    public enum ReadEntityBodyMode
    {
        None,
        Classic,
        Bufferless,
        Buffered,
    }
    
    [Flags]
    public enum RequestNotification
    {
        BeginRequest = 0x00000001,
        AuthenticateRequest = 0x00000002,
        AuthorizeRequest = 0x00000004,
        ResolveRequestCache = 0x00000008,
        MapRequestHandler = 0x00000010,
        AcquireRequestState = 0x00000020,
        PreExecuteRequestHandler = 0x00000040,
        ExecuteRequestHandler = 0x00000080,
        ReleaseRequestState = 0x00000100,
        UpdateRequestCache = 0x00000200,
        LogRequest = 0x00000400,
        EndRequest = 0x00000800,
        SendResponse = 0x20000000
    }
    
    public enum SameSiteMode
    {
        None,
        Lax,
        Strict,
    }

    public sealed class TraceContext
    {
        public TraceContext(HttpContext context)
        {
            throw new PlatformNotSupportedException();
        }
 
        public TraceMode TraceMode { get; set; }
        public bool IsEnabled { get; set; }
#pragma warning disable CS0067
        public event TraceContextEventHandler TraceFinished;
#pragma warning restore CS0067
        public void Write(string message) { }
        public void Write(string category, string message) { }
        public void Write(string category, string message, Exception errorInfo) { }
        public void Warn(string message) { }
        public void Warn(string category, string message) { }
        public void Warn(string category, string message, Exception errorInfo) { }
    }

    public sealed class TraceContextEventArgs : EventArgs
    {
        public TraceContextEventArgs(ICollection records)
        {
            TraceRecords = records;
        }
 
        public ICollection TraceRecords { get; }
    }

    public enum TraceMode
    {
        SortByTime = 0,
        SortByCategory = 1,
        Default = 2,
    }
    
    public sealed class UnvalidatedRequestValues
    {
        internal UnvalidatedRequestValues(HttpRequest request)
        {
            throw new PlatformNotSupportedException();
        }
 
        public NameValueCollection Form => default;
        public NameValueCollection QueryString => default;
        public NameValueCollection Headers => default;
        public HttpCookieCollection Cookies => default;
        public HttpFileCollection Files => default;
        public string RawUrl => default;
        public string Path => default;
        public string PathInfo => default;
        public string this[string field] => default;
        public Uri Url => default;
    }

    public abstract class UnvalidatedRequestValuesBase
    {
        public virtual NameValueCollection Form => throw new NotImplementedException();
        public virtual NameValueCollection QueryString => throw new NotImplementedException();
        public virtual NameValueCollection Headers => throw new NotImplementedException();
        public virtual HttpCookieCollection Cookies => throw new NotImplementedException();
        public virtual HttpFileCollectionBase Files => throw new NotImplementedException();
        public virtual string RawUrl => throw new NotImplementedException();
        public virtual string Path => throw new NotImplementedException();
        public virtual string PathInfo => throw new NotImplementedException();
        public virtual string this[string field] => throw new NotImplementedException();
        public virtual Uri Url => throw new NotImplementedException();
    }
}

namespace System.Web.Caching
{
    public sealed class Cache : IEnumerable
    {
        public static readonly DateTime NoAbsoluteExpiration = DateTime.MaxValue;
        public static readonly TimeSpan NoSlidingExpiration = TimeSpan.Zero;

        // As long as the ctor throws, all of the instance members can just `=> default;`
        public Cache()
        {
            throw new PlatformNotSupportedException();
        }

        public int Count => default;
        IEnumerator IEnumerable.GetEnumerator() => default;
        public IDictionaryEnumerator GetEnumerator() => default;

        public object this[string key]
        {
            get { return null; } set { }
        }
 
        public object Get(string key) => default;
        public void Insert(string key, object value) { }
        public void Insert(string key, object value, CacheDependency dependencies) { }
        public void Insert(string key, object value, CacheDependency dependencies, DateTime absoluteExpiration, TimeSpan slidingExpiration) { }
 
        public void Insert(
            string key,
            object value,
            CacheDependency dependencies,
            DateTime absoluteExpiration,
            TimeSpan slidingExpiration,
            CacheItemPriority priority,
            CacheItemRemovedCallback onRemoveCallback) { }
 
        public void Insert(
            string key,
            object value,
            CacheDependency dependencies,
            DateTime absoluteExpiration,
            TimeSpan slidingExpiration,
            CacheItemUpdateCallback onUpdateCallback) { }
 
        public object Add(
            string key,
            object value,
            CacheDependency dependencies,
            DateTime absoluteExpiration,
            TimeSpan slidingExpiration,
            CacheItemPriority priority,
            CacheItemRemovedCallback onRemoveCallback) => throw new PlatformNotSupportedException();
 
        public object Remove(string key) => throw new PlatformNotSupportedException();

        public long EffectivePrivateBytesLimit => default;
        public long EffectivePercentagePhysicalMemoryLimit => default;
    }

    public class CacheDependency : IDisposable
    {
        protected CacheDependency()
        {
            throw new PlatformNotSupportedException();
        }
 
        public CacheDependency(string filename)
        {
            throw new PlatformNotSupportedException();
        }
 
        public CacheDependency(string filename, DateTime start)
        {
            throw new PlatformNotSupportedException();
        }
 
        public CacheDependency(string[] filenames)
        {
            throw new PlatformNotSupportedException();
        }
 
        public CacheDependency(string[] filenames, DateTime start)
        {
            throw new PlatformNotSupportedException();
        }
 
        public CacheDependency(string[] filenames, string[] cachekeys)
        {
            throw new PlatformNotSupportedException();
        }
 
        public CacheDependency(string[] filenames, string[] cachekeys, DateTime start)
        {
            throw new PlatformNotSupportedException();
        }

        public CacheDependency(string[] filenames, string[] cachekeys, CacheDependency dependency)
        {
            throw new PlatformNotSupportedException();
        }
 
        public CacheDependency(string[] filenames, string[] cachekeys, CacheDependency dependency, DateTime start)
        {
            throw new PlatformNotSupportedException();
        }

        public void Dispose() { }
        protected internal void FinishInit() { }
        protected virtual void DependencyDispose() { }
        public bool TakeOwnership() => default;
        public bool HasChanged => default;
        public DateTime UtcLastModified => default;
        protected void SetUtcLastModified(DateTime utcLastModified) { }
        public void KeepDependenciesAlive() { }
        public void SetCacheDependencyChanged(Action<object, EventArgs> dependencyChangedAction) { }
        public virtual string GetUniqueID() => null;
        protected void NotifyDependencyChanged(object sender, EventArgs e) { }
        public void ItemRemoved() { }
        public virtual string[] GetFileDependencies() => null;
    }

    public enum CacheItemPriority
    {
        Low = 1,
        BelowNormal,
        Normal,
        AboveNormal,
        High,
        NotRemovable,
        Default = Normal,
    }

    public delegate void CacheItemRemovedCallback(string key, object value, CacheItemRemovedReason reason);

    public enum CacheItemRemovedReason
    {
        Removed = 1,
        Expired,
        Underused,
        DependencyChanged,
    }

    public delegate void CacheItemUpdateCallback(
        string key,
        CacheItemUpdateReason reason,
        out object expensiveObject,
        out CacheDependency dependency,
        out DateTime absoluteExpiration,
        out TimeSpan slidingExpiration);
    
    public enum CacheItemUpdateReason
    {
        Expired = 1,
        DependencyChanged,
    }
}

namespace System.Web.Configuration
{
    public interface IConfigMapPath
    {
        string GetMachineConfigFilename();
        string GetRootWebConfigFilename();
        void GetPathConfigFilename(string siteID, string path, out string directory, out string baseName);
        void GetDefaultSiteNameAndID(out string siteName, out string siteID);
        void ResolveSiteArgument(string siteArgument, out string siteName, out string siteID);
        string MapPath(string siteID, string path);
        string GetAppPathForPath(string siteID, string path);
    }
    
    public interface IConfigMapPathFactory
    {
        IConfigMapPath Create(string virtualPath, string physicalPath);
    }

    [Flags]
    public enum AsyncPreloadModeFlags
    {
        None            = 0x00,
        Form            = 0x01,
        FormMultiPart   = 0x02,
        NonForm         = 0x04,
        AllFormTypes    = Form | FormMultiPart,
	    All             = AllFormTypes | NonForm,
    }

    public class HttpCapabilitiesBase : IFilterResolutionService
    {
        public HttpCapabilitiesBase()
        {
            throw new PlatformNotSupportedException();
        }

        public static HttpCapabilitiesProvider BrowserCapabilitiesProvider { get; set; }
        public bool UseOptimizedCacheKey => default;
        public void DisableOptimizedCacheKey() { }

        public static HttpCapabilitiesBase GetConfigCapabilities(string configKey, HttpRequest request)
        {
            throw new PlatformNotSupportedException();
        }
 
        public virtual string this[string key] => default;
        public HtmlTextWriter CreateHtmlTextWriter(TextWriter w) => default;
        protected virtual void Init() { }
        public IDictionary Capabilities { get; set; }
        public IDictionary Adapters => default;
        public string HtmlTextWriter { get; set; }
        public string Id => default;
        public ArrayList Browsers => default;
        public Version ClrVersion => default;
        public Version[] GetClrVersions() => default;
        public string Type => default;
        public string Browser => default;
        public string Version => default;
        public int MajorVersion => default;
        public string MinorVersionString => default;
        public double MinorVersion => default;
        public string Platform => default;
        public Type TagWriter => default;
        public Version EcmaScriptVersion => default;
        public Version MSDomVersion => default;
        public Version W3CDomVersion => default;
        public bool Beta => default;
        public bool Crawler => default;
        public bool AOL => default;
        public bool Win16 => default;
        public bool Win32 => default;
        public bool Frames => default;
        public bool RequiresControlStateInSession => default;
        public bool Tables => default;
        public bool Cookies => default;
        public bool VBScript => default;
        public bool JavaScript => default;
        public bool JavaApplets => default;
        public Version JScriptVersion => default;
        public bool ActiveXControls => default;
        public bool BackgroundSounds => default;
        public bool CDF => default;
        public virtual string MobileDeviceManufacturer => default;
        public virtual string MobileDeviceModel => default;
        public virtual string GatewayVersion => default;
        public virtual int GatewayMajorVersion => default;
        public virtual double GatewayMinorVersion => default;
        public virtual string PreferredRenderingType => default;
        public virtual string PreferredRequestEncoding => default;
        public virtual string PreferredResponseEncoding => default;
        public virtual string PreferredRenderingMime => default;
        public virtual string PreferredImageMime => default;
        public virtual int ScreenCharactersWidth => default;
        public virtual int ScreenCharactersHeight => default;
        public virtual int ScreenPixelsWidth => default;
        public virtual int ScreenPixelsHeight => default;
        public virtual int ScreenBitDepth => default;
        public virtual bool IsColor => default;
        public virtual string InputType => default;
        public virtual int NumberOfSoftkeys => default;
        public virtual int MaximumSoftkeyLabelLength => default;
        public virtual bool CanInitiateVoiceCall => default;
        public virtual bool CanSendMail => default;
        public virtual bool HasBackButton => default;
        public virtual bool RendersWmlDoAcceptsInline => default;
        public virtual bool RendersWmlSelectsAsMenuCards => default;
        public virtual bool RendersBreaksAfterWmlAnchor => default;
        public virtual bool RendersBreaksAfterWmlInput => default;
        public virtual bool RendersBreakBeforeWmlSelectAndInput => default;
        public virtual bool RequiresPhoneNumbersAsPlainText => default;
        public virtual bool RequiresUrlEncodedPostfieldValues => default;
        public virtual string RequiredMetaTagNameValue => default;
        public virtual bool RendersBreaksAfterHtmlLists => default;
        public virtual bool RequiresUniqueHtmlInputNames => default;
        public virtual bool RequiresUniqueHtmlCheckboxNames => default;
        public virtual bool SupportsCss => default;
        public virtual bool HidesRightAlignedMultiselectScrollbars => default;
        public virtual bool IsMobileDevice => default;
        public virtual bool RequiresAttributeColonSubstitution => default;
        public virtual bool CanRenderOneventAndPrevElementsTogether => default;
        public virtual bool CanRenderInputAndSelectElementsTogether => default;
        public virtual bool CanRenderAfterInputOrSelectElement => default;
        public virtual bool CanRenderPostBackCards => default;
        public virtual bool CanRenderMixedSelects => default;
        public virtual bool CanCombineFormsInDeck => default;
        public virtual bool CanRenderSetvarZeroWithMultiSelectionList => default;
        public virtual bool SupportsImageSubmit => default;
        public virtual bool RequiresUniqueFilePathSuffix => default;
        public virtual bool RequiresNoBreakInFormatting => default;
        public virtual bool RequiresLeadingPageBreak => default;
        public virtual bool SupportsSelectMultiple => default;
        public virtual bool SupportsBold => default;
        public virtual bool SupportsItalic => default;
        public virtual bool SupportsFontSize => default;
        public virtual bool SupportsFontName => default;
        public virtual bool SupportsFontColor => default;
        public virtual bool SupportsBodyColor => default;
        public virtual bool SupportsDivAlign => default;
        public virtual bool SupportsDivNoWrap => default;
        public virtual bool RequiresContentTypeMetaTag => default;
        public virtual bool RequiresDBCSCharacter => default;
        public virtual bool RequiresHtmlAdaptiveErrorReporting => default;
        public virtual bool RequiresOutputOptimization => default;
        public virtual bool SupportsAccesskeyAttribute => default;
        public virtual bool SupportsInputIStyle => default;
        public virtual bool SupportsInputMode => default;
        public virtual bool SupportsIModeSymbols => default;
        public virtual bool SupportsJPhoneSymbols => default;
        public virtual bool SupportsJPhoneMultiMediaAttributes => default;
        public virtual int MaximumRenderedPageSize => default;
        public virtual bool RequiresSpecialViewStateEncoding => default;
        public virtual bool SupportsQueryStringInFormAction => default;
        public virtual bool SupportsCacheControlMetaTag => default;
        public virtual bool SupportsUncheck => default;
        public virtual bool CanRenderEmptySelects => default;
        public virtual bool SupportsRedirectWithCookie => default;
        public virtual bool SupportsEmptyStringInCookieValue => default;
        public virtual int DefaultSubmitButtonLimit => default;
        public virtual bool SupportsXmlHttp => default;
        public virtual bool SupportsCallback => default;
        public virtual int MaximumHrefLength => default;
        public bool IsBrowser(string browserName) => default;
        public void AddBrowser(string browserName) { }
 
        bool IFilterResolutionService.EvaluateFilter(string filterName) => default;
        int IFilterResolutionService.CompareFilters(string filter1, string filter2) => default;
    }

    public abstract class HttpCapabilitiesProvider
    {
        public abstract HttpBrowserCapabilities GetBrowserCapabilities(HttpRequest request);
    }
}

namespace System.Web.Hosting
{
    public interface IApplicationHost
    {
        string GetVirtualPath();
        string GetPhysicalPath();
        IConfigMapPathFactory GetConfigMapPathFactory();
        IntPtr GetConfigToken();
        string GetSiteName();
        string GetSiteID();
        void MessageReceived();
    }

    public interface IApplicationMonitor : IDisposable
    {
        void Start();
        void Stop();
    }

    public sealed class ApplicationMonitors
    {
        private IApplicationMonitor _memoryMonitor;

        internal ApplicationMonitors() { }

        public IApplicationMonitor MemoryMonitor
        {
            get { return _memoryMonitor; }

            set
            {
                if (_memoryMonitor != null && _memoryMonitor != value)
                {
                    _memoryMonitor.Stop();
                    _memoryMonitor.Dispose();
                }

                _memoryMonitor = value;

                if (_memoryMonitor != null)
                {
                    _memoryMonitor.Start();
                }
            }
        }
    }
    
    public sealed class HostingEnvironment : MarshalByRefObject
    {
        public HostingEnvironment()
        {
            throw new PlatformNotSupportedException();
        }

        public override object InitializeLifetimeService() => null;

        public static Exception InitializationException => null;

        public static void QueueBackgroundWorkItem(Action<CancellationToken> workItem)
        {
            if (workItem == null)
                throw new ArgumentNullException(nameof(workItem));

            throw new InvalidOperationException();
        }

        public static void QueueBackgroundWorkItem(Func<CancellationToken, Task> workItem) {
            if (workItem == null)
                throw new ArgumentNullException(nameof(workItem));

            throw new InvalidOperationException();
        }

#pragma warning disable CS0067
        public static event EventHandler StopListening;
#pragma warning restore CS0067

        public static void IncrementBusyCount() { }
        public static void DecrementBusyCount() { }
        public static void MessageReceived() { }

        public static bool InClientBuildManager => false;
        public static bool IsHosted => false;

        public static IApplicationHost ApplicationHost => null;
        public static ApplicationMonitors ApplicationMonitors => null;
        public static string ApplicationID => null;
        public static string ApplicationPhysicalPath => null;
        public static string ApplicationVirtualPath => null;
        public static string SiteName => null;
        public static bool IsDevelopmentEnvironment => false;
        public static Cache Cache => throw new PlatformNotSupportedException();
        public static ApplicationShutdownReason ShutdownReason => throw new PlatformNotSupportedException();

        public static void InitiateShutdown() { }

        public static string MapPath(string virtualPath) => null;

        public static IDisposable Impersonate() => throw new PlatformNotSupportedException();
        public static IDisposable Impersonate(IntPtr token) => throw new PlatformNotSupportedException();
        public static IDisposable Impersonate(IntPtr userToken, string virtualPath) => throw new PlatformNotSupportedException();

        public static IDisposable SetCultures() => throw new PlatformNotSupportedException();
        public static IDisposable SetCultures(string virtualPath) => throw new PlatformNotSupportedException();

        public static VirtualPathProvider VirtualPathProvider => null;
        public static void RegisterVirtualPathProvider(VirtualPathProvider virtualPathProvider) => throw new InvalidOperationException();

        public static int MaxConcurrentRequestsPerCPU => throw new PlatformNotSupportedException();
        public static int MaxConcurrentThreadsPerCPU => throw new PlatformNotSupportedException();
    }

    public abstract class VirtualDirectory : VirtualFileBase
    {
        protected VirtualDirectory(string virtualPath)
        {
            throw new PlatformNotSupportedException();
        }

        public override bool IsDirectory => true;
        public abstract IEnumerable Directories { get; }
        public abstract IEnumerable Files { get; }
        public abstract IEnumerable Children { get; }
    }

    public abstract class VirtualFile : VirtualFileBase
    {
        protected VirtualFile(string virtualPath)
        {
            throw new PlatformNotSupportedException();
        }

        public override bool IsDirectory => false;
        public abstract Stream Open();
    }
 
    public abstract class VirtualFileBase : MarshalByRefObject
    {
        public override object InitializeLifetimeService() => null;
        public virtual string Name => throw new PlatformNotSupportedException();
        public string VirtualPath => throw new PlatformNotSupportedException();
        public abstract bool IsDirectory { get; }
    }

    public abstract class VirtualPathProvider : MarshalByRefObject
    {
        public override object InitializeLifetimeService() => null;
        protected virtual void Initialize() { }
        protected internal VirtualPathProvider Previous => null;
        public virtual string GetFileHash(string virtualPath, IEnumerable virtualPathDependencies) => null;
        public virtual CacheDependency GetCacheDependency(string virtualPath, IEnumerable virtualPathDependencies, DateTime utcStart) => null;
        public virtual bool FileExists(string virtualPath) => false;
        public virtual bool DirectoryExists(string virtualDir) => false;
        public virtual VirtualFile GetFile(string virtualPath) => null;
        public virtual VirtualDirectory GetDirectory(string virtualDir) => null;
        public virtual string GetCacheKey(string virtualPath) => null;
        public virtual string CombineVirtualPaths(string basePath, string relativePath) => throw new PlatformNotSupportedException();
        public static Stream OpenFile(string virtualPath) => null;
    }
}

namespace System.Web.Instrumentation
{
    public class PageExecutionContext
    {
        public bool IsLiteral { get; set; }
        public int Length { get; set; }
        public int StartPosition { get; set; }
        public TextWriter TextWriter { get; set; }
        public string VirtualPath { get; set; }
    }

    public abstract class PageExecutionListener
    {
        public abstract void BeginContext(PageExecutionContext context);
        public abstract void EndContext(PageExecutionContext context);
    }
    
    public sealed class PageInstrumentationService
    {
        public static bool IsEnabled => false;
 
        public PageInstrumentationService()
        {
            throw new PlatformNotSupportedException();
        }

        public IList<PageExecutionListener> ExecutionListeners => default;
    }
}


namespace System.Web.Profile
{
    public class ProfileBase : SettingsBase
    {
        public override object this[string propertyName] { get { throw new PlatformNotSupportedException(); } set { throw new PlatformNotSupportedException(); } }
 
        public object GetPropertyValue(string propertyName) => throw new PlatformNotSupportedException();
        public void SetPropertyValue(string propertyName, object propertyValue) { }
        public ProfileGroupBase GetProfileGroup(string groupName) => throw new PlatformNotSupportedException();
        
        public ProfileBase() {
            throw new PlatformNotSupportedException();
        }
 
        public void Initialize(string username, bool isAuthenticated) { }
        public override void Save() { }
        public string UserName => default;
        public bool IsAnonymous => default;
        public bool IsDirty => default;
        public DateTime LastActivityDate => default;
        public DateTime LastUpdatedDate => default;
        
        public static ProfileBase Create(string username) => throw new PlatformNotSupportedException();
        public static ProfileBase Create(string username, bool isAuthenticated) => throw new PlatformNotSupportedException();
        public static new SettingsPropertyCollection Properties => throw new PlatformNotSupportedException();
    }

    public class ProfileGroupBase
    {
        private string _MyName;
        private ProfileBase _Parent;

        public object this[string propertyName]
        {
            get { return _Parent[_MyName + propertyName];}
            set { _Parent[_MyName + propertyName] = value; }
        }
 
        public object GetPropertyValue(string propertyName)
        {
            return _Parent[_MyName + propertyName];
        }
 
        public void SetPropertyValue(string propertyName, object propertyValue)
        {
            _Parent[_MyName + propertyName] = propertyValue;
        }
 
        public ProfileGroupBase()
        {
        }
 
        public void Init(ProfileBase parent, string myName)
        {
            if (_Parent == null)
            {
                _Parent = parent;
                _MyName = myName + ".";
            }
        }
    }
}

namespace System.Web.Routing
{
    public interface IRouteHandler
    {
        IHttpHandler GetHttpHandler(RequestContext requestContext);
    }
    
    public class RequestContext
    {
        public RequestContext()
        {
            throw new PlatformNotSupportedException();
        }
 
        public RequestContext(HttpContextBase httpContext, RouteData routeData)
        {
            throw new PlatformNotSupportedException();
        }
 
        public virtual HttpContextBase HttpContext { get; set; }
        public virtual RouteData RouteData { get; set; }
    }

    public abstract class RouteBase
    {
        public abstract RouteData GetRouteData(HttpContextBase httpContext);
        public abstract VirtualPathData GetVirtualPath(RequestContext requestContext, RouteValueDictionary values);
 
        public bool RouteExistingFiles { get; set; } = true;
    }
    
    public class RouteData
    {
        public RouteData()
        {
            throw new PlatformNotSupportedException();
        }
 
        public RouteData(RouteBase route, IRouteHandler routeHandler)
        {
            throw new PlatformNotSupportedException();
        }
 
        public RouteValueDictionary DataTokens => default;
        public RouteBase Route { get; set; }
        public IRouteHandler RouteHandler { get; set; }
        public RouteValueDictionary Values => default;
        public string GetRequiredString(string valueName) => default;
    }

    public class RouteValueDictionary : IDictionary<string, object>
    {
        private Dictionary<string, object> _dictionary;
 
        public RouteValueDictionary()
        {
            _dictionary = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        }
 
        public RouteValueDictionary(object values)
        {
            _dictionary = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
 
            AddValues(values);
        }
 
        public RouteValueDictionary(IDictionary<string, object> dictionary)
        {
            _dictionary = new Dictionary<string, object>(dictionary, StringComparer.OrdinalIgnoreCase);
        }
 
        public int Count => _dictionary.Count;
        public Dictionary<string, object>.KeyCollection Keys => _dictionary.Keys;
        public Dictionary<string, object>.ValueCollection Values => _dictionary.Values;

        public object this[string key]
        {
            get
            {
                object value;
                TryGetValue(key, out value);
                return value;
            }
            set
            {
                _dictionary[key] = value;
            }
        }
 
        public void Add(string key, object value)
        {
            _dictionary.Add(key, value);
        }
 
        private void AddValues(object values)
        {
            if (values != null)
            {
                PropertyDescriptorCollection props = TypeDescriptor.GetProperties(values);
                foreach (PropertyDescriptor prop in props)
                {
                    object val = prop.GetValue(values);
                    Add(prop.Name, val);
                }
            }
        }
 
        public void Clear()
        {
            _dictionary.Clear();
        }
 
        public bool ContainsKey(string key) => _dictionary.ContainsKey(key);
        public bool ContainsValue(object value) => _dictionary.ContainsValue(value);
        public Dictionary<string, object>.Enumerator GetEnumerator() => _dictionary.GetEnumerator();
        public bool Remove(string key) => _dictionary.Remove(key);
        public bool TryGetValue(string key, out object value) => _dictionary.TryGetValue(key, out value);

        ICollection<string> IDictionary<string, object>.Keys => _dictionary.Keys;
        ICollection<object> IDictionary<string, object>.Values => _dictionary.Values;

        void ICollection<KeyValuePair<string, object>>.Add(KeyValuePair<string, object> item)
        {
            ((ICollection<KeyValuePair<string, object>>)_dictionary).Add(item);
        }
 
        bool ICollection<KeyValuePair<string, object>>.Contains(KeyValuePair<string, object> item)
        {
            return ((ICollection<KeyValuePair<string, object>>)_dictionary).Contains(item);
        }
 
        void ICollection<KeyValuePair<string, object>>.CopyTo(KeyValuePair<string, object>[] array, int arrayIndex)
        {
            ((ICollection<KeyValuePair<string, object>>)_dictionary).CopyTo(array, arrayIndex);
        }
 
        bool ICollection<KeyValuePair<string, object>>.IsReadOnly =>
            ((ICollection<KeyValuePair<string, object>>)_dictionary).IsReadOnly;
 
        bool ICollection<KeyValuePair<string, object>>.Remove(KeyValuePair<string, object> item)
        {
            return ((ICollection<KeyValuePair<string, object>>)_dictionary).Remove(item);
        }
 
        IEnumerator<KeyValuePair<string, object>> IEnumerable<KeyValuePair<string, object>>.GetEnumerator()
        {
            return GetEnumerator();
        }
 
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }

    public class VirtualPathData
    {
        private string _virtualPath;
        private RouteValueDictionary _dataTokens = new RouteValueDictionary();
 
        public VirtualPathData(RouteBase route, string virtualPath)
        {
            Route = route;
            VirtualPath = virtualPath;
        }
 
        public RouteValueDictionary DataTokens => _dataTokens;
        public RouteBase Route { get; set; }
 
        public string VirtualPath
        {
            get
            {
                return _virtualPath ?? String.Empty;
            }
            set
            {
                _virtualPath = value;
            }
        }
    }
}

namespace System.Web.SessionState
{
    public sealed class HttpSessionState : ICollection
    {
        internal HttpSessionState()
        {
            throw new PlatformNotSupportedException();
        }
 
        public String SessionID => default;
        public int Timeout { get; set; }
        public bool IsNewSession => default;
        public SessionStateMode Mode => default;
        public bool IsCookieless => default;
        public HttpCookieMode CookieMode => default;
        public void Abandon() { }
        public int LCID { get; set; }
        public int CodePage { get; set; }
        public HttpSessionState Contents => default;
        public HttpStaticObjectsCollection StaticObjects => default;
        public Object this[String name] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public Object this[int index] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public void Add(String name, Object value) { }
        public void Remove(String name) { }
        public void RemoveAt(int index) { }
        public void Clear() { }
        public void RemoveAll() { }
        public int Count => default;
        public NameObjectCollectionBase.KeysCollection Keys => default;
        public IEnumerator GetEnumerator() => default;
        public void CopyTo(Array array, int index) { }
        public Object SyncRoot => default;
        public bool IsReadOnly => default;
        public bool IsSynchronized => default;
    }

    public enum SessionStateBehavior
    {
        Default = 0,
        Required = 1,
        ReadOnly = 2,
        Disabled = 3,
    }
    
    public enum SessionStateMode
    {
        Off = 0,
        InProc = 1,
        StateServer = 2,
        SQLServer = 3,
        Custom = 4,
    }
}

namespace System.Web.UI
{
    public interface IFilterResolutionService
    {
        bool EvaluateFilter(string filterName);
        int CompareFilters(string filter1, string filter2);
    }
    
    public interface IStateManager
    {
        bool IsTrackingViewState { get; }
        void LoadViewState(object state);
        object SaveViewState();
        void TrackViewState();
    }

    public interface IUrlResolutionService
    {
        string ResolveClientUrl(string relativeUrl);
    }

    public sealed class CssStyleCollection
    {
        internal CssStyleCollection() : this(null)
        {
            throw new PlatformNotSupportedException();
        }
 
        internal CssStyleCollection(StateBag state)
        {
            throw new PlatformNotSupportedException();
        }
 
        public string this[string key] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string this[HtmlTextWriterStyle key] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ICollection Keys => default;
        public int Count => default;
        public string Value { get; set; }
        public void Add(string key, string value) { }
        public void Add(HtmlTextWriterStyle key, string value) { }
        public void Remove(string key) { }
        public void Remove(HtmlTextWriterStyle key) { }
        public void Clear() { }
    }
    
    public class HtmlTextWriter : TextWriter
    {
        public virtual void EnterStyle(Style style, HtmlTextWriterTag tag) { }
        public virtual void ExitStyle(System.Web.UI.WebControls.Style style, HtmlTextWriterTag tag) { }
        public virtual bool IsValidFormAttribute(String attribute) => default;

        public const char TagLeftChar = '<';
        public const char TagRightChar = '>';
        public const string SelfClosingChars = " /";
        public const string SelfClosingTagEnd = " />";
        public const string EndTagLeftChars = "</";
        public const char DoubleQuoteChar = '"';
        public const char SingleQuoteChar = '\'';
        public const char SpaceChar = ' ';
        public const char EqualsChar = '=';
        public const char SlashChar = '/';
        public const string EqualsDoubleQuoteString = "=\"";
        public const char SemicolonChar = ';';
        public const char StyleEqualsChar = ':';
        public const string DefaultTabString = "\t";
 
        public override Encoding Encoding => default;
        public override string NewLine { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public int Indent { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public TextWriter InnerWriter { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual void BeginRender() { }
        public override void Close() { }
        public virtual void EndRender() { }
        public virtual void EnterStyle(System.Web.UI.WebControls.Style style) { }
        public virtual void ExitStyle(System.Web.UI.WebControls.Style style) { }
        public override void Flush() { }
        protected virtual void OutputTabs() { }
        public override void Write(string s) { }
        public override void Write(bool value) { }
        public override void Write(char value) { }
        public override void Write(char[] buffer) { }
        public override void Write(char[] buffer, int index, int count) { }
        public override void Write(double value) { }
        public override void Write(float value) { }
        public override void Write(int value) { }
        public override void Write(long value) { }
        public override void Write(object value) { }
        public override void Write(string format, object arg0) { }
        public override void Write(string format, object arg0, object arg1) { }
        public override void Write(string format, params object[] arg) { }
        public void WriteLineNoTabs(string s) { }
        public override void WriteLine(string s) { }
        public override void WriteLine() { }
        public override void WriteLine(bool value) { }
        public override void WriteLine(char value) { }
        public override void WriteLine(char[] buffer) { }
        public override void WriteLine(char[] buffer, int index, int count) { }
        public override void WriteLine(double value) { }
        public override void WriteLine(float value) { }
        public override void WriteLine(int value) { }
        public override void WriteLine(long value) { }
        public override void WriteLine(object value) { }
        public override void WriteLine(string format, object arg0) { }
        public override void WriteLine(string format, object arg0, object arg1) { }
        public override void WriteLine(string format, params object[] arg) { }
        [CLSCompliant(false)]
        public override void WriteLine(UInt32 value) { }

        protected static void RegisterTag(string name, HtmlTextWriterTag key)
        {
            throw new PlatformNotSupportedException();
        }
 
        protected static void RegisterAttribute(string name, HtmlTextWriterAttribute key)
        {
            throw new PlatformNotSupportedException();
        }
 
        protected static void RegisterStyle(string name, HtmlTextWriterStyle key)
        {
            throw new PlatformNotSupportedException();
        }
 
        public HtmlTextWriter(TextWriter writer) : this(writer, DefaultTabString)
        {
            throw new PlatformNotSupportedException();
        }
 
        public HtmlTextWriter(TextWriter writer, string tabString) : base(CultureInfo.InvariantCulture)
        {
            throw new PlatformNotSupportedException();
        }
 
        protected HtmlTextWriterTag TagKey { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        protected string TagName { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public virtual void AddAttribute(string name,string value) { }
        public virtual void AddAttribute(string name,string value, bool fEndode) { }
        public virtual void AddAttribute(HtmlTextWriterAttribute key,string value) { }
        public virtual void AddAttribute(HtmlTextWriterAttribute key,string value, bool fEncode) { }
        protected virtual void AddAttribute(string name, string value, HtmlTextWriterAttribute key) { }
        public virtual void AddStyleAttribute(string name, string value) { }
        public virtual void AddStyleAttribute(HtmlTextWriterStyle key, string value) { }
        protected virtual void AddStyleAttribute(string name, string value, HtmlTextWriterStyle key) { }
        protected string EncodeAttributeValue(string value, bool fEncode) => default;
        protected virtual string EncodeAttributeValue(HtmlTextWriterAttribute attrKey, string value) => default;
        protected string EncodeUrl(string url) => default;
        protected HtmlTextWriterAttribute GetAttributeKey(string attrName) => default;
        protected string GetAttributeName(HtmlTextWriterAttribute attrKey) => default;
        protected HtmlTextWriterStyle GetStyleKey(string styleName) => default;
        protected string GetStyleName(HtmlTextWriterStyle styleKey) => default;
        protected virtual HtmlTextWriterTag GetTagKey(string tagName) => default;
        protected virtual string GetTagName(HtmlTextWriterTag tagKey) => default;
        protected bool IsAttributeDefined(HtmlTextWriterAttribute key) => default;
        protected bool IsAttributeDefined(HtmlTextWriterAttribute key, out string value) => throw new PlatformNotSupportedException();
        protected bool IsStyleAttributeDefined(HtmlTextWriterStyle key) => default;
        protected bool IsStyleAttributeDefined(HtmlTextWriterStyle key, out string value) => throw new PlatformNotSupportedException();
        protected virtual bool OnAttributeRender(string name, string value, HtmlTextWriterAttribute key) => default;
        protected virtual bool OnStyleAttributeRender(string name, string value, HtmlTextWriterStyle key) => default;
        protected virtual bool OnTagRender(string name, HtmlTextWriterTag key) => default;
        protected string PopEndTag() => default;
        protected void PushEndTag(string endTag) { }
        protected virtual void FilterAttributes() { }
        public virtual void RenderBeginTag(string tagName) { }
        public virtual void RenderBeginTag(HtmlTextWriterTag tagKey) { }
        public virtual void RenderEndTag() { }
        protected virtual string RenderBeforeTag() => default;
        protected virtual string RenderBeforeContent() => default;
        protected virtual string RenderAfterContent() => default;
        protected virtual string RenderAfterTag() => default;
        public virtual void WriteAttribute(string name, string value) { }
        public virtual void WriteAttribute(string name, string value, bool fEncode) { }
        public virtual void WriteBeginTag(string tagName) { }
        public virtual void WriteBreak() { }
        public virtual void WriteFullBeginTag(string tagName) { }
        public virtual void WriteEndTag(string tagName) { }
        public virtual void WriteStyleAttribute(string name, string value) { }
        public virtual void WriteStyleAttribute(string name, string value, bool fEncode) { }
        public virtual void WriteEncodedUrl(String url) { }
        public virtual void WriteEncodedUrlParameter(String urlText) { }
        public virtual void WriteEncodedText(String text) { }
        protected void WriteUrlEncodedString(String text, bool argument) { }
    }

    public enum HtmlTextWriterAttribute
    {
        Accesskey,
        Align,
        Alt,
        Background,
        Bgcolor,
        Border,
        Bordercolor,
        Cellpadding,
        Cellspacing,
        Checked,
        Class,
        Cols,
        Colspan,
        Disabled,
        For,
        Height,
        Href,
        Id,
        Maxlength,
        Multiple,
        Name,
        Nowrap,
        Onchange,
        Onclick,
        ReadOnly,
        Rows,
        Rowspan,
        Rules,
        Selected,
        Size,
        Src,
        Style,
        Tabindex,
        Target,
        Title,
        Type,
        Valign,
        Value,
        Width,
        Wrap,
        Abbr,
        AutoComplete,
        Axis,
        Content,
        Coords,
        DesignerRegion,
        Dir,
        Headers,
        Longdesc,
        Rel,
        Scope,
        Shape,
        Usemap,
        VCardName,
    }

    public enum HtmlTextWriterStyle
    {
        BackgroundColor,
        BackgroundImage,
        BorderCollapse,
        BorderColor,
        BorderStyle,
        BorderWidth,
        Color,
        FontFamily,
        FontSize,
        FontStyle,
        FontWeight,
        Height,
        TextDecoration,
        Width,
        ListStyleImage,
        ListStyleType,
        Cursor,
        Direction,
        Display,
        Filter,
        FontVariant,
        Left,
        Margin,
        MarginBottom,
        MarginLeft,
        MarginRight,
        MarginTop,
        Overflow,
        OverflowX,
        OverflowY,
        Padding,
        PaddingBottom,
        PaddingLeft,
        PaddingRight,
        PaddingTop,
        Position,
        TextAlign,
        VerticalAlign,
        TextOverflow,
        Top,
        Visibility,
        WhiteSpace,
        ZIndex,
    }
    
    public enum HtmlTextWriterTag
    {
        Unknown,
        A,
        Acronym,
        Address,
        Area,
        B,
        Base,
        Basefont,
        Bdo,
        Bgsound,
        Big,
        Blockquote,
        Body,
        Br,
        Button,
        Caption,
        Center,
        Cite,
        Code,
        Col,
        Colgroup,
        Dd,
        Del,
        Dfn,
        Dir,
        Div,
        Dl,
        Dt,
        Em,
        Embed,
        Fieldset,
        Font,
        Form,
        Frame,
        Frameset,
        H1,
        H2,
        H3,
        H4,
        H5,
        H6,
        Head,
        Hr,
        Html,
        I,
        Iframe,
        Img,
        Input,
        Ins,
        Isindex,
        Kbd,
        Label,
        Legend,
        Li,
        Link,
        Map,
        Marquee,
        Menu,
        Meta,
        Nobr,
        Noframes,
        Noscript,
        Object,
        Ol,
        Option,
        P,
        Param,
        Pre,
        Q,
        Rt,
        Ruby,
        S,
        Samp,
        Script,
        Select,
        Small,
        Span,
        Strike,
        Strong,
        Style,
        Sub,
        Sup,
        Table,
        Tbody,
        Td,
        Textarea,
        Tfoot,
        Th,
        Thead,
        Title,
        Tr,
        Tt,
        U,
        Ul,
        Var,
        Wbr,
        Xml,
    }

    public sealed class StateBag : IStateManager, IDictionary
    {
        public StateBag() : this(false)
        {
            throw new PlatformNotSupportedException();
        }
 
        public StateBag(bool ignoreCase)
        {
            throw new PlatformNotSupportedException();
        }
 
        public int Count => default;
        public ICollection Keys => default;
        public ICollection Values => default;
        public object this[string key] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        object IDictionary.this[object key] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public StateItem Add(string key,object value) => default;
        void IDictionary.Add(object key,object value) { }
        public void Clear() { }
        public IDictionaryEnumerator GetEnumerator() => default;
        public bool IsItemDirty(string key) => default;
        public void Remove(string key) { }
        void IDictionary.Remove(object key) { }
        public void SetDirty(bool dirty) { }
        public void SetItemDirty(string key,bool dirty) { }
        bool IDictionary.IsFixedSize { get { return false; } }
        bool IDictionary.IsReadOnly { get { return false; } }
        bool ICollection.IsSynchronized { get { return false;} }
        object ICollection.SyncRoot { get {return this; } }
        bool IDictionary.Contains(object key) => default;
        IEnumerator IEnumerable.GetEnumerator() => default;
        void ICollection.CopyTo(Array array, int index) { }
        bool IStateManager.IsTrackingViewState => default;
        void IStateManager.LoadViewState(object state) { }
        void IStateManager.TrackViewState() { }
        object IStateManager.SaveViewState() => default;
    }

    public sealed class StateItem
    {
        internal StateItem(object initialValue)
        {
            throw new PlatformNotSupportedException();
        }
 
        public bool IsDirty { get; set; }
        public object Value { get; set; }
    }
}

namespace System.Web.UI.WebControls
{
    public enum BorderStyle
    {
        NotSet = 0,
        None = 1,
        Dotted = 2,
        Dashed = 3,
        Solid = 4,
        Double = 5,
        Groove = 6,
        Ridge = 7,
        Inset = 8,
        Outset = 9,
    }

    public sealed class FontInfo
    {
        internal FontInfo(Style owner)
        {
            throw new PlatformNotSupportedException();
        }

        public bool Bold { get; set; }
        public bool Italic { get; set; }
        public string Name { get; set; }
        public string[] Names { get; set; }
        public bool Overline { get; set; }
        public FontUnit Size { get; set; }
        public bool Strikeout { get; set; }
        public bool Underline { get; set; }
        public void ClearDefaults() { }
        public void CopyFrom(FontInfo f) { }
        public void MergeWith(FontInfo f) { }
        public bool ShouldSerializeNames() => default;
    }

    public struct FontUnit
    {
        public static readonly FontUnit Empty = default;
        public static readonly FontUnit Smaller = default;
        public static readonly FontUnit Larger = default;
        public static readonly FontUnit XXSmall = default;
        public static readonly FontUnit XSmall = default;
        public static readonly FontUnit Small = default;
        public static readonly FontUnit Medium = default;
        public static readonly FontUnit Large = default;
        public static readonly FontUnit XLarge = default;
        public static readonly FontUnit XXLarge = default;

        public FontUnit(FontSize type)
        {
            throw new PlatformNotSupportedException();
        }
 
        public FontUnit(Unit value) {
            throw new PlatformNotSupportedException();
        }
 
        public FontUnit(int value) {
            throw new PlatformNotSupportedException();
        }
 
        public FontUnit(double value) {
            throw new PlatformNotSupportedException();
        }
 
        public FontUnit(double value, UnitType type) {
            throw new PlatformNotSupportedException();
        }
 
        public FontUnit(string value) {
            throw new PlatformNotSupportedException();
        }
 
        public FontUnit(string value, CultureInfo culture) {
            throw new PlatformNotSupportedException();
        }
        
        public bool IsEmpty => true;
        public FontSize Type => default;
        public Unit Unit => default;
        public override int GetHashCode() => default;
        public override bool Equals(object obj) => default;
        public static bool operator ==(FontUnit left, FontUnit right) => true;
        public static bool operator !=(FontUnit left, FontUnit right) => false;
 
        public static FontUnit Parse(string s) {
            throw new PlatformNotSupportedException();
        }
 
        public static FontUnit Parse(string s, CultureInfo culture) {
            throw new PlatformNotSupportedException();
        }
        
        public static FontUnit Point(int n) {
            throw new PlatformNotSupportedException();
        }
 
        public override string ToString() => string.Empty;
        public string ToString(CultureInfo culture) => string.Empty;
        public string ToString(IFormatProvider formatProvider) => string.Empty;
 
        public static implicit operator FontUnit(int n) => default;
    }

    public enum FontSize
    {
        NotSet = 0,
        AsUnit = 1,
        Smaller = 2,
        Larger = 3,
        XXSmall = 4,
        XSmall = 5,
        Small = 6,
        Medium = 7,
        Large = 8,
        XLarge = 9,
        XXLarge = 10,
    }
    
    public class Style : Component, IStateManager
    {
        public Style()
        {
            throw new PlatformNotSupportedException();
        }
        
        public Style(StateBag bag)
        {
            throw new PlatformNotSupportedException();
        }

        public Color BackColor { get; set; }
        public Color BorderColor { get; set; }
        public Unit BorderWidth { get; set; }
        public BorderStyle BorderStyle { get; set; }
        public string CssClass { get; set; }
        public FontInfo Font => default;
        public Color ForeColor { get; set; }
        public Unit Height { get; set; }
        public virtual bool IsEmpty => default;
        protected bool IsTrackingViewState => default;
        public string RegisteredCssClass => default;
        protected internal StateBag ViewState => default;
        public Unit Width { get; set; }
        public void AddAttributesToRender(HtmlTextWriter writer) { }
        public virtual void AddAttributesToRender(HtmlTextWriter writer, WebControl owner) { }
        public virtual void CopyFrom(Style s) { }
        protected virtual void FillStyleAttributes(CssStyleCollection attributes, IUrlResolutionService urlResolver) { }
        public CssStyleCollection GetStyleAttributes(IUrlResolutionService urlResolver) => default;
        protected internal void LoadViewState(object state) { }
        protected internal virtual void TrackViewState() { }
        public virtual void MergeWith(Style s) { }
        public virtual void Reset() { }
        protected internal virtual object SaveViewState() => default;
        protected internal virtual void SetBit(int bit) { }
        public void SetDirty() { }
        
        bool IStateManager.IsTrackingViewState => default;
        void IStateManager.LoadViewState(object state) { }
        void IStateManager.TrackViewState() { }
        object IStateManager.SaveViewState() => default;
    }

    public struct Unit
    {
        public static readonly Unit Empty = default;

        public Unit(int value) {
            throw new PlatformNotSupportedException();
        }
 
        public Unit(double value) {
            throw new PlatformNotSupportedException();
        }
 
        public Unit(double value, UnitType type) {
            throw new PlatformNotSupportedException();
        }
 
        public Unit(string value) {
            throw new PlatformNotSupportedException();
        }
 
        public Unit(string value, CultureInfo culture) {
            throw new PlatformNotSupportedException();
        }
 
        public bool IsEmpty => true;
        public UnitType Type => UnitType.Pixel;
        public double Value => default;
        public override int GetHashCode() => default;
        public override bool Equals(object obj) => default;
        
        // Only default instances? Equality is easy
        public static bool operator ==(Unit left, Unit right) => true;
        public static bool operator !=(Unit left, Unit right) => false;
        
        public static Unit Parse(string s) {
            throw new PlatformNotSupportedException();
        }
 
        public static Unit Parse(string s, CultureInfo culture) {
            throw new PlatformNotSupportedException();
        }
 
        public static Unit Percentage(double n) {
            throw new PlatformNotSupportedException();
        }
 
        public static Unit Pixel(int n) {
            throw new PlatformNotSupportedException();
        }
 
        public static Unit Point(int n) {
            throw new PlatformNotSupportedException();
        }
 
        public override string ToString() => string.Empty;
        public string ToString(CultureInfo culture) => string.Empty;
        public string ToString(IFormatProvider formatProvider) => string.Empty;
        
        public static implicit operator Unit(int n) => default;
    }

    public enum UnitType
    {
        Pixel = 1,
        Point = 2,
        Pica = 3,
        Inch = 4,
        Mm = 5,
        Cm = 6,
        Percentage = 7,
        Em = 8,
        Ex = 9,
    }
}

namespace System.Web.WebSockets
{
    public abstract class AspNetWebSocketContext : WebSocketContext
    {
        public virtual string AnonymousID => throw new NotImplementedException(); 
        public virtual HttpApplicationStateBase Application => throw new NotImplementedException(); 
        public virtual string ApplicationPath => throw new NotImplementedException(); 
        public virtual Cache Cache => throw new NotImplementedException(); 
        public virtual HttpClientCertificate ClientCertificate => throw new NotImplementedException(); 
        public static int ConnectionCount => default;
        public override CookieCollection CookieCollection => throw new NotImplementedException(); 
        public virtual HttpCookieCollection Cookies => throw new NotImplementedException(); 
        public virtual string FilePath => throw new NotImplementedException(); 
        public override NameValueCollection Headers => throw new NotImplementedException(); 
        public override bool IsAuthenticated => throw new NotImplementedException(); 
        public virtual bool IsClientConnected => throw new NotImplementedException(); 
        public virtual bool IsDebuggingEnabled => throw new NotImplementedException(); 
        public override bool IsLocal => throw new NotImplementedException(); 
        public override bool IsSecureConnection => throw new NotImplementedException(); 
        public virtual IDictionary Items => throw new NotImplementedException(); 
        public virtual WindowsIdentity LogonUserIdentity => throw new NotImplementedException(); 
        public override string Origin => throw new NotImplementedException(); 
        public virtual string Path => throw new NotImplementedException(); 
        public virtual string PathInfo => throw new NotImplementedException(); 
        public virtual ProfileBase Profile => throw new NotImplementedException(); 
        public virtual NameValueCollection QueryString => throw new NotImplementedException(); 
        public virtual string RawUrl => throw new NotImplementedException(); 
        public override Uri RequestUri => throw new NotImplementedException(); 
        public override string SecWebSocketKey => throw new NotImplementedException(); 
        public override IEnumerable<string> SecWebSocketProtocols => throw new NotImplementedException(); 
        public override string SecWebSocketVersion => throw new NotImplementedException(); 
        public virtual HttpServerUtilityBase Server => throw new NotImplementedException(); 
        public virtual NameValueCollection ServerVariables => throw new NotImplementedException(); 
        public virtual DateTime Timestamp => throw new NotImplementedException(); 
        public virtual UnvalidatedRequestValuesBase Unvalidated => throw new NotImplementedException(); 
        public virtual Uri UrlReferrer => throw new NotImplementedException(); 
        public override IPrincipal User => throw new NotImplementedException(); 
        public virtual string UserAgent => throw new NotImplementedException(); 
        public virtual string UserHostAddress => throw new NotImplementedException(); 
        public virtual string UserHostName => throw new NotImplementedException(); 
        public virtual string[] UserLanguages => throw new NotImplementedException(); 
        public override WebSocket WebSocket => throw new NotImplementedException();
    }

    public sealed class AspNetWebSocketOptions
    {
        public AspNetWebSocketOptions()
        {
            throw new PlatformNotSupportedException();
        }
 
        public bool RequireSameOrigin { get; set; }
 
        public string SubProtocol { get; set; }
    }
}    
