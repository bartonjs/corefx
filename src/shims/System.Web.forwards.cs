// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

// This file contains shim types to allow application platforms with
// ASP.NET lightup code to execute (and detect that they're not in ASP.NET)
using System.Collections;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace System.Web
{
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
        public void SetCacheDependencyChanged(Action<Object, EventArgs> dependencyChangedAction) { }
        public virtual string GetUniqueID() => null;
        protected void NotifyDependencyChanged(Object sender, EventArgs e) { }
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
}

namespace System.Web.Hosting
{
    using Caching;
    using Configuration;

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
        public override Object InitializeLifetimeService() => null;
        public virtual string Name => throw new PlatformNotSupportedException();
        public string VirtualPath => throw new PlatformNotSupportedException();
        public abstract bool IsDirectory { get; }
    }

    public abstract class VirtualPathProvider : MarshalByRefObject
    {
        public override Object InitializeLifetimeService() => null;
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
