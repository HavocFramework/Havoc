#ifndef DEMON_CLR_H
#define DEMON_CLR_H

#include <windows.h>

#include <Core/Win32.h>

extern GUID xCLSID_CLRMetaHost;
extern GUID xIID_ICLRMetaHost;
extern GUID xIID_ICLRRuntimeInfo;
extern GUID xCLSID_CorRuntimeHost;
extern GUID xIID_ICorRuntimeHost;
extern GUID xIID_AppDomain;

typedef struct _ICLRMetaHost    ICLRMetaHost;
typedef struct _ICLRRuntimeInfo ICLRRuntimeInfo;
typedef struct _AppDomain       IAppDomain;
typedef struct _Assembly        IAssembly;
typedef struct _Type            IType;
typedef struct _Binder          IBinder;
typedef struct _MethodInfo      IMethodInfo;

typedef ICLRMetaHost    *PICLRMetaHost;
typedef ICLRRuntimeInfo *PICLRRuntimeInfo;
typedef IAssembly       *PIAssembly;
typedef IEnumUnknown    *PIEnumUnknown;
typedef IUnknown        *PIUnknown;
typedef ICorRuntimeHost *PICorRuntimeHost;

typedef void* HDOMAINENUM;

typedef HRESULT(__stdcall* CLRCreateInstanceFnPtr)(
        REFCLSID clsid,
        REFIID riid,
        LPVOID* ppInterface);

typedef HRESULT(__stdcall* CreateInterfaceFnPtr)(
        REFCLSID clsid,
        REFIID riid,
        LPVOID* ppInterface);


typedef HRESULT(__stdcall* CallbackThreadSetFnPtr)(void);

typedef HRESULT(__stdcall* CallbackThreadUnsetFnPtr)(void);

typedef void(__stdcall* RuntimeLoadedCallbackFnPtr)(
        ICLRRuntimeInfo* pRuntimeInfo,
        CallbackThreadSetFnPtr pfnCallbackThreadSet,
        CallbackThreadUnsetFnPtr pfnCallbackThreadUnset);

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IBinder *This)

typedef struct _BinderVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IBinder* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
            IBinder* This);

    ULONG(STDMETHODCALLTYPE* Release)(
            IBinder* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);
    DUMMY_METHOD(Invoke);
    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(BindToMethod);
    DUMMY_METHOD(BindToField);
    DUMMY_METHOD(SelectMethod);
    DUMMY_METHOD(SelectProperty);
    DUMMY_METHOD(ChangeType);
    DUMMY_METHOD(ReorderArgumentArray);
} BinderVtbl;

typedef struct _Binder {
    BinderVtbl* lpVtbl;
} Binder;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAppDomain *This)

typedef struct _AppDomainVtbl {
    BEGIN_INTERFACE

    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IAppDomain* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
            IAppDomain* This);

    ULONG(STDMETHODCALLTYPE* Release)(
            IAppDomain* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);
    DUMMY_METHOD(Invoke);

    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(InitializeLifetimeService);
    DUMMY_METHOD(GetLifetimeService);
    DUMMY_METHOD(Evidence);
    DUMMY_METHOD(add_DomainUnload);
    DUMMY_METHOD(remove_DomainUnload);
    DUMMY_METHOD(add_AssemblyLoad);
    DUMMY_METHOD(remove_AssemblyLoad);
    DUMMY_METHOD(add_ProcessExit);
    DUMMY_METHOD(remove_ProcessExit);
    DUMMY_METHOD(add_TypeResolve);
    DUMMY_METHOD(remove_TypeResolve);
    DUMMY_METHOD(add_ResourceResolve);
    DUMMY_METHOD(remove_ResourceResolve);
    DUMMY_METHOD(add_AssemblyResolve);
    DUMMY_METHOD(remove_AssemblyResolve);
    DUMMY_METHOD(add_UnhandledException);
    DUMMY_METHOD(remove_UnhandledException);
    DUMMY_METHOD(DefineDynamicAssembly);
    DUMMY_METHOD(DefineDynamicAssembly_2);
    DUMMY_METHOD(DefineDynamicAssembly_3);
    DUMMY_METHOD(DefineDynamicAssembly_4);
    DUMMY_METHOD(DefineDynamicAssembly_5);
    DUMMY_METHOD(DefineDynamicAssembly_6);
    DUMMY_METHOD(DefineDynamicAssembly_7);
    DUMMY_METHOD(DefineDynamicAssembly_8);
    DUMMY_METHOD(DefineDynamicAssembly_9);
    DUMMY_METHOD(CreateInstance);
    DUMMY_METHOD(CreateInstanceFrom);
    DUMMY_METHOD(CreateInstance_2);
    DUMMY_METHOD(CreateInstanceFrom_2);
    DUMMY_METHOD(CreateInstance_3);
    DUMMY_METHOD(CreateInstanceFrom_3);
    DUMMY_METHOD(Load);
    DUMMY_METHOD(Load_2);

    HRESULT(STDMETHODCALLTYPE* Load_3)(
            IAppDomain* This,
            SAFEARRAY* rawAssembly,
            IAssembly** pRetVal);

    DUMMY_METHOD(Load_4);
    DUMMY_METHOD(Load_5);
    DUMMY_METHOD(Load_6);
    DUMMY_METHOD(Load_7);
    DUMMY_METHOD(ExecuteAssembly);
    DUMMY_METHOD(ExecuteAssembly_2);
    DUMMY_METHOD(ExecuteAssembly_3);
    DUMMY_METHOD(FriendlyName);
    DUMMY_METHOD(BaseDirectory);
    DUMMY_METHOD(RelativeSearchPath);
    DUMMY_METHOD(ShadowCopyFiles);
    DUMMY_METHOD(GetAssemblies);
    DUMMY_METHOD(AppendPrivatePath);
    DUMMY_METHOD(ClearPrivatePath);
    DUMMY_METHOD(SetShadowCopyPath);
    DUMMY_METHOD(ClearShadowCopyPath);
    DUMMY_METHOD(SetCachePath);
    DUMMY_METHOD(SetData);
    DUMMY_METHOD(GetData);
    DUMMY_METHOD(SetAppDomainPolicy);
    DUMMY_METHOD(SetThreadPrincipal);
    DUMMY_METHOD(SetPrincipalPolicy);
    DUMMY_METHOD(DoCallBack);
    DUMMY_METHOD(DynamicDirectory);

    END_INTERFACE
} AppDomainVtbl;

typedef struct _AppDomain {
    AppDomainVtbl* lpVtbl;
} AppDomain, *PAppDomain;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAssembly *This)

typedef struct _AssemblyVtbl {
    BEGIN_INTERFACE

    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IAssembly* This,
            REFIID riid,
            void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
            IAssembly* This);

    ULONG(STDMETHODCALLTYPE* Release)(
            IAssembly* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);

    DUMMY_METHOD(Invoke);
    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(CodeBase);
    DUMMY_METHOD(EscapedCodeBase);
    DUMMY_METHOD(GetName);
    DUMMY_METHOD(GetName_2);
    DUMMY_METHOD(FullName);

    HRESULT(STDMETHODCALLTYPE* EntryPoint)(
            IAssembly* This,
            IMethodInfo** pRetVal);

    HRESULT(STDMETHODCALLTYPE* GetType_2)(
            IAssembly* This,
            BSTR        name,
            IType** pRetVal);

    DUMMY_METHOD(GetType_3);
    DUMMY_METHOD(GetExportedTypes);
    DUMMY_METHOD(GetTypes);
    DUMMY_METHOD(GetManifestResourceStream);
    DUMMY_METHOD(GetManifestResourceStream_2);
    DUMMY_METHOD(GetFile);
    DUMMY_METHOD(GetFiles);
    DUMMY_METHOD(GetFiles_2);
    DUMMY_METHOD(GetManifestResourceNames);
    DUMMY_METHOD(GetManifestResourceInfo);
    DUMMY_METHOD(Location);
    DUMMY_METHOD(Evidence);
    DUMMY_METHOD(GetCustomAttributes);
    DUMMY_METHOD(GetCustomAttributes_2);
    DUMMY_METHOD(IsDefined);
    DUMMY_METHOD(GetObjectData);
    DUMMY_METHOD(add_ModuleResolve);
    DUMMY_METHOD(remove_ModuleResolve);
    DUMMY_METHOD(GetType_4);
    DUMMY_METHOD(GetSatelliteAssembly);
    DUMMY_METHOD(GetSatelliteAssembly_2);
    DUMMY_METHOD(LoadModule);
    DUMMY_METHOD(LoadModule_2);
    DUMMY_METHOD(CreateInstance);
    DUMMY_METHOD(CreateInstance_2);
    DUMMY_METHOD(CreateInstance_3);
    DUMMY_METHOD(GetLoadedModules);
    DUMMY_METHOD(GetLoadedModules_2);
    DUMMY_METHOD(GetModules);
    DUMMY_METHOD(GetModules_2);
    DUMMY_METHOD(GetModule);
    DUMMY_METHOD(GetReferencedAssemblies);
    DUMMY_METHOD(GlobalAssemblyCache);

    END_INTERFACE
} AssemblyVtbl;

typedef enum _BindingFlags {
    BindingFlags_Default = 0,
    BindingFlags_IgnoreCase = 1,
    BindingFlags_DeclaredOnly = 2,
    BindingFlags_Instance = 4,
    BindingFlags_Static = 8,
    BindingFlags_Public = 16,
    BindingFlags_NonPublic = 32,
    BindingFlags_FlattenHierarchy = 64,
    BindingFlags_InvokeMethod = 256,
    BindingFlags_CreateInstance = 512,
    BindingFlags_GetField = 1024,
    BindingFlags_SetField = 2048,
    BindingFlags_GetProperty = 4096,
    BindingFlags_SetProperty = 8192,
    BindingFlags_PutDispProperty = 16384,
    BindingFlags_PutRefDispProperty = 32768,
    BindingFlags_ExactBinding = 65536,
    BindingFlags_SuppressChangeType = 131072,
    BindingFlags_OptionalParamBinding = 262144,
    BindingFlags_IgnoreReturn = 16777216
} BindingFlags;

typedef struct _Assembly {
    AssemblyVtbl* lpVtbl;
} Assembly, *PAssembly;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IType *This)

typedef struct _TypeVtbl {
    BEGIN_INTERFACE

    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IType* This,
            REFIID riid,
            void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
            IType* This);

    ULONG(STDMETHODCALLTYPE* Release)(
            IType* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);
    DUMMY_METHOD(Invoke);

    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(MemberType);
    DUMMY_METHOD(name);
    DUMMY_METHOD(DeclaringType);
    DUMMY_METHOD(ReflectedType);
    DUMMY_METHOD(GetCustomAttributes);
    DUMMY_METHOD(GetCustomAttributes_2);
    DUMMY_METHOD(IsDefined);
    DUMMY_METHOD(Guid);
    DUMMY_METHOD(Module);
    DUMMY_METHOD(Assembly);
    DUMMY_METHOD(TypeHandle);
    DUMMY_METHOD(FullName);
    DUMMY_METHOD(Namespace);
    DUMMY_METHOD(AssemblyQualifiedName);
    DUMMY_METHOD(GetArrayRank);
    DUMMY_METHOD(BaseType);
    DUMMY_METHOD(GetConstructors);
    DUMMY_METHOD(GetInterface);
    DUMMY_METHOD(GetInterfaces);
    DUMMY_METHOD(FindInterfaces);
    DUMMY_METHOD(GetEvent);
    DUMMY_METHOD(GetEvents);
    DUMMY_METHOD(GetEvents_2);
    DUMMY_METHOD(GetNestedTypes);
    DUMMY_METHOD(GetNestedType);
    DUMMY_METHOD(GetMember);
    DUMMY_METHOD(GetDefaultMembers);
    DUMMY_METHOD(FindMembers);
    DUMMY_METHOD(GetElementType);
    DUMMY_METHOD(IsSubclassOf);
    DUMMY_METHOD(IsInstanceOfType);
    DUMMY_METHOD(IsAssignableFrom);
    DUMMY_METHOD(GetInterfaceMap);
    DUMMY_METHOD(GetMethod);
    DUMMY_METHOD(GetMethod_2);
    DUMMY_METHOD(GetMethods);
    DUMMY_METHOD(GetField);
    DUMMY_METHOD(GetFields);
    DUMMY_METHOD(GetProperty);
    DUMMY_METHOD(GetProperty_2);
    DUMMY_METHOD(GetProperties);
    DUMMY_METHOD(GetMember_2);
    DUMMY_METHOD(GetMembers);
    DUMMY_METHOD(InvokeMember);
    DUMMY_METHOD(UnderlyingSystemType);
    DUMMY_METHOD(InvokeMember_2);

    HRESULT(STDMETHODCALLTYPE* InvokeMember_3)(
            IType* This,
            BSTR         name,
            BindingFlags invokeAttr,
            IBinder* Binder,
            VARIANT      Target,
            SAFEARRAY* args,
            VARIANT* pRetVal);

    DUMMY_METHOD(GetConstructor);
    DUMMY_METHOD(GetConstructor_2);
    DUMMY_METHOD(GetConstructor_3);
    DUMMY_METHOD(GetConstructors_2);
    DUMMY_METHOD(TypeInitializer);
    DUMMY_METHOD(GetMethod_3);
    DUMMY_METHOD(GetMethod_4);
    DUMMY_METHOD(GetMethod_5);
    DUMMY_METHOD(GetMethod_6);
    DUMMY_METHOD(GetMethods_2);
    DUMMY_METHOD(GetField_2);
    DUMMY_METHOD(GetFields_2);
    DUMMY_METHOD(GetInterface_2);
    DUMMY_METHOD(GetEvent_2);
    DUMMY_METHOD(GetProperty_3);
    DUMMY_METHOD(GetProperty_4);
    DUMMY_METHOD(GetProperty_5);
    DUMMY_METHOD(GetProperty_6);
    DUMMY_METHOD(GetProperty_7);
    DUMMY_METHOD(GetProperties_2);
    DUMMY_METHOD(GetNestedTypes_2);
    DUMMY_METHOD(GetNestedType_2);
    DUMMY_METHOD(GetMember_3);
    DUMMY_METHOD(GetMembers_2);
    DUMMY_METHOD(Attributes);
    DUMMY_METHOD(IsNotPublic);
    DUMMY_METHOD(IsPublic);
    DUMMY_METHOD(IsNestedPublic);
    DUMMY_METHOD(IsNestedPrivate);
    DUMMY_METHOD(IsNestedFamily);
    DUMMY_METHOD(IsNestedAssembly);
    DUMMY_METHOD(IsNestedFamANDAssem);
    DUMMY_METHOD(IsNestedFamORAssem);
    DUMMY_METHOD(IsAutoLayout);
    DUMMY_METHOD(IsLayoutSequential);
    DUMMY_METHOD(IsExplicitLayout);
    DUMMY_METHOD(IsClass);
    DUMMY_METHOD(IsInterface);
    DUMMY_METHOD(IsValueType);
    DUMMY_METHOD(IsAbstract);
    DUMMY_METHOD(IsSealed);
    DUMMY_METHOD(IsEnum);
    DUMMY_METHOD(IsSpecialName);
    DUMMY_METHOD(IsImport);
    DUMMY_METHOD(IsSerializable);
    DUMMY_METHOD(IsAnsiClass);
    DUMMY_METHOD(IsUnicodeClass);
    DUMMY_METHOD(IsAutoClass);
    DUMMY_METHOD(IsArray);
    DUMMY_METHOD(IsByRef);
    DUMMY_METHOD(IsPointer);
    DUMMY_METHOD(IsPrimitive);
    DUMMY_METHOD(IsCOMObject);
    DUMMY_METHOD(HasElementType);
    DUMMY_METHOD(IsContextful);
    DUMMY_METHOD(IsMarshalByRef);
    DUMMY_METHOD(Equals_2);

    END_INTERFACE
} TypeVtbl;

typedef struct ICLRRuntimeInfoVtbl
{
    BEGIN_INTERFACE

    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            ICLRRuntimeInfo* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */
            __RPC__deref_out  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
            ICLRRuntimeInfo* This);

    ULONG(STDMETHODCALLTYPE* Release)(
            ICLRRuntimeInfo* This);

    HRESULT(STDMETHODCALLTYPE* GetVersionString)(
            ICLRRuntimeInfo* This,
            /* [size_is][out] */
            LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBuffer);

    HRESULT(STDMETHODCALLTYPE* GetRuntimeDirectory)(
            ICLRRuntimeInfo* This,
            /* [size_is][out] */
            __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBuffer);

    HRESULT(STDMETHODCALLTYPE* IsLoaded)(
            ICLRRuntimeInfo* This,
            /* [in] */ HANDLE hndProcess,
            /* [retval][out] */ BOOL* pbLoaded);

    HRESULT(STDMETHODCALLTYPE* LoadErrorString)(
            ICLRRuntimeInfo* This,
            /* [in] */ UINT iResourceID,
            /* [size_is][out] */
            __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBuffer,
            /* [lcid][in] */ LONG iLocaleID);

    HRESULT(STDMETHODCALLTYPE* LoadLibrary)(
            ICLRRuntimeInfo* This,
            /* [in] */ LPCWSTR pwzDllName,
            /* [retval][out] */ HMODULE* phndModule);

    HRESULT(STDMETHODCALLTYPE* GetProcAddress)(
            ICLRRuntimeInfo* This,
            /* [in] */ LPCSTR pszProcName,
            /* [retval][out] */ LPVOID* ppProc);

    HRESULT(STDMETHODCALLTYPE* GetInterface)(
            ICLRRuntimeInfo* This,
            /* [in] */ REFCLSID rclsid,
            /* [in] */ REFIID riid,
            /* [retval][iid_is][out] */ LPVOID* ppUnk);

    HRESULT(STDMETHODCALLTYPE* IsLoadable)(
            ICLRRuntimeInfo* This,
            /* [retval][out] */ BOOL* pbLoadable);

    HRESULT(STDMETHODCALLTYPE* SetDefaultStartupFlags)(
            ICLRRuntimeInfo* This,
            /* [in] */ DWORD dwStartupFlags,
            /* [in] */ LPCWSTR pwzHostConfigFile);

    HRESULT(STDMETHODCALLTYPE* GetDefaultStartupFlags)(
            ICLRRuntimeInfo* This,
            /* [out] */ DWORD* pdwStartupFlags,
            /* [size_is][out] */
            LPWSTR pwzHostConfigFile,
            /* [out][in] */ DWORD* pcchHostConfigFile);

    HRESULT(STDMETHODCALLTYPE* BindAsLegacyV2Runtime)(
            ICLRRuntimeInfo* This);

    HRESULT(STDMETHODCALLTYPE* IsStarted)(
            ICLRRuntimeInfo* This,
            /* [out] */ BOOL* pbStarted,
            /* [out] */ DWORD* pdwStartupFlags);

    END_INTERFACE
} ICLRRuntimeInfoVtbl;

typedef struct _ICLRRuntimeInfo {
    ICLRRuntimeInfoVtbl* lpVtbl;
} ICLRRuntimeInfo;

typedef struct _Type {
    TypeVtbl* lpVtbl;
} Type;

typedef struct ICLRMetaHostVtbl
{
    BEGIN_INTERFACE

    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            ICLRMetaHost* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */
            __RPC__deref_out  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
            ICLRMetaHost* This);

    ULONG(STDMETHODCALLTYPE* Release)(
            ICLRMetaHost* This);

    HRESULT(STDMETHODCALLTYPE* GetRuntime)(
            ICLRMetaHost* This,
            /* [in] */ LPCWSTR pwzVersion,
            /* [in] */ REFIID riid,
            /* [retval][iid_is][out] */ LPVOID* ppRuntime);

    HRESULT(STDMETHODCALLTYPE* GetVersionFromFile)(
            ICLRMetaHost* This,
            /* [in] */ LPCWSTR pwzFilePath,
            /* [size_is][out] */
            __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBuffer);

    HRESULT(STDMETHODCALLTYPE* EnumerateInstalledRuntimes)(
            ICLRMetaHost* This,
            /* [retval][out] */ IEnumUnknown** ppEnumerator);

    HRESULT(STDMETHODCALLTYPE* EnumerateLoadedRuntimes)(
            ICLRMetaHost* This,
            /* [in] */ HANDLE hndProcess,
            /* [retval][out] */ IEnumUnknown** ppEnumerator);

    HRESULT(STDMETHODCALLTYPE* RequestRuntimeLoadedNotification)(
            ICLRMetaHost* This,
            /* [in] */ RuntimeLoadedCallbackFnPtr pCallbackFunction);

    HRESULT(STDMETHODCALLTYPE* QueryLegacyV2RuntimeBinding)(
            ICLRMetaHost* This,
            /* [in] */ REFIID riid,
            /* [retval][iid_is][out] */ LPVOID* ppUnk);

    HRESULT(STDMETHODCALLTYPE* ExitProcess)(
            ICLRMetaHost* This,
            /* [in] */ INT32 iExitCode);

    END_INTERFACE
} ICLRMetaHostVtbl;

typedef struct _ICLRMetaHost
{
    ICLRMetaHostVtbl* lpVtbl;
} ICLRMetaHost;


#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IMethodInfo *This)

typedef struct _MethodInfoVtbl {
    BEGIN_INTERFACE

    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IMethodInfo* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */
            __RPC__deref_out  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
            IMethodInfo* This);

    ULONG(STDMETHODCALLTYPE* Release)(
            IMethodInfo* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);
    DUMMY_METHOD(Invoke);

    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(MemberType);
    DUMMY_METHOD(name);
    DUMMY_METHOD(DeclaringType);
    DUMMY_METHOD(ReflectedType);
    DUMMY_METHOD(GetCustomAttributes);
    DUMMY_METHOD(GetCustomAttributes_2);
    DUMMY_METHOD(IsDefined);

    HRESULT(STDMETHODCALLTYPE* GetParameters)(
            IMethodInfo* This,
            SAFEARRAY** pRetVal);

    DUMMY_METHOD(GetMethodImplementationFlags);
    DUMMY_METHOD(MethodHandle);
    DUMMY_METHOD(Attributes);
    DUMMY_METHOD(CallingConvention);
    DUMMY_METHOD(Invoke_2);
    DUMMY_METHOD(IsPublic);
    DUMMY_METHOD(IsPrivate);
    DUMMY_METHOD(IsFamily);
    DUMMY_METHOD(IsAssembly);
    DUMMY_METHOD(IsFamilyAndAssembly);
    DUMMY_METHOD(IsFamilyOrAssembly);
    DUMMY_METHOD(IsStatic);
    DUMMY_METHOD(IsFinal);
    DUMMY_METHOD(IsVirtual);
    DUMMY_METHOD(IsHideBySig);
    DUMMY_METHOD(IsAbstract);
    DUMMY_METHOD(IsSpecialName);
    DUMMY_METHOD(IsConstructor);

    HRESULT(STDMETHODCALLTYPE* Invoke_3)(
            IMethodInfo* This,
            VARIANT     obj,
            SAFEARRAY* parameters,
            VARIANT* ret);

    DUMMY_METHOD(returnType);
    DUMMY_METHOD(ReturnTypeCustomAttributes);
    DUMMY_METHOD(GetBaseDefinition);

    END_INTERFACE
} MethodInfoVtbl;

typedef struct _MethodInfo {
    MethodInfoVtbl* lpVtbl;
} MethodInfo, *PMethodInfo;

typedef struct _DOTNET_ARGS
{
    /* The random task id associated with the requested DOTNET exec */
    UINT32 RequestID;

    /* Buffers */
    BUFFER PipeName;
    BUFFER AppDomainName;
    BUFFER NetVersion;
    BUFFER Output;

    /* Handles */
    HANDLE Pipe;
    HANDLE File;
    HANDLE StdOut;
    HANDLE Thread;
    HANDLE Event;
    HANDLE Exit;

    /* Argument Array */
    UNICODE_STRING ArgumentArray;

    /* Some Assembly Variables. */
    SAFEARRAY* SafeArray;
    SAFEARRAY* MethodArgs;

    /* Clr variables */
    PICLRMetaHost    MetaHost;
    PICLRRuntimeInfo ClrRuntimeInfo;
    PICorRuntimeHost ICorRuntimeHost;
    PAssembly        Assembly;
    PIUnknown        AppDomainThunk;
    PAppDomain       AppDomain;
    PMethodInfo      MethodInfo;

    /* Variants */
    VARIANT vtPsa;
    VARIANT Return;

    /* Successful invoked ? */
    BOOL Invoked;

    /* Contexts */
    PCONTEXT RopInit;
    PCONTEXT RopInvk;
    PCONTEXT RopEvnt;
    PCONTEXT RopExit;
} DOTNET_ARGS, *PDOTNET_ARGS;

#define DEMOn_CLR_ERROR_REFUSE_VERSION 0x1

DWORD ClrCreateInstance( LPCWSTR dotNetVersion, PICLRMetaHost* ppClrMetaHost, PICLRRuntimeInfo* ppClrRuntimeInfo, ICorRuntimeHost** ppICorRuntimeHost );
BOOL  FindVersion( PVOID Assembly, DWORD length );

#endif
