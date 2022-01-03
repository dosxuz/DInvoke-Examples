using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

using static SimpleDinvoke.Types;

using static SimpleDinvoke.Program;

namespace SimpleDinvoke
{
    class Helper
    {
        public static IntPtr GetLibaddr(string dllName, string funcName)
        {
            IntPtr hModule = IntPtr.Zero;
            ProcessModuleCollection procModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in procModules)
            {
                if (Mod.FileName.ToLower().EndsWith(dllName.ToLower()))
                {
                    hModule = Mod.BaseAddress;
                    break;
                }
            }

            //GetLibraryAddress if if it is not found
            if (hModule == IntPtr.Zero)
            {
                //Loading module from disk
                UNICODE_STRING uModuleName = new UNICODE_STRING();
                NTSTATUS res = ldrldll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
                if (res != NTSTATUS.Success || hModule == IntPtr.Zero)
                {
                    Console.WriteLine("Error : DLL Not Found");
                    Environment.Exit(-1);
                }
            }

            IntPtr pFunction = ParseExportAddress(hModule, funcName);
            return pFunction;
        }
        //Dynamic invokation of LdrLoadDll
        public static NTSTATUS ldrldll(IntPtr PathToFile, UInt32 dwFlags, ref UNICODE_STRING moduleFileName, ref IntPtr ModuleHandle)
        {
            object[] parms = { PathToFile, dwFlags, moduleFileName, ModuleHandle };
            NTSTATUS res = (NTSTATUS)CreateFunctionDelegate(@"ntdll.dll", @"LdrLoadDll", typeof(rtlinitucodestring), ref parms);

            ModuleHandle = (IntPtr)parms[3];
            return res;
        }

        //dynamic invokation for RtlInitUnicodeString

        public static void rtlinitucodestring(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
        {
            object[] parms = { DestinationString, SourceString };
            CreateFunctionDelegate(@"ntdll.dll", @"RtlInitUnicodeString", typeof(rtlinitucodestring), ref parms);
            DestinationString = (UNICODE_STRING)parms[0];
        }

        //Function for creating delegates

        public static object CreateFunctionDelegate(string dllName, string funcName, Type delegateType, ref object[] parms)
        {
            //Getting address of loaded module
            IntPtr hModule = IntPtr.Zero;
            ProcessModuleCollection procModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in procModules)
            {
                if (Mod.FileName.ToLower().EndsWith(dllName.ToLower()))
                {
                    hModule = Mod.BaseAddress;
                    break;
                }
            }

            //GetLibraryAddress if if it is not found
            if(hModule == IntPtr.Zero)
            {
                //Loading module from disk
                UNICODE_STRING uModuleName = new UNICODE_STRING();
                NTSTATUS res = ldrldll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
                if (res != NTSTATUS.Success || hModule == IntPtr.Zero)
                {
                    Console.WriteLine("Error : DLL Not Found");
                    Environment.Exit(-1);
                }
            }

            IntPtr pFunction = ParseExportAddress(hModule, funcName);

            //Dynamic Function invoke
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pFunction, delegateType);
            return funcDelegate.DynamicInvoke(parms);
        }

        public static IntPtr ParseExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr funcPtr = IntPtr.Zero;

            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3c));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14)); //Size of optional pe header is 20 source: https://blog.kowalczyk.info/articles/pefileformat.html
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            //Read IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 functionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1c));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 ordinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            for (int i = 0; i < NumberOfNames; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + ordinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + functionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    funcPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
            return funcPtr;
        }
    }
}
