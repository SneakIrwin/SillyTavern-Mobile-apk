$ErrorActionPreference = 'Stop'

if (-not ('StMobile.NativeCommandLine' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace StMobile {
    public static class NativeCommandLine {
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CommandLineToArgvW(string commandLine, out int argumentCount);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static string[] Split(string commandLine) {
            int count;
            IntPtr pointer = CommandLineToArgvW(commandLine, out count);
            if (pointer == IntPtr.Zero) {
                throw new InvalidOperationException("CommandLineToArgvW failed.");
            }
            try {
                string[] arguments = new string[count];
                for (int index = 0; index < count; index++) {
                    IntPtr value = Marshal.ReadIntPtr(pointer, index * IntPtr.Size);
                    arguments[index] = Marshal.PtrToStringUni(value);
                }
                return arguments;
            } finally {
                LocalFree(pointer);
            }
        }
    }
}
'@
}

if (-not ('StMobile.PinnedFileOperations' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace StMobile {
    public sealed class PinnedFileIdentity {
        public string ParentToken { get; private set; }
        public string FileToken { get; private set; }
        internal PinnedFileIdentity(string parentToken, string fileToken) {
            ParentToken = parentToken;
            FileToken = fileToken;
        }
    }

    public sealed class PinnedFileSnapshot {
        public string ParentToken { get; private set; }
        public string FileToken { get; private set; }
        public byte[] Bytes { get; private set; }
        internal PinnedFileSnapshot(string parentToken, string fileToken, byte[] bytes) {
            ParentToken = parentToken;
            FileToken = fileToken;
            Bytes = bytes;
        }
    }

    public sealed class PinnedFileReservation : IDisposable {
        internal IDisposable ParentLease;
        internal SafeFileHandle FileHandle;
        public string Path { get; private set; }
        public string ParentToken { get; private set; }
        public string FileToken { get; private set; }
        public byte[] Bytes { get; private set; }
        internal PinnedFileReservation(string path, string parentToken, string fileToken, byte[] bytes, IDisposable parentLease, SafeFileHandle fileHandle) {
            Path = path; ParentToken = parentToken; FileToken = fileToken;
            Bytes = (byte[])bytes.Clone();
            ParentLease = parentLease; FileHandle = fileHandle;
        }
        public void Retire() { PinnedFileOperations.RetireReservation(this); }
        public void Dispose() {
            if (FileHandle != null) { FileHandle.Dispose(); FileHandle = null; }
            if (ParentLease != null) { ParentLease.Dispose(); ParentLease = null; }
        }
    }

    public sealed class PinnedDirectoryLease : IDisposable {
        private IDisposable inner;
        public string ParentToken { get; private set; }
        internal PinnedDirectoryLease(IDisposable inner, string parentToken) {
            this.inner = inner;
            ParentToken = parentToken;
        }
        public void Dispose() {
            if (inner != null) {
                inner.Dispose();
                inner = null;
            }
        }
    }

    public static class PinnedFileOperations {
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint DELETE = 0x00010000;
        private const uint FILE_LIST_DIRECTORY = 0x00000001;
        private const uint FILE_READ_ATTRIBUTES = 0x00000080;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint CREATE_NEW = 1;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        private const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
        private const int FileRenameInfo = 3;
        private const int FileDispositionInfo = 4;
        private static string TestOperation;
        private static string TestMarker;
        private static string TestContinuation;

        private static void ConfigurePinnedInterlock(string operation, string marker, string continuation) {
            TestOperation = operation;
            TestMarker = marker;
            TestContinuation = continuation;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
            uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file, out BY_HANDLE_FILE_INFORMATION information);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileSizeEx(SafeFileHandle file, out long size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFilePointerEx(
            SafeFileHandle file, long distance, out long newPointer, uint moveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(
            SafeFileHandle file, byte[] buffer, int bytesToRead, out int bytesRead, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile(
            SafeFileHandle file, byte[] buffer, int bytesToWrite, out int bytesWritten, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FlushFileBuffers(SafeFileHandle file);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file, int informationClass, IntPtr information, int bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        public static IntPtr PinProcess(Process process) {
            if (process == null) throw new ArgumentNullException("process");
            IntPtr handle = process.Handle;
            if (handle == IntPtr.Zero) throw new IOException("Could not pin process handle.");
            return handle;
        }

        public static void TerminatePinnedProcess(Process process, uint exitCode) {
            IntPtr handle = PinProcess(process);
            if (!TerminateProcess(handle, exitCode))
                throw Win32("Could not terminate pinned process handle");
        }

        private sealed class PinnedParent : IDisposable {
            internal readonly List<SafeFileHandle> Handles = new List<SafeFileHandle>();
            internal string Token;
            public void Dispose() {
                for (int index = Handles.Count - 1; index >= 0; index--) Handles[index].Dispose();
            }
        }

        private static Exception Win32(string action) {
            return new IOException(action + ": " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
        }

        private static SafeFileHandle Open(string path, uint access, uint share, uint disposition, uint flags) {
            SafeFileHandle handle = CreateFileW(path, access, share, IntPtr.Zero, disposition, flags, IntPtr.Zero);
            if (handle == null || handle.IsInvalid) {
                if (handle != null) handle.Dispose();
                throw Win32("Could not open pinned path " + path);
            }
            return handle;
        }

        private static BY_HANDLE_FILE_INFORMATION Information(SafeFileHandle handle, string path) {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information)) throw Win32("Could not identify pinned path " + path);
            if ((information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new IOException("Pinned path is a reparse point; refusing mutation: " + path);
            return information;
        }

        private static string Token(BY_HANDLE_FILE_INFORMATION information) {
            return information.VolumeSerialNumber.ToString("x8") + ":" +
                information.FileIndexHigh.ToString("x8") + ":" + information.FileIndexLow.ToString("x8");
        }

        private static void RequireToken(string actual, string expected, string kind, string path) {
            if (!String.IsNullOrEmpty(expected) && !String.Equals(actual, expected, StringComparison.Ordinal))
                throw new IOException(kind + " generation changed; refusing mutation: " + path);
        }

        private static void TestPause(string operation) {
            string requested = TestOperation;
            if (!String.Equals(requested, operation, StringComparison.OrdinalIgnoreCase)) return;
            string marker = TestMarker;
            string continuation = TestContinuation;
            if (String.IsNullOrEmpty(marker) || String.IsNullOrEmpty(continuation))
                throw new IOException("Pinned-operation test hook is incomplete.");
            File.WriteAllText(marker, operation);
            DateTime deadline = DateTime.UtcNow.AddSeconds(15);
            while (!File.Exists(continuation)) {
                if (DateTime.UtcNow >= deadline) throw new TimeoutException("Pinned-operation test hook timed out.");
                System.Threading.Thread.Sleep(20);
            }
        }

        private static PinnedParent PinOrdinaryParent(string filePath, string expectedParentToken) {
            string full = Path.GetFullPath(filePath);
            string parentPath = Path.GetDirectoryName(full);
            string root = Path.GetPathRoot(parentPath);
            if (String.IsNullOrEmpty(parentPath) || String.IsNullOrEmpty(root) || root.StartsWith("\\\\", StringComparison.Ordinal))
                throw new IOException("Pinned operations require a local absolute Windows drive path: " + full);
            PinnedParent pinned = new PinnedParent();
            try {
                SafeFileHandle rootHandle = Open(root, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
                pinned.Handles.Add(rootHandle);
                Information(rootHandle, root);
                string current = root.TrimEnd(Path.DirectorySeparatorChar);
                string relative = parentPath.Substring(root.Length);
                string[] parts = relative.Split(new char[] { Path.DirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
                for (int index = 0; index < parts.Length; index++) {
                    current = current.Length == 2 && current[1] == ':'
                        ? current + Path.DirectorySeparatorChar + parts[index]
                        : Path.Combine(current, parts[index]);
                    SafeFileHandle directory = Open(current, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
                    pinned.Handles.Add(directory);
                    BY_HANDLE_FILE_INFORMATION directoryInfo = Information(directory, current);
                    if (index == parts.Length - 1) pinned.Token = Token(directoryInfo);
                }
                if (parts.Length == 0) pinned.Token = Token(Information(rootHandle, root));
                RequireToken(pinned.Token, expectedParentToken, "Parent directory", parentPath);
                return pinned;
            } catch {
                pinned.Dispose();
                throw;
            }
        }

        private static void RequireExactBytes(SafeFileHandle handle, byte[] expected, string path) {
            long size;
            if (!GetFileSizeEx(handle, out size)) throw Win32("Could not size pinned file " + path);
            if (size != expected.LongLength) throw new IOException("Pinned file bytes changed; refusing mutation: " + path);
            long pointer;
            if (!SetFilePointerEx(handle, 0, out pointer, 0)) throw Win32("Could not rewind pinned file " + path);
            byte[] buffer = new byte[Math.Min(65536, Math.Max(1, expected.Length))];
            int offset = 0;
            while (offset < expected.Length) {
                int wanted = Math.Min(buffer.Length, expected.Length - offset);
                int read;
                if (!ReadFile(handle, buffer, wanted, out read, IntPtr.Zero)) throw Win32("Could not read pinned file " + path);
                if (read != wanted) throw new IOException("Pinned file ended during exact-byte validation: " + path);
                for (int index = 0; index < read; index++) {
                    if (buffer[index] != expected[offset + index])
                        throw new IOException("Pinned file bytes changed; refusing mutation: " + path);
                }
                offset += read;
            }
        }

        private static byte[] ReadPinnedBytes(SafeFileHandle handle, string path) {
            long size;
            if (!GetFileSizeEx(handle, out size)) throw Win32("Could not size pinned file " + path);
            if (size < 0 || size > Int32.MaxValue) throw new IOException("Pinned file is too large to snapshot safely: " + path);
            long pointer;
            if (!SetFilePointerEx(handle, 0, out pointer, 0)) throw Win32("Could not rewind pinned file " + path);
            byte[] bytes = new byte[(int)size];
            int offset = 0;
            while (offset < bytes.Length) {
                int read;
                int wanted = Math.Min(65536, bytes.Length - offset);
                byte[] buffer = new byte[wanted];
                if (!ReadFile(handle, buffer, wanted, out read, IntPtr.Zero)) throw Win32("Could not read pinned file " + path);
                if (read != wanted) throw new IOException("Pinned file ended during snapshot: " + path);
                Buffer.BlockCopy(buffer, 0, bytes, offset, read);
                offset += read;
            }
            return bytes;
        }

        private static PinnedFileIdentity InspectOpenFile(
            string full, byte[] expected, string expectedParentToken, string expectedFileToken,
            uint access, uint shareMode, out PinnedParent parent, out SafeFileHandle file) {
            parent = PinOrdinaryParent(full, expectedParentToken);
            file = null;
            try {
                file = Open(full, access | FILE_READ_ATTRIBUTES,
                    shareMode, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT);
                BY_HANDLE_FILE_INFORMATION fileInfo = Information(file, full);
                if (fileInfo.NumberOfLinks != 1) throw new IOException("Pinned file is not a single-link file: " + full);
                string fileToken = Token(fileInfo);
                RequireToken(fileToken, expectedFileToken, "File", full);
                RequireExactBytes(file, expected, full);
                return new PinnedFileIdentity(parent.Token, fileToken);
            } catch {
                if (file != null) file.Dispose();
                parent.Dispose();
                file = null;
                throw;
            }
        }

        public static PinnedFileIdentity InspectExact(string path, byte[] expected, string expectedParentToken, string expectedFileToken) {
            string full = Path.GetFullPath(path);
            PinnedParent parent;
            SafeFileHandle file;
            PinnedFileIdentity identity = InspectOpenFile(full, expected, expectedParentToken, expectedFileToken,
                GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, out parent, out file);
            file.Dispose();
            parent.Dispose();
            return identity;
        }

        public static PinnedFileSnapshot ReadSnapshot(string path, string expectedParentToken) {
            string full = Path.GetFullPath(path);
            using (PinnedParent parent = PinOrdinaryParent(full, expectedParentToken)) {
                using (SafeFileHandle file = Open(full, GENERIC_READ | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT)) {
                    BY_HANDLE_FILE_INFORMATION information = Information(file, full);
                    if (information.NumberOfLinks != 1) throw new IOException("Pinned snapshot source is not a single-link file: " + full);
                    byte[] bytes = ReadPinnedBytes(file, full);
                    return new PinnedFileSnapshot(parent.Token, Token(information), bytes);
                }
            }
        }

        public static PinnedFileReservation ReserveNew(string path, byte[] bytes, string expectedParentToken) {
            string full = Path.GetFullPath(path);
            PinnedParent parent = PinOrdinaryParent(full, expectedParentToken);
            SafeFileHandle file = null;
            bool complete = false;
            try {
                file = Open(full, GENERIC_READ | GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
                    0, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_DELETE_ON_CLOSE);
                BY_HANDLE_FILE_INFORMATION information = Information(file, full);
                if (information.NumberOfLinks != 1) throw new IOException("Pinned reservation is not a single-link file: " + full);
                int written;
                if (bytes.Length > 0 && (!WriteFile(file, bytes, bytes.Length, out written, IntPtr.Zero) || written != bytes.Length))
                    throw Win32("Could not write pinned reservation " + full);
                if (!FlushFileBuffers(file)) throw Win32("Could not flush pinned reservation " + full);
                RequireExactBytes(file, bytes, full);
                TestPause("reserve");
                BY_HANDLE_FILE_INFORMATION exposedInformation = Information(file, full);
                if (exposedInformation.NumberOfLinks != 1) throw new IOException("Pinned reservation link count changed before exposure: " + full);
                RequireToken(Token(exposedInformation), Token(information), "Reservation file", full);
                RequireExactBytes(file, bytes, full);
                complete = true;
                return new PinnedFileReservation(full, parent.Token, Token(information), bytes, parent, file);
            } finally {
                if (!complete) {
                    if (file != null) {
                        file.Dispose();
                    }
                    parent.Dispose();
                }
            }
        }

        internal static void RetireReservation(PinnedFileReservation reservation) {
            if (reservation == null || reservation.FileHandle == null) throw new ObjectDisposedException("PinnedFileReservation");
            try {
                BY_HANDLE_FILE_INFORMATION information = Information(reservation.FileHandle, reservation.Path);
                if (information.NumberOfLinks != 1) throw new IOException("Pinned reservation is not single-link at retirement: " + reservation.Path);
                RequireToken(Token(information), reservation.FileToken, "Reservation file", reservation.Path);
                RequireExactBytes(reservation.FileHandle, reservation.Bytes, reservation.Path);
            } finally {
                reservation.Dispose();
            }
        }

        public static PinnedDirectoryLease PinParent(string path, string expectedParentToken) {
            PinnedParent parent = PinOrdinaryParent(Path.GetFullPath(path), expectedParentToken);
            return new PinnedDirectoryLease(parent, parent.Token);
        }

        public static PinnedFileIdentity CreateNew(string path, byte[] bytes, string expectedParentToken) {
            string full = Path.GetFullPath(path);
            using (PinnedParent parent = PinOrdinaryParent(full, expectedParentToken)) {
                TestPause("create");
                SafeFileHandle file = Open(full, GENERIC_READ | GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
                    0, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH);
                bool complete = false;
                try {
                    BY_HANDLE_FILE_INFORMATION fileInfo = Information(file, full);
                    if (fileInfo.NumberOfLinks != 1) throw new IOException("Pinned create-new file is not single-link: " + full);
                    int written;
                    if (bytes.Length > 0 && (!WriteFile(file, bytes, bytes.Length, out written, IntPtr.Zero) || written != bytes.Length))
                        throw Win32("Could not write pinned create-new file " + full);
                    if (!FlushFileBuffers(file)) throw Win32("Could not flush pinned create-new file " + full);
                    RequireExactBytes(file, bytes, full);
                    BY_HANDLE_FILE_INFORMATION finalInfo = Information(file, full);
                    if (finalInfo.NumberOfLinks != 1) throw new IOException("Pinned create-new file link count changed before publication: " + full);
                    RequireToken(Token(finalInfo), Token(fileInfo), "Created file", full);
                    complete = true;
                    return new PinnedFileIdentity(parent.Token, Token(fileInfo));
                } finally {
                    if (!complete) {
                        IntPtr disposition = Marshal.AllocHGlobal(4);
                        try {
                            Marshal.WriteInt32(disposition, 1);
                            SetFileInformationByHandle(file, FileDispositionInfo, disposition, 4);
                        } finally { Marshal.FreeHGlobal(disposition); }
                    }
                    file.Dispose();
                }
            }
        }

        public static PinnedFileIdentity MoveExact(
            string source, string destination, byte[] expected, string expectedParentToken, string expectedFileToken) {
            string fullSource = Path.GetFullPath(source);
            string fullDestination = Path.GetFullPath(destination);
            if (!String.Equals(Path.GetDirectoryName(fullSource), Path.GetDirectoryName(fullDestination), StringComparison.OrdinalIgnoreCase))
                throw new IOException("Pinned exact-generation quarantine must stay within one parent directory.");
            PinnedParent parent;
            SafeFileHandle file;
            PinnedFileIdentity identity = InspectOpenFile(fullSource, expected, expectedParentToken, expectedFileToken,
                GENERIC_READ | DELETE, FILE_SHARE_READ, out parent, out file);
            try {
                TestPause("move");
                BY_HANDLE_FILE_INFORMATION moveInfo = Information(file, fullSource);
                if (moveInfo.NumberOfLinks != 1) throw new IOException("Pinned move source is not single-link: " + fullSource);
                RequireToken(Token(moveInfo), expectedFileToken, "File", fullSource);
                RequireExactBytes(file, expected, fullSource);
                string destinationName = fullDestination;
                int nameBytes = System.Text.Encoding.Unicode.GetByteCount(destinationName);
                int nameOffset = IntPtr.Size == 8 ? 20 : 12;
                IntPtr rename = Marshal.AllocHGlobal(nameOffset + nameBytes + 2);
                try {
                    for (int index = 0; index < nameOffset + nameBytes + 2; index++) Marshal.WriteByte(rename, index, 0);
                    Marshal.WriteInt32(rename, 0, 0);
                    Marshal.WriteIntPtr(rename, IntPtr.Size == 8 ? 8 : 4, IntPtr.Zero);
                    Marshal.WriteInt32(rename, IntPtr.Size == 8 ? 16 : 8, nameBytes);
                    byte[] encoded = System.Text.Encoding.Unicode.GetBytes(destinationName);
                    Marshal.Copy(encoded, 0, IntPtr.Add(rename, nameOffset), encoded.Length);
                    if (!SetFileInformationByHandle(file, FileRenameInfo, rename, nameOffset + nameBytes + 2))
                        throw Win32("Could not quarantine pinned file " + fullSource);
                } finally { Marshal.FreeHGlobal(rename); }
                return identity;
            } finally {
                file.Dispose();
                parent.Dispose();
            }
        }

        public static void DeleteExact(
            string path, byte[] expected, string expectedParentToken, string expectedFileToken) {
            string full = Path.GetFullPath(path);
            PinnedParent parent;
            SafeFileHandle file;
            InspectOpenFile(full, expected, expectedParentToken, expectedFileToken,
                GENERIC_READ | DELETE, FILE_SHARE_READ, out parent, out file);
            try {
                TestPause("delete");
                BY_HANDLE_FILE_INFORMATION deleteInfo = Information(file, full);
                if (deleteInfo.NumberOfLinks != 1) throw new IOException("Pinned delete target is not single-link: " + full);
                RequireToken(Token(deleteInfo), expectedFileToken, "File", full);
                RequireExactBytes(file, expected, full);
                IntPtr disposition = Marshal.AllocHGlobal(4);
                try {
                    Marshal.WriteInt32(disposition, 1);
                    if (!SetFileInformationByHandle(file, FileDispositionInfo, disposition, 4))
                        throw Win32("Could not delete pinned file generation " + full);
                } finally { Marshal.FreeHGlobal(disposition); }
            } finally {
                file.Dispose();
                parent.Dispose();
            }
        }
    }
}
'@
}

if (-not ('StMobile.ShellLinkSerializer' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace StMobile {
    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    internal class ShellLinkComObject { }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
    internal interface IShellLinkW {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder file, int maximum,
            out WIN32_FIND_DATAW data, uint flags);
        void GetIDList(out IntPtr itemIdList);
        void SetIDList(IntPtr itemIdList);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder description, int maximum);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string description);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder directory, int maximum);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string directory);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder arguments, int maximum);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string arguments);
        void GetHotkey(out short hotkey);
        void SetHotkey(short hotkey);
        void GetShowCmd(out int showCommand);
        void SetShowCmd(int showCommand);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder iconPath, int maximum, out int iconIndex);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string iconPath, int iconIndex);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string path, uint reserved);
        void Resolve(IntPtr window, uint flags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string path);
    }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("00000109-0000-0000-C000-000000000046")]
    internal interface IPersistStreamNative {
        void GetClassID(out Guid classId);
        [PreserveSig] int IsDirty();
        void Load(IStream stream);
        void Save(IStream stream, [MarshalAs(UnmanagedType.Bool)] bool clearDirty);
        void GetSizeMax(out long size);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WIN32_FIND_DATAW {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint Reserved0;
        public uint Reserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string FileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string AlternateFileName;
    }

    public static class ShellLinkSerializer {
        private const uint GMEM_MOVEABLE = 0x0002;

        [DllImport("ole32.dll")]
        private static extern int CreateStreamOnHGlobal(IntPtr global, bool deleteOnRelease, out IStream stream);

        [DllImport("ole32.dll")]
        private static extern int GetHGlobalFromStream(IStream stream, out IntPtr global);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GlobalAlloc(uint flags, UIntPtr bytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GlobalLock(IntPtr global);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalUnlock(IntPtr global);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GlobalFree(IntPtr global);

        private static void HResult(int result, string operation) {
            if (result < 0) Marshal.ThrowExceptionForHR(result, new IntPtr(-1));
        }

        private static IStream NewMemoryStream() {
            IStream stream;
            HResult(CreateStreamOnHGlobal(IntPtr.Zero, true, out stream), "CreateStreamOnHGlobal");
            return stream;
        }

        private static IStream StreamFromBytes(byte[] bytes) {
            IntPtr global = GlobalAlloc(GMEM_MOVEABLE, new UIntPtr((uint)Math.Max(1, bytes.Length)));
            if (global == IntPtr.Zero) throw new OutOfMemoryException("GlobalAlloc failed for shell-link stream.");
            bool ownedByStream = false;
            try {
                IntPtr memory = GlobalLock(global);
                if (memory == IntPtr.Zero) throw new IOException("GlobalLock failed for shell-link stream.");
                try {
                    if (bytes.Length > 0) Marshal.Copy(bytes, 0, memory, bytes.Length);
                } finally { GlobalUnlock(global); }
                IStream stream;
                HResult(CreateStreamOnHGlobal(global, true, out stream), "CreateStreamOnHGlobal");
                ownedByStream = true;
                return stream;
            } finally {
                if (!ownedByStream) GlobalFree(global);
            }
        }

        private static byte[] BytesFromStream(IStream stream) {
            System.Runtime.InteropServices.ComTypes.STATSTG statistics;
            stream.Stat(out statistics, 1);
            if (statistics.cbSize < 0 || statistics.cbSize > Int32.MaxValue)
                throw new IOException("Serialized shell link has an invalid size.");
            IntPtr global;
            HResult(GetHGlobalFromStream(stream, out global), "GetHGlobalFromStream");
            IntPtr memory = GlobalLock(global);
            if (memory == IntPtr.Zero) throw new IOException("GlobalLock failed for serialized shell link.");
            try {
                byte[] bytes = new byte[(int)statistics.cbSize];
                if (bytes.Length > 0) Marshal.Copy(memory, bytes, 0, bytes.Length);
                return bytes;
            } finally { GlobalUnlock(global); }
        }

        private static bool PathEqual(string left, string right) {
            return String.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
        }

        private static void Validate(
            byte[] bytes, string targetPath, string arguments, string workingDirectory,
            string description, int showCommand, string iconPath, int iconIndex) {
            IStream stream = null;
            object comObject = null;
            try {
                stream = StreamFromBytes(bytes);
                comObject = new ShellLinkComObject();
                ((IPersistStreamNative)comObject).Load(stream);
                IShellLinkW link = (IShellLinkW)comObject;
                StringBuilder pathValue = new StringBuilder(32768);
                WIN32_FIND_DATAW data;
                link.GetPath(pathValue, pathValue.Capacity, out data, 4);
                StringBuilder argumentValue = new StringBuilder(32768);
                link.GetArguments(argumentValue, argumentValue.Capacity);
                StringBuilder workingValue = new StringBuilder(32768);
                link.GetWorkingDirectory(workingValue, workingValue.Capacity);
                StringBuilder descriptionValue = new StringBuilder(4096);
                link.GetDescription(descriptionValue, descriptionValue.Capacity);
                StringBuilder iconValue = new StringBuilder(32768);
                int actualIconIndex;
                link.GetIconLocation(iconValue, iconValue.Capacity, out actualIconIndex);
                int actualShowCommand;
                link.GetShowCmd(out actualShowCommand);
                short actualHotkey;
                link.GetHotkey(out actualHotkey);
                if (!PathEqual(pathValue.ToString(), targetPath) ||
                    !String.Equals(argumentValue.ToString(), arguments, StringComparison.Ordinal) ||
                    !PathEqual(workingValue.ToString(), workingDirectory) ||
                    !String.Equals(descriptionValue.ToString(), description, StringComparison.Ordinal) ||
                    actualShowCommand != showCommand || !PathEqual(iconValue.ToString(), iconPath) ||
                    actualIconIndex != iconIndex || actualHotkey != 0)
                    throw new IOException("In-memory shell-link semantic round-trip validation failed.");
            } finally {
                if (comObject != null) Marshal.FinalReleaseComObject(comObject);
                if (stream != null) Marshal.FinalReleaseComObject(stream);
            }
        }

        public static byte[] SerializeAndValidate(
            string targetPath, string arguments, string workingDirectory,
            string description, int showCommand, string iconPath, int iconIndex) {
            object comObject = null;
            IStream stream = null;
            try {
                comObject = new ShellLinkComObject();
                IShellLinkW link = (IShellLinkW)comObject;
                link.SetPath(Path.GetFullPath(targetPath));
                link.SetArguments(arguments ?? String.Empty);
                link.SetWorkingDirectory(Path.GetFullPath(workingDirectory));
                link.SetDescription(description ?? String.Empty);
                link.SetShowCmd(showCommand);
                link.SetIconLocation(Path.GetFullPath(iconPath), iconIndex);
                link.SetHotkey(0);
                stream = NewMemoryStream();
                ((IPersistStreamNative)comObject).Save(stream, true);
                byte[] bytes = BytesFromStream(stream);
                Validate(bytes, targetPath, arguments ?? String.Empty, workingDirectory,
                    description ?? String.Empty, showCommand, iconPath, iconIndex);
                return bytes;
            } finally {
                if (stream != null) Marshal.FinalReleaseComObject(stream);
                if (comObject != null) Marshal.FinalReleaseComObject(comObject);
            }
        }
    }
}
'@
}

function Get-StMobileWindowsPowerShellExecutable {
    $command = Get-Command powershell.exe -ErrorAction SilentlyContinue
    if (-not $command -or [string]::IsNullOrWhiteSpace($command.Source) `
            -or -not (Test-Path -LiteralPath $command.Source)) {
        throw 'Windows PowerShell powershell.exe was not found on PATH.'
    }
    return [System.IO.Path]::GetFullPath($command.Source)
}

function Get-StMobileProcessStartIdentity {
    param([System.Diagnostics.Process]$Process)
    if (-not $Process) {
        return $null
    }
    return $Process.StartTime.ToUniversalTime().ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
        [System.Globalization.CultureInfo]::InvariantCulture)
}

function Assert-StMobilePinnedProcessIdentity {
    param(
        [System.Diagnostics.Process]$Process,
        [string]$ExpectedProcessStartTimeUtc,
        [string]$OwnershipName)
    if (-not $Process) {
        throw "$OwnershipName process capability is absent."
    }
    try {
        [void][StMobile.PinnedFileOperations]::PinProcess($Process)
        if ($Process.HasExited) {
            throw "$OwnershipName exact process exited before the mutation boundary."
        }
        $actualStart = Get-StMobileProcessStartIdentity $Process
    } catch {
        throw "$OwnershipName exact process handle is no longer valid: $($_.Exception.Message)"
    }
    if ($actualStart -cne (ConvertTo-StMobileProcessStartIdentity $ExpectedProcessStartTimeUtc)) {
        throw "$OwnershipName pinned process start identity changed before mutation."
    }
}

function ConvertTo-StMobileProcessStartIdentity {
    param([object]$Value)
    if ($Value -is [datetime]) {
        return ([datetime]$Value).ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return ([string]$Value).Trim()
}

function ConvertTo-WindowsCommandLineArgument {
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value) {
        $Value = ''
    }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            if ($backslashes -gt 0) {
                [void]$builder.Append((('\' * (($backslashes * 2) + 1)) -join ''))
            } else {
                [void]$builder.Append('\')
            }
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append((('\' * $backslashes) -join ''))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append((('\' * ($backslashes * 2)) -join ''))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Join-WindowsCommandLineArguments {
    param([string[]]$Arguments)
    return (($Arguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument $_ }) -join ' ')
}

function Test-StMobilePathEqual {
    param([string]$Left, [string]$Right)
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }
    try {
        return [System.IO.Path]::GetFullPath($Left).Equals(
            [System.IO.Path]::GetFullPath($Right),
            [System.StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function Test-BytesEqual {
    param([byte[]]$Left, [byte[]]$Right)
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }
    return $true
}

function Write-StMobileBytesCreateNew {
    param(
        [string]$Path,
        [byte[]]$Bytes,
        [string]$ExpectedParentToken = '',
        [switch]$PassThru
    )
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Pinned create-new file publication is unavailable off Windows; refusing pathname fallback.'
    }
    $identity = [StMobile.PinnedFileOperations]::CreateNew(
        [System.IO.Path]::GetFullPath($Path),
        $Bytes,
        $ExpectedParentToken)
    if ($PassThru) {
        return $identity
    }
}

function Assert-StMobileNonReparsePath {
    param(
        [string]$Path,
        [string]$OwnershipName
    )
    $current = [System.IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $item = Get-Item -Force -LiteralPath $current -ErrorAction SilentlyContinue
        if ($item -and (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "$OwnershipName path contains a reparse point; preserving it: $current"
        }
        $parent = [System.IO.Directory]::GetParent($current)
        if (-not $parent -or $parent.FullName -ceq $current) {
            break
        }
        $current = $parent.FullName
    }
}

function New-StMobileAuthHubUrlRecordBytes {
    param([object]$GatewayRecord)
    if (-not $GatewayRecord `
            -or -not (Test-StMobileCanonicalGuid $GatewayRecord.instanceId) `
            -or -not (Test-StMobileJsonInteger $GatewayRecord.pid) `
            -or [int64]$GatewayRecord.pid -le 0 `
            -or [int64]$GatewayRecord.pid -gt [int]::MaxValue `
            -or -not (Test-StMobileCanonicalProcessStartIdentity $GatewayRecord.processStartTimeUtc) `
            -or -not (Test-StMobileJsonInteger $GatewayRecord.hubPort) `
            -or [int]$GatewayRecord.hubPort -le 0 `
            -or [int]$GatewayRecord.hubPort -gt 65535) {
        throw 'Cannot construct an auth-hub URL record from an invalid gateway ownership record.'
    }
    $record = [ordered]@{
        schema = 'st-mobile-auth-hub-url/v1'
        gatewayInstanceId = [string]$GatewayRecord.instanceId
        gatewayPid = [int]$GatewayRecord.pid
        gatewayProcessStartTimeUtc = ConvertTo-StMobileProcessStartIdentity $GatewayRecord.processStartTimeUtc
        url = "http://127.0.0.1:$([int]$GatewayRecord.hubPort)/"
    }
    return (New-Object System.Text.UTF8Encoding($false)).GetBytes(
        ($record | ConvertTo-Json -Compress) + [Environment]::NewLine)
}

function Get-StMobileOwnedAuthHubUrlRecord {
    param(
        [string]$Path,
        [object]$GatewayRecord
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $snapshot = [StMobile.PinnedFileOperations]::ReadSnapshot(
        [System.IO.Path]::GetFullPath($Path), '')
    $bytes = $snapshot.Bytes
    try {
        $record = ConvertFrom-StMobileJsonStrict ((New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes))
    } catch {
        throw "Auth-hub URL record is not strict UTF-8 JSON; preserving foreign bytes: $($_.Exception.Message)"
    }
    $fields = @('schema', 'gatewayInstanceId', 'gatewayPid', 'gatewayProcessStartTimeUtc', 'url')
    if (-not (Test-StMobileExactPropertySet $record $fields) `
            -or $record.schema -cne 'st-mobile-auth-hub-url/v1' `
            -or -not (Test-StMobileCanonicalGuid $record.gatewayInstanceId) `
            -or -not (Test-StMobileJsonInteger $record.gatewayPid) `
            -or [int64]$record.gatewayPid -le 0 `
            -or [int64]$record.gatewayPid -gt [int]::MaxValue `
            -or -not (Test-StMobileCanonicalProcessStartIdentity $record.gatewayProcessStartTimeUtc) `
            -or [string]$record.gatewayInstanceId -cne [string]$GatewayRecord.instanceId `
            -or [int]$record.gatewayPid -ne [int]$GatewayRecord.pid `
            -or [string]$record.gatewayProcessStartTimeUtc -cne (ConvertTo-StMobileProcessStartIdentity $GatewayRecord.processStartTimeUtc) `
            -or [string]$record.url -cne "http://127.0.0.1:$([int]$GatewayRecord.hubPort)/") {
        throw 'Auth-hub URL record is foreign, modified, noncanonical, or belongs to another gateway instance; preserving it.'
    }
    $expectedBytes = New-StMobileAuthHubUrlRecordBytes $GatewayRecord
    if (-not (Test-BytesEqual $bytes $expectedBytes)) {
        throw 'Auth-hub URL record JSON bytes are not canonical; preserving them.'
    }
    return [pscustomobject]@{
        Record = $record; Bytes = $bytes
        ParentToken = $snapshot.ParentToken; FileToken = $snapshot.FileToken
    }
}

function Publish-StMobileAuthHubUrlRecord {
    param(
        [string]$Path,
        [object]$GatewayRecord,
        [switch]$AllowLegacyUrlCas
    )
    $expectedBytes = New-StMobileAuthHubUrlRecordBytes $GatewayRecord
    Assert-StMobileNonReparsePath $Path 'auth-hub URL record'
    if (Test-Path -LiteralPath $Path) {
        try {
            $existing = Get-StMobileOwnedAuthHubUrlRecord $Path $GatewayRecord
        } catch {
            if (-not $AllowLegacyUrlCas) {
                throw
            }
            Assert-StMobileNonReparsePath $Path 'legacy auth-hub URL record'
            $legacyBytes = [System.IO.File]::ReadAllBytes($Path)
            $expectedLegacyBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(
                "http://127.0.0.1:$([int]$GatewayRecord.hubPort)/" + [Environment]::NewLine)
            if (-not (Test-BytesEqual $legacyBytes $expectedLegacyBytes)) {
                throw 'Existing auth-hub URL bytes are neither a strict owned record nor the exact legacy marker; preserving them.'
            }
            $priorPath = "$Path.st-mobile-legacy-$([guid]::NewGuid().ToString('N'))"
            $legacyIdentity = [StMobile.PinnedFileOperations]::InspectExact(
                [System.IO.Path]::GetFullPath($Path),
                $legacyBytes,
                '',
                '')
            [void][StMobile.PinnedFileOperations]::MoveExact(
                [System.IO.Path]::GetFullPath($Path),
                [System.IO.Path]::GetFullPath($priorPath),
                $legacyBytes,
                $legacyIdentity.ParentToken,
                $legacyIdentity.FileToken)
            try {
                Assert-StMobileNonReparsePath $priorPath 'quarantined legacy auth-hub URL record'
                if (-not (Test-BytesEqual ([System.IO.File]::ReadAllBytes($priorPath)) $legacyBytes)) {
                    throw 'Legacy auth-hub URL bytes changed during compare-and-swap quarantine.'
                }
                $replacementIdentity = Write-StMobileBytesCreateNew `
                    $Path `
                    $expectedBytes `
                    $legacyIdentity.ParentToken `
                    -PassThru
                $existing = Get-StMobileOwnedAuthHubUrlRecord $Path $GatewayRecord
                if ([string]$existing.ParentToken -cne [string]$replacementIdentity.ParentToken `
                        -or [string]$existing.FileToken -cne [string]$replacementIdentity.FileToken) {
                    throw 'Replacement auth-hub URL generation changed during legacy CAS readback.'
                }
            } catch {
                $failure = $_.Exception.Message
                if (-not (Test-Path -LiteralPath $Path) -and (Test-Path -LiteralPath $priorPath)) {
                    try {
                        [void][StMobile.PinnedFileOperations]::MoveExact(
                            [System.IO.Path]::GetFullPath($priorPath),
                            [System.IO.Path]::GetFullPath($Path),
                            $legacyBytes,
                            $legacyIdentity.ParentToken,
                            $legacyIdentity.FileToken)
                    } catch {}
                }
                throw $failure
            }
            try {
                Remove-StMobileFileIfUnchanged `
                    $priorPath `
                    $legacyBytes `
                    'quarantined legacy auth-hub URL record' `
                    $legacyIdentity.ParentToken `
                    $legacyIdentity.FileToken
            } catch {
                Write-Warning "Auth-hub URL CAS succeeded, but exact legacy quarantine cleanup was blocked and was preserved: $($_.Exception.Message)"
            }
        }
        if (-not (Test-BytesEqual $existing.Bytes $expectedBytes)) {
            throw 'Auth-hub URL record changed before compare-and-swap validation; preserving it.'
        }
        return $existing
    }
    $createdIdentity = Write-StMobileBytesCreateNew $Path $expectedBytes -PassThru
    try {
        $created = Get-StMobileOwnedAuthHubUrlRecord $Path $GatewayRecord
        if ([string]$created.ParentToken -cne [string]$createdIdentity.ParentToken `
                -or [string]$created.FileToken -cne [string]$createdIdentity.FileToken) {
            throw 'Auth-hub URL record generation changed during create-new readback.'
        }
        return $created
    } catch {
        throw "Auth-hub URL record create-new publication failed readback: $($_.Exception.Message)"
    }
}

function New-StMobileTrayStopRequestBytes {
    param(
        [object]$TrayRecord,
        [string]$Nonce
    )
    if (-not $TrayRecord `
            -or -not (Test-StMobileCanonicalGuid $TrayRecord.instanceId) `
            -or -not (Test-StMobileJsonInteger $TrayRecord.pid) `
            -or [int64]$TrayRecord.pid -le 0 `
            -or [int64]$TrayRecord.pid -gt [int]::MaxValue `
            -or -not (Test-StMobileCanonicalProcessStartIdentity $TrayRecord.processStartTimeUtc) `
            -or -not (Test-StMobileCanonicalGuid $TrayRecord.stopCapability) `
            -or -not (Test-StMobileCanonicalGuid $Nonce)) {
        throw 'Cannot construct a tray stop request from an invalid tray ownership record or nonce.'
    }
    $record = [ordered]@{
        schema = 'st-mobile-tray-stop-request/v1'
        trayInstanceId = [string]$TrayRecord.instanceId
        trayPid = [int]$TrayRecord.pid
        trayProcessStartTimeUtc = ConvertTo-StMobileProcessStartIdentity $TrayRecord.processStartTimeUtc
        stopCapability = [string]$TrayRecord.stopCapability
        requestNonce = $Nonce
    }
    return (New-Object System.Text.UTF8Encoding($false)).GetBytes(
        ($record | ConvertTo-Json -Compress) + [Environment]::NewLine)
}

function Get-StMobileOwnedTrayStopRequest {
    param(
        [string]$Path,
        [object]$TrayRecord
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $snapshot = [StMobile.PinnedFileOperations]::ReadSnapshot(
        [System.IO.Path]::GetFullPath($Path), '')
    $bytes = $snapshot.Bytes
    try {
        $record = ConvertFrom-StMobileJsonStrict ((New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes))
    } catch {
        throw "Tray stop request is not strict UTF-8 JSON; preserving foreign bytes: $($_.Exception.Message)"
    }
    $fields = @(
        'schema', 'trayInstanceId', 'trayPid', 'trayProcessStartTimeUtc',
        'stopCapability', 'requestNonce')
    if (-not (Test-StMobileExactPropertySet $record $fields) `
            -or $record.schema -cne 'st-mobile-tray-stop-request/v1' `
            -or -not (Test-StMobileCanonicalGuid $record.trayInstanceId) `
            -or -not (Test-StMobileCanonicalGuid $record.stopCapability) `
            -or -not (Test-StMobileCanonicalGuid $record.requestNonce) `
            -or -not (Test-StMobileJsonInteger $record.trayPid) `
            -or [int64]$record.trayPid -le 0 `
            -or [int64]$record.trayPid -gt [int]::MaxValue `
            -or -not (Test-StMobileCanonicalProcessStartIdentity $record.trayProcessStartTimeUtc) `
            -or [string]$record.trayInstanceId -cne [string]$TrayRecord.instanceId `
            -or [int]$record.trayPid -ne [int]$TrayRecord.pid `
            -or [string]$record.trayProcessStartTimeUtc -cne (ConvertTo-StMobileProcessStartIdentity $TrayRecord.processStartTimeUtc) `
            -or [string]$record.stopCapability -cne [string]$TrayRecord.stopCapability) {
        throw 'Tray stop request is foreign, modified, noncanonical, or belongs to another tray instance; preserving it.'
    }
    $expectedBytes = New-StMobileTrayStopRequestBytes $TrayRecord ([string]$record.requestNonce)
    if (-not (Test-BytesEqual $bytes $expectedBytes)) {
        throw 'Tray stop request JSON bytes are not canonical; preserving them.'
    }
    return [pscustomobject]@{
        Record = $record; Bytes = $bytes
        ParentToken = $snapshot.ParentToken; FileToken = $snapshot.FileToken
    }
}

function Remove-StMobileFileIfUnchanged {
    param(
        [string]$Path, [byte[]]$ExpectedBytes, [string]$OwnershipName,
        [string]$ExpectedParentToken = '',
        [string]$ExpectedFileToken = '')
    if ([string]::IsNullOrWhiteSpace($ExpectedParentToken) -or [string]::IsNullOrWhiteSpace($ExpectedFileToken)) {
        throw "Pinned exact-generation cleanup identity is required for $Path."
    }
    Remove-StMobileFileSetIfUnchanged `
        -Entries @([pscustomobject]@{
            Path = $Path; Bytes = $ExpectedBytes
            ParentToken = $ExpectedParentToken; FileToken = $ExpectedFileToken
        }) `
        -OwnershipName $OwnershipName
}

function Remove-StMobileFileSetIfUnchanged {
    param([object[]]$Entries, [string]$OwnershipName)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Pinned exact-generation cleanup is unavailable off Windows; refusing pathname fallback.'
    }
    $validated = New-Object 'System.Collections.Generic.List[object]'
    foreach ($entry in $Entries) {
        $requiredParentToken = if ($entry.PSObject.Properties.Name -contains 'ParentToken') { [string]$entry.ParentToken } else { '' }
        $requiredFileToken = if ($entry.PSObject.Properties.Name -contains 'FileToken') { [string]$entry.FileToken } else { '' }
        if ([string]::IsNullOrWhiteSpace($requiredParentToken) -or [string]::IsNullOrWhiteSpace($requiredFileToken)) {
            throw "Pinned exact-generation cleanup identity is required for $($entry.Path)."
        }
        $identity = [StMobile.PinnedFileOperations]::InspectExact(
            [System.IO.Path]::GetFullPath([string]$entry.Path),
            [byte[]]$entry.Bytes,
            $requiredParentToken,
            $requiredFileToken)
        $validated.Add([pscustomobject]@{
            Path = [System.IO.Path]::GetFullPath([string]$entry.Path)
            Bytes = [byte[]]$entry.Bytes
            ParentToken = $identity.ParentToken
            FileToken = $identity.FileToken
        })
    }
    $moved = New-Object 'System.Collections.Generic.List[object]'
    $backups = New-Object 'System.Collections.Generic.List[object]'
    $cleanupBackups = $false
    try {
        foreach ($entry in $validated) {
            $tombstone = "$($entry.Path).st-mobile-delete-$([guid]::NewGuid().ToString('N'))"
            $quarantined = [StMobile.PinnedFileOperations]::MoveExact(
                $entry.Path,
                $tombstone,
                $entry.Bytes,
                $entry.ParentToken,
                $entry.FileToken)
            $movedEntry = [pscustomobject]@{
                Original = $entry.Path
                Tombstone = $tombstone
                Bytes = $entry.Bytes
                ParentToken = $quarantined.ParentToken
                FileToken = $quarantined.FileToken
            }
            $moved.Add($movedEntry)
        }
        foreach ($entry in $moved) {
            $backup = "$($entry.Tombstone).restore-$([guid]::NewGuid().ToString('N'))"
            $backupIdentity = [StMobile.PinnedFileOperations]::CreateNew(
                [System.IO.Path]::GetFullPath($backup),
                $entry.Bytes,
                $entry.ParentToken)
            $backups.Add([pscustomobject]@{
                Original = $entry.Original
                Backup = $backup
                Bytes = $entry.Bytes
                ParentToken = $backupIdentity.ParentToken
                FileToken = $backupIdentity.FileToken
            })
        }
        $deleted = 0
        foreach ($entry in $moved) {
            [StMobile.PinnedFileOperations]::DeleteExact(
                $entry.Tombstone,
                $entry.Bytes,
                $entry.ParentToken,
                $entry.FileToken)
            $deleted++
            if (-not [string]::IsNullOrWhiteSpace($env:ST_MOBILE_TEST_FAIL_OWNED_SET_DELETE_AFTER) `
                    -and [int]$env:ST_MOBILE_TEST_FAIL_OWNED_SET_DELETE_AFTER -eq $deleted) {
                throw "Injected owned-set deletion failure after $deleted member(s)."
            }
        }
        $cleanupBackups = $true
    } catch {
        $failure = $_.Exception.Message
        $restoreErrors = New-Object 'System.Collections.Generic.List[string]'
        for ($index = $moved.Count - 1; $index -ge 0; $index--) {
            $entry = $moved[$index]
            try {
                if (Test-Path -LiteralPath $entry.Original) {
                    [void][StMobile.PinnedFileOperations]::InspectExact(
                        $entry.Original,
                        $entry.Bytes,
                        $entry.ParentToken,
                        $entry.FileToken)
                } elseif (Test-Path -LiteralPath $entry.Tombstone) {
                    [void][StMobile.PinnedFileOperations]::MoveExact(
                        $entry.Tombstone,
                        $entry.Original,
                        $entry.Bytes,
                        $entry.ParentToken,
                        $entry.FileToken)
                } else {
                    $backupEntry = $backups | Where-Object { $_.Original -ceq $entry.Original } | Select-Object -First 1
                    if (-not $backupEntry) {
                        throw 'verified restore backup is missing or changed'
                    }
                    [void][StMobile.PinnedFileOperations]::InspectExact(
                        $backupEntry.Backup,
                        $entry.Bytes,
                        $entry.ParentToken,
                        $backupEntry.FileToken)
                    [void][StMobile.PinnedFileOperations]::CreateNew(
                        [System.IO.Path]::GetFullPath($entry.Original),
                        $entry.Bytes,
                        $entry.ParentToken)
                }
            } catch {
                $restoreErrors.Add("$($entry.Original): $($_.Exception.Message)")
            }
        }
        if ($restoreErrors.Count -gt 0) {
            throw "$failure Restore also failed: $($restoreErrors -join '; ')"
        }
        $cleanupBackups = $true
        throw $failure
    } finally {
        if ($cleanupBackups) {
            foreach ($entry in $backups) {
                if (Test-Path -LiteralPath $entry.Backup) {
                    try {
                        [StMobile.PinnedFileOperations]::DeleteExact(
                            $entry.Backup,
                            $entry.Bytes,
                            $entry.ParentToken,
                            $entry.FileToken)
                    } catch {
                        Write-Warning "$OwnershipName exact restore-backup cleanup was blocked and preserved: $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

function Test-StMobileExactPropertySet {
    param([object]$Record, [string[]]$ExpectedNames)
    if (-not $Record) {
        return $false
    }
    $actual = @($Record.PSObject.Properties.Name | Sort-Object)
    $expected = @($ExpectedNames | Sort-Object)
    if ($actual.Count -ne $expected.Count) {
        return $false
    }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ([string]$actual[$index] -cne [string]$expected[$index]) {
            return $false
        }
    }
    return $true
}

function Test-StMobileCanonicalProcessStartIdentity {
    param([object]$Value)
    $text = [string]$Value
    if ($text -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$') {
        return $false
    }
    $parsed = [datetime]::MinValue
    if (-not [datetime]::TryParseExact(
            $text,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed)) {
        return $false
    }
    return $parsed.ToUniversalTime().ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
        [System.Globalization.CultureInfo]::InvariantCulture) -ceq $text
}

function Test-StMobileCanonicalGuid {
    param([object]$Value)
    $parsed = [guid]::Empty
    $text = [string]$Value
    return [guid]::TryParseExact($text, 'D', [ref]$parsed) `
        -and $parsed.ToString('D') -ceq $text
}

function Test-StMobileJsonInteger {
    param([object]$Value)
    return $Value -is [int] -or $Value -is [long]
}

# Rank Audit For Canonical JSON Parsing
# - Rank 4: security and ownership records preserve JSON strings as strings on every supported
#   PowerShell runtime; automatic date coercion must never change validation semantics.
function ConvertFrom-StMobileJsonStrict {
    param([Parameter(Mandatory = $true)][string]$Json)
    $convert = Get-Command ConvertFrom-Json -ErrorAction Stop
    if ($convert.Parameters.ContainsKey('DateKind')) {
        return ConvertFrom-Json -InputObject $Json -DateKind String
    }
    return ConvertFrom-Json -InputObject $Json
}

function Read-StMobileCanonicalPositivePidBytes {
    param([byte[]]$Bytes, [string]$OwnershipName)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        throw "$OwnershipName PID file is empty."
    }
    $text = (New-Object System.Text.ASCIIEncoding).GetString($Bytes)
    $value = 0
    if (-not [int]::TryParse($text.TrimEnd("`r", "`n"), [ref]$value) -or $value -le 0) {
        throw "$OwnershipName PID file is not a canonical positive Windows PID."
    }
    $expected = (New-Object System.Text.ASCIIEncoding).GetBytes(
        ([string]$value) + [Environment]::NewLine)
    if (-not (Test-BytesEqual $Bytes $expected)) {
        throw "$OwnershipName PID file bytes are noncanonical; expected decimal PID plus one platform newline."
    }
    return $value
}

function Test-StMobileCanonicalAbsolutePath {
    param([object]$Value)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value) `
            -or -not [System.IO.Path]::IsPathRooted([string]$Value)) {
        return $false
    }
    try {
        return [System.IO.Path]::GetFullPath([string]$Value) -ceq [string]$Value
    } catch {
        return $false
    }
}

function Test-StMobileGatewayRetryStateRecord {
    param([object]$Record, [int]$MaxAttempts)
    $fields = @(
        'schema', 'stSessionKey', 'stPid', 'stProcessStartTimeUtc',
        'attempts', 'exhausted', 'updatedAtUtc')
    return (Test-StMobileExactPropertySet $Record $fields) `
        -and $Record.schema -ceq 'st-mobile-gateway-retry/v1' `
        -and (Test-StMobileJsonInteger $Record.stPid) `
        -and [int64]$Record.stPid -gt 0 `
        -and (Test-StMobileCanonicalProcessStartIdentity $Record.stProcessStartTimeUtc) `
        -and $Record.stSessionKey -ceq ('{0}|{1}' -f [int64]$Record.stPid, $Record.stProcessStartTimeUtc) `
        -and (Test-StMobileJsonInteger $Record.attempts) `
        -and [int]$Record.attempts -ge 0 `
        -and [int]$Record.attempts -le $MaxAttempts `
        -and $Record.exhausted -is [bool] `
        -and [bool]$Record.exhausted -eq ([int]$Record.attempts -ge $MaxAttempts) `
        -and (Test-StMobileCanonicalProcessStartIdentity $Record.updatedAtUtc)
}

function Test-StMobileGatewaySuppressionStateRecord {
    param([object]$Record)
    $fields = @(
        'schema', 'stSessionKey', 'stPid', 'stProcessStartTimeUtc', 'suppressedAtUtc')
    return (Test-StMobileExactPropertySet $Record $fields) `
        -and $Record.schema -ceq 'st-mobile-gateway-suppression/v1' `
        -and (Test-StMobileJsonInteger $Record.stPid) `
        -and [int64]$Record.stPid -gt 0 `
        -and (Test-StMobileCanonicalProcessStartIdentity $Record.stProcessStartTimeUtc) `
        -and $Record.stSessionKey -ceq ('{0}|{1}' -f [int64]$Record.stPid, $Record.stProcessStartTimeUtc) `
        -and (Test-StMobileCanonicalProcessStartIdentity $Record.suppressedAtUtc)
}

function Read-StMobileBoundedResponseText {
    param(
        [System.Net.WebResponse]$Response,
        [ValidateRange(1, 4194304)][int]$MaxCharacters,
        [ValidateRange(1, 60000)][int]$ReadTimeoutMilliseconds
    )
    $stream = $Response.GetResponseStream()
    if (-not $stream) {
        throw 'HTTP response did not expose a readable body stream.'
    }
    if ($stream.CanTimeout) {
        $stream.ReadTimeout = $ReadTimeoutMilliseconds
    }
    $reader = New-Object System.IO.StreamReader($stream)
    try {
        $builder = New-Object System.Text.StringBuilder
        $buffer = New-Object 'char[]' 4096
        while (($count = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($builder.Length + $count -gt $MaxCharacters) {
                throw "HTTP response body exceeded the $MaxCharacters-character limit."
            }
            [void]$builder.Append($buffer, 0, $count)
        }
        return $builder.ToString()
    } finally {
        $reader.Dispose()
    }
}

function Test-StMobileServedRootChallenge {
    param([int]$Port, [string]$SillyTavernRoot)
    $publicRoot = Join-Path ([System.IO.Path]::GetFullPath($SillyTavernRoot)) 'public'
    if (-not (Test-Path -LiteralPath $publicRoot -PathType Container)) {
        return $false
    }
    $nonce = [guid]::NewGuid().ToString('N')
    $fileName = "st-mobile-root-proof-$nonce.txt"
    $challengePath = [System.IO.Path]::GetFullPath((Join-Path $publicRoot $fileName))
    $challenge = "st-mobile-root-proof-v1:$nonce"
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($challenge)
    $createdIdentity = $null
    $verified = $false
    try {
        $createdIdentity = [StMobile.PinnedFileOperations]::CreateNew(
            $challengePath,
            $bytes,
            '')

        $request = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$Port/$fileName")
        $request.Method = 'GET'
        $request.Proxy = $null
        $request.Timeout = 1000
        $request.ReadWriteTimeout = 1000
        $response = $request.GetResponse()
        try {
            if ([int]$response.StatusCode -ne 200) {
                $verified = $false
            } else {
                $body = Read-StMobileBoundedResponseText `
                    -Response $response `
                    -MaxCharacters 256 `
                    -ReadTimeoutMilliseconds 1000
                $verified = $body -ceq $challenge
            }
        } finally {
            $response.Dispose()
        }
    } catch {
        $verified = $false
    } finally {
        if ($createdIdentity) {
            try {
                [StMobile.PinnedFileOperations]::DeleteExact(
                    $challengePath,
                    $bytes,
                    $createdIdentity.ParentToken,
                    $createdIdentity.FileToken)
            } catch {
                Write-Warning "Exact root-proof challenge cleanup was blocked; preserving the changed generation: $($_.Exception.Message)"
                $verified = $false
            }
        }
    }
    return $verified
}

function Get-ExactArgumentValue {
    param([string[]]$Arguments, [string]$Name)
    $indexes = @()
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        if ($Arguments[$index].Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            $indexes += $index
        }
    }
    if ($indexes.Count -ne 1 -or $indexes[0] + 1 -ge $Arguments.Count) {
        return $null
    }
    return $Arguments[$indexes[0] + 1]
}

function Test-ExactSwitchPresent {
    param([string[]]$Arguments, [string]$Name)
    return @($Arguments | Where-Object { $_.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase) }).Count -eq 1
}

function Test-StMobileExactTrayArguments {
    param(
        [string[]]$Actual,
        [object]$Record
    )

    $expected = @(
        '-NoProfile',
        '-STA',
        '-WindowStyle', 'Hidden',
        '-ExecutionPolicy', 'Bypass',
        '-File', [string]$Record.scriptPath,
        '-Mode', 'Tray',
        '-HubPort', [string]$Record.hubPort,
        '-SillyTavernPort', [string]$Record.sillyTavernPort,
        '-SillyTavernRoot', [string]$Record.sillyTavernRoot,
        '-LauncherIconPath', [string]$Record.launcherIconPath
    )
    if ($Actual.Count -ne $expected.Count) {
        return $false
    }
    $pathValueIndexes = @(7, 15, 17)
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ($pathValueIndexes -contains $index) {
            if (-not (Test-StMobilePathEqual $Actual[$index] $expected[$index])) {
                return $false
            }
        } elseif (-not $Actual[$index].Equals($expected[$index], [System.StringComparison]::Ordinal)) {
            return $false
        }
    }
    return $true
}

function Get-VerifiedStMobileTrayProcess {
    param(
        [string]$RecordPath,
        [object]$RecordSnapshot,
        [string]$PowerShellExe,
        [string]$TrayScriptPath,
        [int]$ExpectedHubPort = 0,
        [int]$ExpectedSillyTavernPort = 0,
        [string]$ExpectedSillyTavernRoot = '',
        [string]$ExpectedLauncherIconPath = '',
        [switch]$ThrowOnInvalid
    )

    function Fail-Verification([string]$Message) {
        if ($ThrowOnInvalid) {
            throw $Message
        }
        return $null
    }

    if (-not $RecordSnapshot -and -not (Test-Path -LiteralPath $RecordPath)) {
        return $null
    }
    try {
        if (-not $RecordSnapshot) {
            $RecordSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot(
                [System.IO.Path]::GetFullPath($RecordPath), '')
        }
        [void][StMobile.PinnedFileOperations]::InspectExact(
            [System.IO.Path]::GetFullPath($RecordPath),
            $RecordSnapshot.Bytes,
            $RecordSnapshot.ParentToken,
            $RecordSnapshot.FileToken)
        $record = ConvertFrom-StMobileJsonStrict ((New-Object System.Text.UTF8Encoding($false, $true)).GetString(
            $RecordSnapshot.Bytes))
    } catch {
        return Fail-Verification "Invalid tray process record $RecordPath`: $($_.Exception.Message)"
    }
    $trayFields = @(
        'schema', 'pid', 'processStartTimeUtc', 'executablePath', 'scriptPath', 'mode',
        'hubPort', 'sillyTavernPort', 'sillyTavernRoot', 'launcherIconPath', 'instanceId',
        'stopCapability')
    if (-not (Test-StMobileExactPropertySet $record $trayFields) `
            -or $record.schema -cne 'st-mobile-tray-process/v2' `
            -or -not (Test-StMobileJsonInteger $record.pid) -or [int64]$record.pid -le 0 -or [int64]$record.pid -gt [int]::MaxValue `
            -or -not (Test-StMobileCanonicalProcessStartIdentity $record.processStartTimeUtc) `
            -or -not (Test-StMobileCanonicalAbsolutePath $record.executablePath) `
            -or [string]$record.executablePath -cne [System.IO.Path]::GetFullPath($PowerShellExe) `
            -or -not (Test-StMobileCanonicalAbsolutePath $record.scriptPath) `
            -or [string]$record.scriptPath -cne [System.IO.Path]::GetFullPath($TrayScriptPath) `
            -or $record.mode -cne 'Tray' `
            -or -not (Test-StMobileJsonInteger $record.hubPort) `
            -or [int]$record.hubPort -le 0 -or [int]$record.hubPort -gt 65535 `
            -or -not (Test-StMobileJsonInteger $record.sillyTavernPort) `
            -or [int]$record.sillyTavernPort -le 0 -or [int]$record.sillyTavernPort -gt 65535 `
            -or -not (Test-StMobileCanonicalAbsolutePath $record.sillyTavernRoot) `
            -or -not (Test-StMobileCanonicalAbsolutePath $record.launcherIconPath) `
            -or -not (Test-StMobileCanonicalGuid $record.instanceId) `
            -or -not (Test-StMobileCanonicalGuid $record.stopCapability)) {
        return Fail-Verification "Tray process record failed ownership validation: $RecordPath"
    }
    if (($ExpectedHubPort -gt 0 -and [int]$record.hubPort -ne $ExpectedHubPort) `
            -or ($ExpectedSillyTavernPort -gt 0 -and [int]$record.sillyTavernPort -ne $ExpectedSillyTavernPort) `
            -or (-not [string]::IsNullOrWhiteSpace($ExpectedSillyTavernRoot) `
                -and [string]$record.sillyTavernRoot -cne [System.IO.Path]::GetFullPath($ExpectedSillyTavernRoot)) `
            -or (-not [string]::IsNullOrWhiteSpace($ExpectedLauncherIconPath) `
                -and [string]$record.launcherIconPath -cne [System.IO.Path]::GetFullPath($ExpectedLauncherIconPath))) {
        return Fail-Verification "Tray process record does not match the caller's expected ports, root, or icon: $RecordPath"
    }
    $candidate = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
    if (-not $candidate) {
        return $null
    }
    try {
        [void][StMobile.PinnedFileOperations]::PinProcess($candidate)
        $actualStart = Get-StMobileProcessStartIdentity $candidate
    } catch {
        return Fail-Verification "Tray PID $($record.pid) could not be pinned for exact-instance verification: $($_.Exception.Message)"
    }
    if ($actualStart -ne (ConvertTo-StMobileProcessStartIdentity $record.processStartTimeUtc)) {
        return $null
    }
    $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($record.pid)" -ErrorAction SilentlyContinue
    if (-not $cim -or -not (Test-StMobilePathEqual $cim.ExecutablePath $PowerShellExe)) {
        return Fail-Verification "Tray PID $($record.pid) executable identity does not match PowerShell."
    }
    try {
        $arguments = [StMobile.NativeCommandLine]::Split([string]$cim.CommandLine)
    } catch {
        return Fail-Verification "Tray PID $($record.pid) command line could not be parsed: $($_.Exception.Message)"
    }
    $processArguments = if ($arguments.Count -gt 1) { @($arguments[1..($arguments.Count - 1)]) } else { @() }
    $identityMatches = (Test-StMobilePathEqual $arguments[0] $PowerShellExe) `
        -and (Test-StMobileExactTrayArguments $processArguments $record)
    if (-not $identityMatches) {
        return Fail-Verification "Tray PID $($record.pid) command line does not match its exact ownership record."
    }
    if ($candidate.MainWindowHandle -ne 0) {
        return Fail-Verification "Tray PID $($record.pid) owns a visible main window."
    }
    return [pscustomobject]@{ Process = $candidate; Record = $record; Cim = $cim; RecordSnapshot = $RecordSnapshot }
}

function Get-StMobileTrayOwnershipState {
    param(
        [string]$RecordPath,
        [object]$RecordSnapshot,
        [string]$PowerShellExe,
        [string]$TrayScriptPath,
        [int]$ExpectedHubPort = 0,
        [int]$ExpectedSillyTavernPort = 0,
        [string]$ExpectedSillyTavernRoot = '',
        [string]$ExpectedLauncherIconPath = '')
    if (-not (Test-Path -LiteralPath $RecordPath)) {
        return [pscustomobject]@{ State = 'Absent'; Verified = $null; Error = '' }
    }
    try {
        $verified = Get-VerifiedStMobileTrayProcess `
            -RecordPath $RecordPath `
            -RecordSnapshot $RecordSnapshot `
            -PowerShellExe $PowerShellExe `
            -TrayScriptPath $TrayScriptPath `
            -ExpectedHubPort $ExpectedHubPort `
            -ExpectedSillyTavernPort $ExpectedSillyTavernPort `
            -ExpectedSillyTavernRoot $ExpectedSillyTavernRoot `
            -ExpectedLauncherIconPath $ExpectedLauncherIconPath `
            -ThrowOnInvalid
        if ($verified) {
            return [pscustomobject]@{ State = 'OwnedLive'; Verified = $verified; Error = '' }
        }
        return [pscustomobject]@{ State = 'OwnedStale'; Verified = $null; Error = '' }
    } catch {
        return [pscustomobject]@{ State = 'Conflict'; Verified = $null; Error = $_.Exception.Message }
    }
}

function Test-StMobileExactGatewayArguments {
    param(
        [string[]]$Actual,
        [object]$Record
    )
    $expected = @(
        [string]$Record.cliPath,
        'serve',
        '--host', [string]$Record.publicHost,
        '--port', [string]$Record.port,
        '--hub-port', [string]$Record.hubPort
    )
    if ($Actual.Count -ne $expected.Count) {
        return $false
    }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ($index -eq 0) {
            if (-not (Test-StMobilePathEqual $Actual[$index] $expected[$index])) {
                return $false
            }
        } elseif (-not $Actual[$index].Equals($expected[$index], [System.StringComparison]::Ordinal)) {
            return $false
        }
    }
    return $true
}

function Get-VerifiedStMobileGatewayProcess {
    param(
        [string]$RecordPath,
        [object]$RecordSnapshot,
        [string]$NodeExe,
        [string]$GatewayCli,
        [string]$PublicHost,
        [int]$Port,
        [int]$HubPort,
        [switch]$RequireListeners,
        [switch]$ThrowOnInvalid
    )

    function Fail-GatewayVerification([string]$Message) {
        if ($ThrowOnInvalid) {
            throw $Message
        }
        return $null
    }

    if (-not $RecordSnapshot -and -not (Test-Path -LiteralPath $RecordPath)) {
        return $null
    }
    try {
        if (-not $RecordSnapshot) {
            $RecordSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot(
                [System.IO.Path]::GetFullPath($RecordPath), '')
        }
        [void][StMobile.PinnedFileOperations]::InspectExact(
            [System.IO.Path]::GetFullPath($RecordPath),
            $RecordSnapshot.Bytes,
            $RecordSnapshot.ParentToken,
            $RecordSnapshot.FileToken)
        $record = ConvertFrom-StMobileJsonStrict ((New-Object System.Text.UTF8Encoding($false, $true)).GetString(
            $RecordSnapshot.Bytes))
    } catch {
        return Fail-GatewayVerification "Invalid gateway process record $RecordPath`: $($_.Exception.Message)"
    }
    $gatewayFields = @(
        'schema', 'pid', 'processStartTimeUtc', 'executablePath', 'cliPath',
        'publicHost', 'port', 'hubPort', 'instanceId')
    if (-not (Test-StMobileExactPropertySet $record $gatewayFields) `
            -or $record.schema -cne 'st-mobile-gateway-process/v1' `
            -or -not (Test-StMobileJsonInteger $record.pid) -or [int64]$record.pid -le 0 -or [int64]$record.pid -gt [int]::MaxValue `
            -or -not (Test-StMobileCanonicalProcessStartIdentity $record.processStartTimeUtc) `
            -or -not (Test-StMobileCanonicalAbsolutePath $record.executablePath) `
            -or [string]$record.executablePath -cne [System.IO.Path]::GetFullPath($NodeExe) `
            -or -not (Test-StMobileCanonicalAbsolutePath $record.cliPath) `
            -or [string]$record.cliPath -cne [System.IO.Path]::GetFullPath($GatewayCli) `
            -or [string]$record.publicHost -cne $PublicHost `
            -or -not (Test-StMobileJsonInteger $record.port) `
            -or -not (Test-StMobileJsonInteger $record.hubPort) `
            -or [int]$record.port -ne $Port -or [int]$record.hubPort -ne $HubPort `
            -or -not (Test-StMobileCanonicalGuid $record.instanceId)) {
        return Fail-GatewayVerification "Gateway process record failed ownership validation: $RecordPath"
    }
    $candidate = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
    if (-not $candidate) {
        return $null
    }
    try {
        [void][StMobile.PinnedFileOperations]::PinProcess($candidate)
        $candidateStart = Get-StMobileProcessStartIdentity $candidate
    } catch {
        return Fail-GatewayVerification "Gateway PID $($record.pid) could not be pinned for exact-instance verification: $($_.Exception.Message)"
    }
    if ($candidateStart -ne (ConvertTo-StMobileProcessStartIdentity $record.processStartTimeUtc)) {
        return $null
    }
    $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($record.pid)" -ErrorAction SilentlyContinue
    if (-not $cim -or -not (Test-StMobilePathEqual $cim.ExecutablePath $NodeExe)) {
        return Fail-GatewayVerification "Gateway PID $($record.pid) executable identity does not match node.exe."
    }
    try {
        $arguments = [StMobile.NativeCommandLine]::Split([string]$cim.CommandLine)
    } catch {
        return Fail-GatewayVerification "Gateway PID $($record.pid) command line could not be parsed: $($_.Exception.Message)"
    }
    $processArguments = if ($arguments.Count -gt 1) { @($arguments[1..($arguments.Count - 1)]) } else { @() }
    if (-not (Test-StMobilePathEqual $arguments[0] $NodeExe) `
            -or -not (Test-StMobileExactGatewayArguments $processArguments $record)) {
        return Fail-GatewayVerification "Gateway PID $($record.pid) command line does not match its exact ownership record."
    }
    if ($candidate.MainWindowHandle -ne 0) {
        return Fail-GatewayVerification "Gateway PID $($record.pid) owns a visible main window."
    }
    if ($RequireListeners) {
        $gatewayListeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
        $hubListeners = @(Get-NetTCPConnection -State Listen -LocalPort $HubPort -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1') })
        if (-not ($gatewayListeners | Where-Object { $_.OwningProcess -eq [int]$record.pid }) `
                -or -not ($hubListeners | Where-Object { $_.OwningProcess -eq [int]$record.pid })) {
            return Fail-GatewayVerification "Gateway PID $($record.pid) does not own both expected gateway and loopback hub listeners."
        }
    }
    return [pscustomobject]@{ Process = $candidate; Record = $record; Cim = $cim; RecordSnapshot = $RecordSnapshot }
}

function Get-StMobileGatewayOwnershipState {
    param(
        [string]$RecordPath,
        [object]$RecordSnapshot,
        [string]$NodeExe,
        [string]$GatewayCli,
        [string]$PublicHost,
        [int]$Port,
        [int]$HubPort,
        [switch]$RequireListeners
    )
    if (-not (Test-Path -LiteralPath $RecordPath)) {
        return [pscustomobject]@{ State = 'Absent'; Verified = $null; Error = '' }
    }
    try {
        $arguments = @{
            RecordPath = $RecordPath
            RecordSnapshot = $RecordSnapshot
            NodeExe = $NodeExe
            GatewayCli = $GatewayCli
            PublicHost = $PublicHost
            Port = $Port
            HubPort = $HubPort
            ThrowOnInvalid = $true
        }
        if ($RequireListeners) {
            $arguments.RequireListeners = $true
        }
        $verified = Get-VerifiedStMobileGatewayProcess @arguments
        if ($verified) {
            return [pscustomobject]@{ State = 'OwnedLive'; Verified = $verified; Error = '' }
        }
        return [pscustomobject]@{ State = 'OwnedStale'; Verified = $null; Error = '' }
    } catch {
        return [pscustomobject]@{ State = 'Conflict'; Verified = $null; Error = $_.Exception.Message }
    }
}

function Test-SillyTavernHttpIdentity {
    param([int]$Port)
    try {
        $request = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$Port/")
        $request.Method = 'GET'
        $request.Proxy = $null
        $request.Timeout = 1000
        $request.ReadWriteTimeout = 1000
        $response = $request.GetResponse()
        try {
            if ([int]$response.StatusCode -ne 200) {
                return $false
            }
            $content = Read-StMobileBoundedResponseText `
                -Response $response `
                -MaxCharacters 1048576 `
                -ReadTimeoutMilliseconds 1000
        } finally {
            $response.Dispose()
        }
        $anchors = @(
            '<title>\s*SillyTavern\s*</title>',
            'href=["'']manifest\.json["'']',
            'href=["'']css/st-tailwind\.css["'']',
            'id=["'']top-settings-holder["'']',
            'id=["'']ai-config-button["'']'
        )
        return -not ($anchors | Where-Object { $content -notmatch $_ } | Select-Object -First 1)
    } catch {
        return $false
    }
}

function Test-StMobileSillyTavernRecordStructure {
    param(
        [object]$Record,
        [string]$ExpectedRoot,
        [string]$ExpectedServerScript,
        [string]$ExpectedExecutablePath
    )
    $fields = @(
        'schema', 'pid', 'processStartTimeUtc', 'executablePath', 'sillyTavernRoot',
        'serverScriptPath', 'provenance', 'instanceId', 'rootProofMethod', 'rootProofAtUtc')
    return (Test-StMobileExactPropertySet $Record $fields) `
        -and $Record.schema -ceq 'st-mobile-sillytavern-process/v2' `
        -and (Test-StMobileJsonInteger $Record.pid) `
        -and [int64]$Record.pid -gt 0 -and [int64]$Record.pid -le [int]::MaxValue `
        -and (Test-StMobileCanonicalProcessStartIdentity $Record.processStartTimeUtc) `
        -and (Test-StMobileCanonicalGuid $Record.instanceId) `
        -and (Test-StMobileCanonicalProcessStartIdentity $Record.rootProofAtUtc) `
        -and $Record.rootProofMethod -cin @('served-random-challenge-v1', 'absolute-server-argv-v1') `
        -and $Record.provenance -cin @('st-launcher-option-1', 'start-st-mobile') `
        -and (Test-StMobileCanonicalAbsolutePath $Record.executablePath) `
        -and (Test-StMobileCanonicalAbsolutePath $Record.sillyTavernRoot) `
        -and (Test-StMobileCanonicalAbsolutePath $Record.serverScriptPath) `
        -and [string]$Record.sillyTavernRoot -ceq [System.IO.Path]::GetFullPath($ExpectedRoot) `
        -and [string]$Record.serverScriptPath -ceq [System.IO.Path]::GetFullPath($ExpectedServerScript) `
        -and ([string]::IsNullOrWhiteSpace($ExpectedExecutablePath) `
            -or [string]$Record.executablePath -ceq [System.IO.Path]::GetFullPath($ExpectedExecutablePath))
}

function Get-StMobileSillyTavernCandidateSession {
    param(
        [int]$Port,
        [string]$SillyTavernRoot,
        [object]$TrustedRecord,
        [switch]$IncludeProcessCapability
    )
    $rootPath = [System.IO.Path]::GetFullPath($SillyTavernRoot)
    $serverScript = Join-Path $rootPath 'server.js'
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1') })
    $owners = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
    if ($owners.Count -ne 1) {
        return $null
    }
    $process = Get-Process -Id ([int]$owners[0]) -ErrorAction SilentlyContinue
    if ($process -and $IncludeProcessCapability) {
        try { [void][StMobile.PinnedFileOperations]::PinProcess($process) } catch { return $null }
    }
    $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($owners[0])" -ErrorAction SilentlyContinue
    if (-not $process -or -not $cim -or $process.ProcessName -ne 'node' `
            -or -not (Test-StMobilePathEqual $cim.ExecutablePath $process.Path) `
            -or -not (Test-Path -LiteralPath $serverScript) `
            -or -not (Test-SillyTavernHttpIdentity -Port $Port)) {
        return $null
    }
    try {
        $arguments = [StMobile.NativeCommandLine]::Split([string]$cim.CommandLine)
    } catch {
        return $null
    }
    if ($arguments.Count -ne 2) {
        return $null
    }
    $startTime = Get-StMobileProcessStartIdentity $process
    $rootProofMethod = $null
    $rootProofAtUtc = $null
    $trustedRecordMatches = $TrustedRecord `
        -and (Test-StMobileSillyTavernRecordStructure `
            -Record $TrustedRecord `
            -ExpectedRoot $rootPath `
            -ExpectedServerScript $serverScript `
            -ExpectedExecutablePath ([string]$cim.ExecutablePath)) `
        -and [int]$TrustedRecord.pid -eq $process.Id `
        -and (ConvertTo-StMobileProcessStartIdentity $TrustedRecord.processStartTimeUtc) -ceq $startTime
    if ([System.IO.Path]::IsPathRooted([string]$arguments[1])) {
        if (-not (Test-StMobilePathEqual $arguments[1] $serverScript)) {
            return $null
        }
        $rootProofMethod = 'absolute-server-argv-v1'
        if ($trustedRecordMatches -and $TrustedRecord.rootProofMethod -ceq $rootProofMethod) {
            $rootProofAtUtc = ConvertTo-StMobileProcessStartIdentity $TrustedRecord.rootProofAtUtc
        } elseif ($TrustedRecord) {
            return $null
        } else {
            $rootProofAtUtc = [DateTime]::UtcNow.ToString(
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                [System.Globalization.CultureInfo]::InvariantCulture)
        }
    } elseif ([string]$arguments[1] -ceq 'server.js') {
        if ($trustedRecordMatches -and $TrustedRecord.rootProofMethod -ceq 'served-random-challenge-v1') {
            $rootProofMethod = [string]$TrustedRecord.rootProofMethod
            $rootProofAtUtc = ConvertTo-StMobileProcessStartIdentity $TrustedRecord.rootProofAtUtc
        } elseif ($TrustedRecord) {
            return $null
        } elseif (Test-StMobileServedRootChallenge -Port $Port -SillyTavernRoot $rootPath) {
            $rootProofMethod = 'served-random-challenge-v1'
            $rootProofAtUtc = [DateTime]::UtcNow.ToString(
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                [System.Globalization.CultureInfo]::InvariantCulture)
        } else {
            return $null
        }
    } else {
        return $null
    }
    $result = [pscustomobject]@{
        Pid = $process.Id
        ProcessStartTimeUtc = $startTime
        Key = '{0}|{1}' -f $process.Id, $startTime
        ExecutablePath = [string]$cim.ExecutablePath
        SillyTavernRoot = $rootPath
        ServerScriptPath = [System.IO.Path]::GetFullPath($serverScript)
        RootProofMethod = $rootProofMethod
        RootProofAtUtc = $rootProofAtUtc
    }
    if ($IncludeProcessCapability) {
        $result | Add-Member -NotePropertyName ProcessCapability -NotePropertyValue $process
    }
    return $result
}

function Write-StMobileSillyTavernRecord {
    param(
        [object]$Session,
        [string]$RecordPath,
        [ValidateSet('st-launcher-option-1', 'start-st-mobile')][string]$Provenance
    )
    if (-not $Session -or -not (Test-StMobileJsonInteger $Session.Pid) -or [int64]$Session.Pid -le 0 `
            -or [string]::IsNullOrWhiteSpace([string]$Session.ProcessStartTimeUtc) `
            -or -not (Test-StMobileCanonicalProcessStartIdentity $Session.ProcessStartTimeUtc) `
            -or $Session.RootProofMethod -cnotin @('served-random-challenge-v1', 'absolute-server-argv-v1') `
            -or -not (Test-StMobileCanonicalProcessStartIdentity $Session.RootProofAtUtc) `
            -or -not (Test-StMobileCanonicalAbsolutePath $Session.ExecutablePath) `
            -or -not (Test-StMobileCanonicalAbsolutePath $Session.SillyTavernRoot) `
            -or -not (Test-StMobileCanonicalAbsolutePath $Session.ServerScriptPath) `
            -or -not (Test-Path -LiteralPath $Session.ServerScriptPath)) {
        throw 'Cannot publish a trusted SillyTavern record from an incomplete session.'
    }

    $existingBytes = $null
    $existingIdentity = $null
    if (Test-Path -LiteralPath $RecordPath) {
        $existingBytes = [System.IO.File]::ReadAllBytes($RecordPath)
        $existingIdentity = [StMobile.PinnedFileOperations]::InspectExact(
            [System.IO.Path]::GetFullPath($RecordPath),
            $existingBytes,
            '',
            '')
        try {
            $existing = ConvertFrom-StMobileJsonStrict ((New-Object System.Text.UTF8Encoding($false, $true)).GetString($existingBytes))
        } catch {
            throw "Existing SillyTavern ownership record is invalid; refusing overwrite: $($_.Exception.Message)"
        }
        $legacyFields = @(
            'schema', 'pid', 'processStartTimeUtc', 'executablePath', 'sillyTavernRoot',
            'serverScriptPath', 'provenance', 'instanceId')
        $legacyExact = (Test-StMobileExactPropertySet $existing $legacyFields) `
            -and $existing.schema -ceq 'st-mobile-sillytavern-process/v1' `
            -and (Test-StMobileJsonInteger $existing.pid) `
            -and [int64]$existing.pid -gt 0 `
            -and (Test-StMobileCanonicalProcessStartIdentity $existing.processStartTimeUtc) `
            -and (Test-StMobileCanonicalGuid $existing.instanceId) `
            -and (Test-StMobileCanonicalAbsolutePath $existing.executablePath) `
            -and (Test-StMobileCanonicalAbsolutePath $existing.sillyTavernRoot) `
            -and (Test-StMobileCanonicalAbsolutePath $existing.serverScriptPath) `
            -and [string]$existing.executablePath -ceq [System.IO.Path]::GetFullPath([string]$Session.ExecutablePath) `
            -and [string]$existing.sillyTavernRoot -ceq [System.IO.Path]::GetFullPath([string]$Session.SillyTavernRoot) `
            -and [string]$existing.serverScriptPath -ceq [System.IO.Path]::GetFullPath([string]$Session.ServerScriptPath) `
            -and $existing.provenance -cin @('st-launcher-option-1', 'start-st-mobile')
        $currentExact = Test-StMobileSillyTavernRecordStructure `
            -Record $existing `
            -ExpectedRoot $Session.SillyTavernRoot `
            -ExpectedServerScript $Session.ServerScriptPath `
            -ExpectedExecutablePath $Session.ExecutablePath
        if (-not $legacyExact -and -not $currentExact) {
            throw 'Existing SillyTavern ownership record is foreign or modified; refusing overwrite.'
        }
        $existingProcess = Get-Process -Id ([int]$existing.pid) -ErrorAction SilentlyContinue
        $existingStart = if ($existingProcess) { Get-StMobileProcessStartIdentity $existingProcess } else { $null }
        if ($existingProcess -and $existingStart -eq (ConvertTo-StMobileProcessStartIdentity $existing.processStartTimeUtc)) {
            if ([int]$existing.pid -eq [int]$Session.Pid `
                    -and $existingStart -eq (ConvertTo-StMobileProcessStartIdentity $Session.ProcessStartTimeUtc)) {
                if ($currentExact) {
                    return $existing
                }
                # An exact legacy v1 record for this same live process may advance only
                # after the caller has supplied the new root proof fields validated above.
            } else {
                throw 'Existing SillyTavern ownership record still names a live different process; refusing overwrite.'
            }
        }
    }

    $record = [ordered]@{
        schema = 'st-mobile-sillytavern-process/v2'
        pid = [int]$Session.Pid
        processStartTimeUtc = ConvertTo-StMobileProcessStartIdentity $Session.ProcessStartTimeUtc
        executablePath = [System.IO.Path]::GetFullPath([string]$Session.ExecutablePath)
        sillyTavernRoot = [System.IO.Path]::GetFullPath([string]$Session.SillyTavernRoot)
        serverScriptPath = [System.IO.Path]::GetFullPath([string]$Session.ServerScriptPath)
        provenance = $Provenance
        instanceId = [guid]::NewGuid().ToString('D')
        rootProofMethod = [string]$Session.RootProofMethod
        rootProofAtUtc = ConvertTo-StMobileProcessStartIdentity $Session.RootProofAtUtc
    }
    $recordBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(
        ($record | ConvertTo-Json) + [Environment]::NewLine)
    if ($existingBytes) {
        $priorPath = "$RecordPath.st-mobile-prior-$([guid]::NewGuid().ToString('N'))"
        $quarantinedIdentity = [StMobile.PinnedFileOperations]::MoveExact(
            [System.IO.Path]::GetFullPath($RecordPath),
            [System.IO.Path]::GetFullPath($priorPath),
            $existingBytes,
            $existingIdentity.ParentToken,
            $existingIdentity.FileToken)
        try {
            $publishedIdentity = [StMobile.PinnedFileOperations]::CreateNew(
                [System.IO.Path]::GetFullPath($RecordPath),
                $recordBytes,
                $existingIdentity.ParentToken)
            [void][StMobile.PinnedFileOperations]::InspectExact(
                [System.IO.Path]::GetFullPath($RecordPath),
                $recordBytes,
                $publishedIdentity.ParentToken,
                $publishedIdentity.FileToken)
        } catch {
            $failure = $_.Exception.Message
            if (-not (Test-Path -LiteralPath $RecordPath)) {
                try {
                    [void][StMobile.PinnedFileOperations]::MoveExact(
                        [System.IO.Path]::GetFullPath($priorPath),
                        [System.IO.Path]::GetFullPath($RecordPath),
                        $existingBytes,
                        $quarantinedIdentity.ParentToken,
                        $quarantinedIdentity.FileToken)
                } catch {
                    $failure += " Exact legacy ownership-record rollback was blocked; quarantine preserved at ${priorPath}: $($_.Exception.Message)"
                }
            }
            throw $failure
        }
        try {
            [StMobile.PinnedFileOperations]::DeleteExact(
                [System.IO.Path]::GetFullPath($priorPath),
                $existingBytes,
                $quarantinedIdentity.ParentToken,
                $quarantinedIdentity.FileToken)
        } catch {
            Write-Warning "Published v2 SillyTavern ownership, but exact prior-record cleanup was blocked: $($_.Exception.Message)"
        }
    } else {
        $publishedIdentity = [StMobile.PinnedFileOperations]::CreateNew(
            [System.IO.Path]::GetFullPath($RecordPath),
            $recordBytes,
            '')
        [void][StMobile.PinnedFileOperations]::InspectExact(
            [System.IO.Path]::GetFullPath($RecordPath),
            $recordBytes,
            $publishedIdentity.ParentToken,
            $publishedIdentity.FileToken)
    }
    return [pscustomobject]$record
}

function Get-SillyTavernSession {
    param(
        [int]$Port,
        [string]$SillyTavernRoot,
        [string]$RecordPath,
        [object]$RecordSnapshot,
        [switch]$IncludeProcessCapability,
        [switch]$ThrowOnInvalid
    )

    function Fail-SillyTavernVerification([string]$Message) {
        if ($ThrowOnInvalid) {
            throw $Message
        }
        return $null
    }

    if (-not $RecordSnapshot -and -not (Test-Path -LiteralPath $RecordPath)) {
        return $null
    }
    try {
        if (-not $RecordSnapshot) {
            $RecordSnapshot = [StMobile.PinnedFileOperations]::ReadSnapshot(
                [System.IO.Path]::GetFullPath($RecordPath), '')
        }
        [void][StMobile.PinnedFileOperations]::InspectExact(
            [System.IO.Path]::GetFullPath($RecordPath),
            $RecordSnapshot.Bytes,
            $RecordSnapshot.ParentToken,
            $RecordSnapshot.FileToken)
        $record = ConvertFrom-StMobileJsonStrict ((New-Object System.Text.UTF8Encoding($false, $true)).GetString(
            $RecordSnapshot.Bytes))
    } catch {
        return Fail-SillyTavernVerification "Invalid SillyTavern ownership record $RecordPath`: $($_.Exception.Message)"
    }
    $rootPath = [System.IO.Path]::GetFullPath($SillyTavernRoot)
    $serverScript = [System.IO.Path]::GetFullPath((Join-Path $rootPath 'server.js'))
    if (-not (Test-StMobileSillyTavernRecordStructure `
            -Record $record `
            -ExpectedRoot $rootPath `
            -ExpectedServerScript $serverScript `
            -ExpectedExecutablePath '')) {
        return Fail-SillyTavernVerification 'SillyTavern ownership record failed exact structural validation.'
    }
    $candidateArguments = @{
        Port = $Port
        SillyTavernRoot = $rootPath
        TrustedRecord = $record
    }
    if ($IncludeProcessCapability) { $candidateArguments.IncludeProcessCapability = $true }
    $session = Get-StMobileSillyTavernCandidateSession @candidateArguments
    if (-not $session) {
        return $null
    }
    if ([int]$record.pid -ne [int]$session.Pid `
            -or (ConvertTo-StMobileProcessStartIdentity $record.processStartTimeUtc) -ne (ConvertTo-StMobileProcessStartIdentity $session.ProcessStartTimeUtc) `
            -or [string]$record.executablePath -cne [System.IO.Path]::GetFullPath([string]$session.ExecutablePath) `
            -or [string]$record.sillyTavernRoot -cne [System.IO.Path]::GetFullPath([string]$session.SillyTavernRoot) `
            -or [string]$record.serverScriptPath -cne [System.IO.Path]::GetFullPath([string]$session.ServerScriptPath) `
            -or $record.rootProofMethod -cne $session.RootProofMethod `
            -or (ConvertTo-StMobileProcessStartIdentity $record.rootProofAtUtc) -cne (ConvertTo-StMobileProcessStartIdentity $session.RootProofAtUtc)) {
        return Fail-SillyTavernVerification 'Live SillyTavern listener does not match its exact trusted launcher record.'
    }
    $session | Add-Member -NotePropertyName Record -NotePropertyValue $record
    return $session
}

function Test-SillyTavernSessionAlive {
    param([object]$Session)
    if (-not $Session) {
        return $false
    }
    $process = Get-Process -Id ([int]$Session.Pid) -ErrorAction SilentlyContinue
    return $process -and (Get-StMobileProcessStartIdentity $process) -eq (ConvertTo-StMobileProcessStartIdentity $Session.ProcessStartTimeUtc)
}
