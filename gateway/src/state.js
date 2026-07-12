import { mkdir, readFile, readdir, realpath, rename, rm, stat, unlink, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';

const LOCK_TIMEOUT_MS = 30_000;
const LOCK_STALE_MS = 60_000;

function freshState() {
  const now = new Date().toISOString();
  return {
    version: 1,
    createdAt: now,
    updatedAt: now,
    pendingNonces: {},
    devices: {},
    certs: {},
  };
}

function normalizeState(value) {
  const state = value && typeof value === 'object' ? value : {};
  return {
    ...freshState(),
    ...state,
    pendingNonces: state.pendingNonces && typeof state.pendingNonces === 'object' ? state.pendingNonces : {},
    devices: state.devices && typeof state.devices === 'object' ? state.devices : {},
    certs: state.certs && typeof state.certs === 'object' ? state.certs : {},
  };
}

export function createStateStore({ stateDir, lockTimeoutMs = LOCK_TIMEOUT_MS, lockStaleMs = LOCK_STALE_MS }) {
  if (!stateDir) {
    throw new Error('stateDir is required');
  }

  const stateFile = path.join(stateDir, 'state.json');
  const lockDir = path.join(stateDir, 'state.json.lock');
  let updateQueue = Promise.resolve();

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function renameWithRetry(source, destination) {
    const transientCodes = new Set(['EPERM', 'EACCES', 'EBUSY']);
    for (let attempt = 0; attempt < 12; attempt += 1) {
      try {
        await rename(source, destination);
        return;
      } catch (error) {
        if (!transientCodes.has(error.code) || attempt === 11) {
          throw error;
        }
        await sleep(Math.min(500, 20 * (attempt + 1)));
      }
    }
  }

  async function ensureDir() {
    await mkdir(stateDir, { recursive: true });
  }

  async function readStateFile(filePath = stateFile) {
    await ensureDir();
    try {
      return normalizeState(JSON.parse(await readFile(filePath, 'utf8')));
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
      return freshState();
    }
  }

  async function removeStaleTempFiles(excludedFile = null) {
    const stateName = path.basename(stateFile);
    let entries = [];
    try {
      entries = await readdir(stateDir, { withFileTypes: true });
    } catch (error) {
      if (error.code === 'ENOENT') {
        return;
      }
      throw error;
    }

    await Promise.all(entries
      .filter((entry) => entry.isFile()
        && entry.name.startsWith(`${stateName}.`)
        && entry.name.endsWith('.tmp')
        && path.join(stateDir, entry.name) !== excludedFile)
      .map(async (entry) => {
        try {
          await unlink(path.join(stateDir, entry.name));
        } catch (error) {
          if (error.code !== 'ENOENT') {
            throw error;
          }
        }
      }));
  }

  function serializeNextState(state) {
    const next = normalizeState(state);
    next.updatedAt = new Date().toISOString();
    return { next, text: `${JSON.stringify(next, null, 2)}\n` };
  }

  async function readLockMetadata(directory = lockDir) {
    try {
      return JSON.parse(await readFile(path.join(directory, 'owner.json'), 'utf8'));
    } catch {
      return null;
    }
  }

  async function acquireWindowsMutex() {
    await ensureDir();
    const canonicalStateDir = await realpath(stateDir);
    const canonicalStateFile = path.join(canonicalStateDir, path.basename(stateFile));
    const canonicalLockDir = path.join(canonicalStateDir, path.basename(lockDir));
    const physicalStateDir = await stat(canonicalStateDir, { bigint: true });
    const physicalIdentity = `${physicalStateDir.dev}:${physicalStateDir.ino}:${canonicalStateDir.toLowerCase()}:${path.basename(stateFile).toLowerCase()}`;
    const windowsMutexName = `Global\\STMobileGatewayState-${crypto.createHash('sha256').update(physicalIdentity).digest('hex').slice(0, 48)}`;
    const powershell = path.join(
      process.env.SystemRoot ?? 'C:\\Windows',
      'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
    );
    const legacyOwnerToken = crypto.randomUUID();
    const psStateFile = canonicalStateFile.replaceAll("'", "''");
    const psStateDir = canonicalStateDir.replaceAll("'", "''");
    const psLegacyLockDir = canonicalLockDir.replaceAll("'", "''");
    const psLegacyOwnerToken = legacyOwnerToken.replaceAll("'", "''");
    const helperScript = `
$ErrorActionPreference = 'Stop'
$process = [System.Diagnostics.Process]::GetCurrentProcess()
$process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
if ($process.PriorityClass -ne [System.Diagnostics.ProcessPriorityClass]::Idle) { throw 'Mutex helper priority is not Idle.' }
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
public static class StMobileAtomicStateFile {
  const uint DELETE = 0x00010000;
  const uint SYNCHRONIZE = 0x00100000;
  const uint FILE_READ_DATA = 0x00000001;
  const uint FILE_TRAVERSE = 0x00000020;
  const uint FILE_READ_ATTRIBUTES = 0x00000080;
  const uint FILE_SHARE_READ = 0x00000001;
  const uint FILE_SHARE_WRITE = 0x00000002;
  const uint OPEN_EXISTING = 3;
  const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
  const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
  const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
  const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
  const uint FILE_NON_DIRECTORY_FILE = 0x00000040;
  const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
  const uint FILE_OPEN_REPARSE_POINT = 0x00200000;
  const uint OBJ_CASE_INSENSITIVE = 0x00000040;

  [StructLayout(LayoutKind.Sequential)]
  struct FileDispositionInfo {
    [MarshalAs(UnmanagedType.Bool)]
    public bool DeleteFile;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct FileAttributeTagInfo {
    public uint FileAttributes;
    public uint ReparseTag;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct UnicodeString {
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct ObjectAttributes {
    public int Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;
    public uint Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct IoStatusBlock {
    public IntPtr Status;
    public IntPtr Information;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct FileTime {
    public uint Low;
    public uint High;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct ByHandleFileInformation {
    public uint FileAttributes;
    public FileTime CreationTime;
    public FileTime LastAccessTime;
    public FileTime LastWriteTime;
    public uint VolumeSerialNumber;
    public uint FileSizeHigh;
    public uint FileSizeLow;
    public uint NumberOfLinks;
    public uint FileIndexHigh;
    public uint FileIndexLow;
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool CreateDirectory(string path, IntPtr securityAttributes);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool MoveFileEx(string existingName, string newName, int flags);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr CreateFile(
    string fileName,
    uint desiredAccess,
    uint shareMode,
    IntPtr securityAttributes,
    uint creationDisposition,
    uint flagsAndAttributes,
    IntPtr templateFile);

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  static extern bool SetFileInformationByHandle(
    IntPtr file,
    int fileInformationClass,
    ref FileDispositionInfo fileInformation,
    int bufferSize);

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  static extern bool GetFileInformationByHandleEx(
    IntPtr file,
    int fileInformationClass,
    out FileAttributeTagInfo fileInformation,
    int bufferSize);

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  static extern bool GetFileInformationByHandle(IntPtr file, out ByHandleFileInformation information);

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  static extern bool ReadFile(IntPtr file, byte[] buffer, int bytesToRead, out int bytesRead, IntPtr overlapped);

  [DllImport("ntdll.dll")]
  static extern int NtCreateFile(
    out IntPtr file,
    uint desiredAccess,
    ref ObjectAttributes objectAttributes,
    out IoStatusBlock ioStatusBlock,
    IntPtr allocationSize,
    uint fileAttributes,
    uint shareAccess,
    uint createDisposition,
    uint createOptions,
    IntPtr eaBuffer,
    uint eaLength);

  [DllImport("ntdll.dll")]
  static extern int NtSetInformationFile(
    IntPtr file,
    out IoStatusBlock ioStatusBlock,
    IntPtr fileInformation,
    uint length,
    int fileInformationClass);

  [DllImport("ntdll.dll")]
  static extern int NtQueryDirectoryFile(
    IntPtr file,
    IntPtr eventHandle,
    IntPtr apcRoutine,
    IntPtr apcContext,
    out IoStatusBlock ioStatusBlock,
    IntPtr fileInformation,
    uint length,
    int fileInformationClass,
    [MarshalAs(UnmanagedType.U1)] bool returnSingleEntry,
    IntPtr fileName,
    [MarshalAs(UnmanagedType.U1)] bool restartScan);

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool CloseHandle(IntPtr handle);

  public static IntPtr OpenDirectoryGeneration(string directory) {
    return CreateFile(
      directory,
      DELETE | SYNCHRONIZE | FILE_READ_DATA | FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      IntPtr.Zero,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
      IntPtr.Zero);
  }

  public static int GetDirectoryGenerationKind(IntPtr handle) {
    FileAttributeTagInfo info;
    if (!GetFileInformationByHandleEx(handle, 9, out info, Marshal.SizeOf(typeof(FileAttributeTagInfo)))) {
      return -1;
    }
    if ((info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
        || (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
      return 1;
    }
    return 0;
  }

  public static IntPtr OpenPinnedRelativeOwner(IntPtr directory, string relativeName) {
    IntPtr nameBuffer = IntPtr.Zero;
    IntPtr nameStructure = IntPtr.Zero;
    try {
      nameBuffer = Marshal.StringToHGlobalUni(relativeName);
      var name = new UnicodeString {
        Length = checked((ushort)(relativeName.Length * 2)),
        MaximumLength = checked((ushort)((relativeName.Length + 1) * 2)),
        Buffer = nameBuffer
      };
      nameStructure = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
      Marshal.StructureToPtr(name, nameStructure, false);
      var attributes = new ObjectAttributes {
        Length = Marshal.SizeOf(typeof(ObjectAttributes)),
        RootDirectory = directory,
        ObjectName = nameStructure,
        Attributes = OBJ_CASE_INSENSITIVE
      };
      IoStatusBlock statusBlock;
      IntPtr file;
      var status = NtCreateFile(
        out file,
        DELETE | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        ref attributes,
        out statusBlock,
        IntPtr.Zero,
        0,
        FILE_SHARE_READ,
        1,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        IntPtr.Zero,
        0);
      if (status < 0) {
        throw new IOException("Relative owner open failed with NTSTATUS 0x" + status.ToString("X8"));
      }
      return file;
    } finally {
      if (nameStructure != IntPtr.Zero) Marshal.FreeHGlobal(nameStructure);
      if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
    }
  }

  public static string GetOrdinaryFileIdentity(IntPtr file) {
    ByHandleFileInformation information;
    if (!GetFileInformationByHandle(file, out information)) {
      throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
    if ((information.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
      throw new IOException("Refusing non-ordinary or reparse-point legacy owner file.");
    }
    return information.VolumeSerialNumber.ToString("X8") + ":"
      + information.FileIndexHigh.ToString("X8") + information.FileIndexLow.ToString("X8");
  }

  public static string ReadPinnedUtf8(IntPtr file) {
    using (var output = new MemoryStream()) {
      var buffer = new byte[4096];
      while (true) {
        int count;
        if (!ReadFile(file, buffer, buffer.Length, out count, IntPtr.Zero)) {
          var error = Marshal.GetLastWin32Error();
          if (error == 38) break;
          throw new System.ComponentModel.Win32Exception(error);
        }
        if (count == 0) break;
        output.Write(buffer, 0, count);
        if (output.Length > 8 * 1024 * 1024) throw new IOException("Legacy owner metadata exceeds 8 MiB.");
      }
      return new UTF8Encoding(false, true).GetString(output.ToArray());
    }
  }

  public static bool MarkDeleteOnClose(IntPtr handle) {
    var disposition = new FileDispositionInfo { DeleteFile = true };
    return SetFileInformationByHandle(handle, 4, ref disposition, Marshal.SizeOf(disposition));
  }

  public static bool ClearDeleteOnClose(IntPtr handle) {
    var disposition = new FileDispositionInfo { DeleteFile = false };
    return SetFileInformationByHandle(handle, 4, ref disposition, Marshal.SizeOf(disposition));
  }

  public static string[] ListPinnedDirectoryEntries(IntPtr directory) {
    const int statusNoMoreFiles = unchecked((int)0x80000006);
    const int bufferSize = 65536;
    var names = new System.Collections.Generic.List<string>();
    var buffer = Marshal.AllocHGlobal(bufferSize);
    try {
      var restart = true;
      while (true) {
        IoStatusBlock statusBlock;
        var status = NtQueryDirectoryFile(
          directory,
          IntPtr.Zero,
          IntPtr.Zero,
          IntPtr.Zero,
          out statusBlock,
          buffer,
          bufferSize,
          1,
          false,
          IntPtr.Zero,
          restart);
        restart = false;
        if (status == statusNoMoreFiles) break;
        if (status < 0) {
          throw new IOException("Pinned legacy-lock enumeration failed with NTSTATUS 0x" + status.ToString("X8"));
        }
        var offset = 0;
        while (true) {
          var nextOffset = Marshal.ReadInt32(buffer, offset);
          var nameLength = Marshal.ReadInt32(buffer, offset + 60);
          if (nameLength < 0 || (nameLength & 1) != 0 || offset + 64 + nameLength > bufferSize) {
            throw new IOException("Pinned legacy-lock enumeration returned an invalid record.");
          }
          var name = Marshal.PtrToStringUni(new IntPtr(buffer.ToInt64() + offset + 64), nameLength / 2);
          if (!String.IsNullOrEmpty(name) && name != "." && name != "..") names.Add(name);
          if (nextOffset == 0) break;
          if (nextOffset < 64 || offset + nextOffset >= bufferSize) {
            throw new IOException("Pinned legacy-lock enumeration returned an invalid next-entry offset.");
          }
          offset += nextOffset;
        }
      }
      return names.ToArray();
    } finally {
      Marshal.FreeHGlobal(buffer);
    }
  }

  public static void RenameRelativeNoReplace(IntPtr handle, IntPtr parentDirectory, string leafName) {
    if (parentDirectory == new IntPtr(-1) || String.IsNullOrWhiteSpace(leafName)
        || leafName == "." || leafName == ".." || leafName.IndexOf('\\\\') >= 0 || leafName.IndexOf('/') >= 0) {
      throw new ArgumentException("Retirement name must be a single non-empty leaf under the pinned state directory.");
    }
    var nameBytes = Encoding.Unicode.GetBytes(leafName);
    var rootOffset = IntPtr.Size == 8 ? 8 : 4;
    var lengthOffset = rootOffset + IntPtr.Size;
    var nameOffset = lengthOffset + 4;
    var size = checked(nameOffset + nameBytes.Length);
    var buffer = Marshal.AllocHGlobal(size);
    try {
      for (var index = 0; index < size; index++) Marshal.WriteByte(buffer, index, 0);
      Marshal.WriteInt32(buffer, 0, 0);
      Marshal.WriteIntPtr(buffer, rootOffset, parentDirectory);
      Marshal.WriteInt32(buffer, lengthOffset, nameBytes.Length);
      Marshal.Copy(nameBytes, 0, new IntPtr(buffer.ToInt64() + nameOffset), nameBytes.Length);
      IoStatusBlock statusBlock;
      var status = NtSetInformationFile(handle, out statusBlock, buffer, (uint)size, 10);
      if (status < 0) {
        throw new IOException("Exact relative legacy-lock retirement failed with NTSTATUS 0x" + status.ToString("X8"));
      }
    } finally {
      Marshal.FreeHGlobal(buffer);
    }
  }

}
'@
$mutex = New-Object System.Threading.Mutex($false, '${windowsMutexName}')
$stateFile = '${psStateFile}'
$stateDir = '${psStateDir}'
$legacyLockDir = '${psLegacyLockDir}'
$legacyOwnerToken = '${psLegacyOwnerToken}'
$stateName = [System.IO.Path]::GetFileName($stateFile)
$held = $false
$stateDirectoryHandle = [IntPtr](-1)
$legacyDirectoryHandle = [IntPtr](-1)
$legacyOwnerStream = $null
function Move-LegacyDirectoryToRetirement([IntPtr]$DirectoryHandle) {
  if ($stateDirectoryHandle -eq [IntPtr](-1)) {
    throw 'Pinned state-directory handle is unavailable for exact legacy-lock retirement.'
  }
  $retiredName = "$stateName.lock.retired-$([guid]::NewGuid().ToString('N'))"
  [StMobileAtomicStateFile]::RenameRelativeNoReplace(
    $DirectoryHandle,
    $stateDirectoryHandle,
    $retiredName)
  return [System.IO.Path]::Combine($stateDir, $retiredName)
}
function Retire-LegacyDirectoryForDeletion([IntPtr]$DirectoryHandle, [string]$Context) {
  $retiredPath = Move-LegacyDirectoryToRetirement $DirectoryHandle
  # TEST-HARNESS-AFTER-LEGACY-RETIREMENT
  $deleteDispositionSet = $false
  $barrierError = $null
  $entryNames = @()
  try {
    if (-not [StMobileAtomicStateFile]::MarkDeleteOnClose($DirectoryHandle)) {
      $deleteError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      throw (New-Object ComponentModel.Win32Exception($deleteError))
    }
    $deleteDispositionSet = $true
    $entryNames = @([StMobileAtomicStateFile]::ListPinnedDirectoryEntries($DirectoryHandle))
    if ($entryNames.Count -gt 0) {
      throw "Pinned retired legacy-lock generation contains unexpected entries: $($entryNames -join ', ')"
    }
    return $retiredPath
  } catch {
    $barrierError = $_.Exception.Message
    if (-not $deleteDispositionSet) {
      try { $entryNames = @([StMobileAtomicStateFile]::ListPinnedDirectoryEntries($DirectoryHandle)) }
      catch { $barrierError += " Pinned enumeration also failed: $($_.Exception.Message)" }
    }
  }
  if ($deleteDispositionSet) {
    if (-not [StMobileAtomicStateFile]::ClearDeleteOnClose($DirectoryHandle)) {
      $clearError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      throw "$Context failed after exact retirement; delete disposition could not be cleared, so the exact generation is preserved at \${retiredPath}. Barrier: $barrierError. Clear blocker: $((New-Object ComponentModel.Win32Exception($clearError)).Message)"
    }
  }
  $canonicalLeaf = [System.IO.Path]::GetFileName($legacyLockDir)
  try {
    [StMobileAtomicStateFile]::RenameRelativeNoReplace(
      $DirectoryHandle,
      $stateDirectoryHandle,
      $canonicalLeaf)
  } catch {
    $entryText = if ($entryNames.Count -gt 0) { $entryNames -join ', ' } else { '<none-or-unavailable>' }
    throw "$Context failed after exact retirement; the changed generation is preserved at \${retiredPath}. Entries: $entryText. Barrier: $barrierError. Canonical restore blocker: $($_.Exception.Message)"
  }
  $restoredEntries = if ($entryNames.Count -gt 0) { $entryNames -join ', ' } else { '<none-or-unavailable>' }
  throw "$Context failed after exact retirement; the exact generation was restored to $legacyLockDir. Entries: $restoredEntries. Barrier: $barrierError"
}
try {
  try { $held = $mutex.WaitOne(${Math.max(1, Math.trunc(lockTimeoutMs))}) }
  catch [System.Threading.AbandonedMutexException] { $held = $true }
  if (-not $held) { [Console]::Error.WriteLine('LOCK_TIMEOUT'); exit 2 }
  $stateDirectoryHandle = [StMobileAtomicStateFile]::OpenDirectoryGeneration($stateDir)
  if ($stateDirectoryHandle -eq [IntPtr](-1)) {
    $stateDirectoryError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw (New-Object ComponentModel.Win32Exception($stateDirectoryError))
  }
  $stateDirectoryKind = [StMobileAtomicStateFile]::GetDirectoryGenerationKind($stateDirectoryHandle)
  if ($stateDirectoryKind -lt 0) {
    $stateDirectoryAttributeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw (New-Object ComponentModel.Win32Exception($stateDirectoryAttributeError))
  }
  if ($stateDirectoryKind -ne 0) {
    throw "Refusing non-ordinary or reparse-point state directory: $stateDir"
  }
  $legacyOwnerFile = [System.IO.Path]::Combine($legacyLockDir, 'owner.json')
  $legacyDeadline = [DateTime]::UtcNow.AddMilliseconds(${Math.max(1, Math.trunc(lockTimeoutMs))})
  while ($null -eq $legacyOwnerStream) {
    $created = [StMobileAtomicStateFile]::CreateDirectory($legacyLockDir, [IntPtr]::Zero)
    if ($created) {
      $createdDirectoryHandle = [IntPtr](-1)
      $createdOwnerStream = $null
      try {
        $createdDirectoryHandle = [StMobileAtomicStateFile]::OpenDirectoryGeneration($legacyLockDir)
        if ($createdDirectoryHandle -eq [IntPtr](-1)) {
          $directoryError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
          throw (New-Object ComponentModel.Win32Exception($directoryError))
        }
        $directoryKind = [StMobileAtomicStateFile]::GetDirectoryGenerationKind($createdDirectoryHandle)
        if ($directoryKind -lt 0) {
          $attributeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
          throw (New-Object ComponentModel.Win32Exception($attributeError))
        }
        if ($directoryKind -ne 0) {
          throw "Refusing non-ordinary or reparse-point newly-created state lock: $legacyLockDir"
        }
        $ownerRights = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
          [System.Security.AccessControl.FileSystemRights]::Delete
        $createdOwnerStream = [System.IO.FileStream]::new(
          $legacyOwnerFile,
          [System.IO.FileMode]::CreateNew,
          $ownerRights,
          [System.IO.FileShare]::Read,
          4096,
          [System.IO.FileOptions]::WriteThrough)
        $legacyMetadata = [ordered]@{
          pid = $PID
          ownerToken = $legacyOwnerToken
          createdAt = [DateTime]::UtcNow.ToString('o')
          stateFile = $stateFile
          lockProtocol = 'windows-mutex-plus-legacy-directory-v1'
        } | ConvertTo-Json -Compress
        $legacyBytes = [System.Text.UTF8Encoding]::new($false).GetBytes("$legacyMetadata\`n")
        $createdOwnerStream.Write($legacyBytes, 0, $legacyBytes.Length)
        $createdOwnerStream.Flush($true)
        $legacyDirectoryHandle = $createdDirectoryHandle
        $createdDirectoryHandle = [IntPtr](-1)
        $legacyOwnerStream = $createdOwnerStream
        $createdOwnerStream = $null
      } catch {
        $acquisitionFailure = $_.Exception.Message
        $directoryCleanupFailure = $null
        if ($null -ne $createdOwnerStream) {
          try { $null = [StMobileAtomicStateFile]::MarkDeleteOnClose($createdOwnerStream.SafeFileHandle.DangerousGetHandle()) } catch { }
          try { $createdOwnerStream.Dispose() } catch { }
        }
        if ($createdDirectoryHandle -ne [IntPtr](-1)) {
          try {
            $null = Retire-LegacyDirectoryForDeletion $createdDirectoryHandle 'Failed newly-created state-lock cleanup'
          } catch { $directoryCleanupFailure = $_.Exception.Message }
          try { $null = [StMobileAtomicStateFile]::CloseHandle($createdDirectoryHandle) } catch { }
        }
        if ($null -ne $directoryCleanupFailure) {
          throw "$acquisitionFailure Exact cleanup blocker: $directoryCleanupFailure"
        }
        throw $acquisitionFailure
      }
    } else {
      $createError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      if ($createError -ne 183) {
        throw (New-Object ComponentModel.Win32Exception($createError))
      }
      $directoryHandle = [StMobileAtomicStateFile]::OpenDirectoryGeneration($legacyLockDir)
      if ($directoryHandle -ne [IntPtr](-1)) {
        $deleteMarked = $false
        $existingOwnerHandle = [IntPtr](-1)
        $existingOwnerIdentity = $null
        try {
          $directoryKind = [StMobileAtomicStateFile]::GetDirectoryGenerationKind($directoryHandle)
          if ($directoryKind -lt 0) {
            $attributeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw (New-Object ComponentModel.Win32Exception($attributeError))
          }
          if ($directoryKind -ne 0) {
            throw "Refusing non-ordinary or reparse-point legacy state lock: $legacyLockDir"
          }
          $reclaim = $false
          try {
            $existingOwnerHandle = [StMobileAtomicStateFile]::OpenPinnedRelativeOwner($directoryHandle, 'owner.json')
            $existingOwnerIdentity = [StMobileAtomicStateFile]::GetOrdinaryFileIdentity($existingOwnerHandle)
            $existingOwnerText = [StMobileAtomicStateFile]::ReadPinnedUtf8($existingOwnerHandle)
            if ([StMobileAtomicStateFile]::GetOrdinaryFileIdentity($existingOwnerHandle) -cne $existingOwnerIdentity) {
              throw "Legacy owner-file generation changed while pinned: $legacyOwnerFile"
            }
            $existingOwner = $existingOwnerText | ConvertFrom-Json -ErrorAction Stop
            $ownerAlive = $false
            try { $null = [System.Diagnostics.Process]::GetProcessById([int]$existingOwner.pid); $ownerAlive = $true } catch { }
            $createdAt = [DateTime]::MinValue
            $createdAtValid = [DateTime]::TryParse([string]$existingOwner.createdAt, [ref]$createdAt)
            $oldEnough = $createdAtValid -and (([DateTime]::UtcNow - $createdAt.ToUniversalTime()).TotalMilliseconds -gt ${Math.max(1, Math.trunc(lockStaleMs))})
            $reclaim = (-not $ownerAlive) -and (($existingOwner.lockProtocol -eq 'windows-mutex-plus-legacy-directory-v1') -or $oldEnough)
          } catch {
            try {
              $lockAge = ([DateTime]::UtcNow - [System.IO.Directory]::GetLastWriteTimeUtc($legacyLockDir)).TotalMilliseconds
              $reclaim = $lockAge -gt ${Math.max(1, Math.trunc(lockStaleMs))}
            } catch { }
          }
          if ($reclaim) {
            $unexpectedEntries = @(Get-ChildItem -LiteralPath $legacyLockDir -Force -ErrorAction Stop |
              Where-Object { $_.Name -cne 'owner.json' })
            if ($unexpectedEntries.Count -gt 0) {
              throw "Refusing to reclaim legacy state lock with unexpected contents: $legacyLockDir"
            }
            if ($existingOwnerHandle -ne [IntPtr](-1)) {
              if ([StMobileAtomicStateFile]::GetOrdinaryFileIdentity($existingOwnerHandle) -cne $existingOwnerIdentity) {
                throw "Legacy owner-file generation changed before deletion: $legacyOwnerFile"
              }
              if (-not [StMobileAtomicStateFile]::MarkDeleteOnClose($existingOwnerHandle)) {
                $ownerDeleteError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw (New-Object ComponentModel.Win32Exception($ownerDeleteError))
              }
              if (-not [StMobileAtomicStateFile]::CloseHandle($existingOwnerHandle)) {
                $ownerCloseError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw (New-Object ComponentModel.Win32Exception($ownerCloseError))
              }
              $existingOwnerHandle = [IntPtr](-1)
            }
            $remainingEntries = @(Get-ChildItem -LiteralPath $legacyLockDir -Force -ErrorAction Stop)
            if ($remainingEntries.Count -gt 0) {
              throw "Refusing to reclaim legacy state lock after owner deletion because contents remain: $legacyLockDir"
            }
            $null = Retire-LegacyDirectoryForDeletion $directoryHandle 'Stale legacy state-lock reclamation'
            $deleteMarked = $true
          }
        } finally {
          if ($existingOwnerHandle -ne [IntPtr](-1)) {
            if (-not [StMobileAtomicStateFile]::CloseHandle($existingOwnerHandle)) {
              $ownerCloseError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
              throw (New-Object ComponentModel.Win32Exception($ownerCloseError))
            }
          }
          if (-not [StMobileAtomicStateFile]::CloseHandle($directoryHandle)) {
            $closeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw (New-Object ComponentModel.Win32Exception($closeError))
          }
        }
        if ($deleteMarked) { continue }
      }
    }
    if ($null -eq $legacyOwnerStream) {
      if ([DateTime]::UtcNow -gt $legacyDeadline) { throw "Timed out waiting for state lock: $legacyLockDir" }
      Start-Sleep -Milliseconds 20
    }
  }
  [Console]::Out.WriteLine('LOCKED')
  [Console]::Out.Flush()
  $command = [Console]::In.ReadLine()
  $commitPublished = $false
  $unexpectedBeforeCommand = @(Get-ChildItem -LiteralPath $legacyLockDir -Force -ErrorAction Stop |
    Where-Object { $_.Name -cne 'owner.json' })
  if ($unexpectedBeforeCommand.Count -gt 0) {
    if (-not [StMobileAtomicStateFile]::MarkDeleteOnClose($legacyOwnerStream.SafeFileHandle.DangerousGetHandle())) {
      $ownerDeleteError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      throw (New-Object ComponentModel.Win32Exception($ownerDeleteError))
    }
    $legacyOwnerStream.Dispose()
    $legacyOwnerStream = $null
    if (-not [StMobileAtomicStateFile]::CloseHandle($legacyDirectoryHandle)) {
      $directoryCloseError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      throw (New-Object ComponentModel.Win32Exception($directoryCloseError))
    }
    $legacyDirectoryHandle = [IntPtr](-1)
    throw "Refusing state-lock command with unexpected contents: $legacyLockDir"
  }
  if ($command -eq 'COMMIT') {
    $payload = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($payload)) { throw 'COMMIT payload is empty.' }
    $bytes = [Convert]::FromBase64String($payload)
    $temporary = "$stateFile.$PID.$([guid]::NewGuid().ToString('N')).tmp"
    try {
      $stream = [System.IO.File]::Open(
        $temporary,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
      try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
      } finally {
        $stream.Dispose()
      }
      $committed = $false
      for ($attempt = 0; $attempt -lt 12 -and -not $committed; $attempt++) {
        try {
          if (-not [StMobileAtomicStateFile]::MoveFileEx($temporary, $stateFile, 9)) {
            $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw (New-Object ComponentModel.Win32Exception($nativeError))
          }
          $committed = $true
        } catch [System.IO.IOException] {
          if ($attempt -eq 11) { throw }
          Start-Sleep -Milliseconds ([Math]::Min(500, 20 * ($attempt + 1)))
        } catch [System.UnauthorizedAccessException] {
          if ($attempt -eq 11) { throw }
          Start-Sleep -Milliseconds ([Math]::Min(500, 20 * ($attempt + 1)))
        } catch {
          if ($attempt -eq 11) { throw }
          Start-Sleep -Milliseconds ([Math]::Min(500, 20 * ($attempt + 1)))
        }
      }
      $commitPublished = $true
    } finally {
      if ([System.IO.File]::Exists($temporary)) {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
      }
    }
  } elseif ($command -eq 'RELEASE') {
  } else {
    throw "Unsupported mutex-helper command '$command'."
  }

  $cleanupError = $null
  try {
    if ($null -eq $legacyOwnerStream -or $legacyDirectoryHandle -eq [IntPtr](-1)) {
      throw "Legacy state-lock ownership handles were lost before cleanup: $legacyLockDir"
    }
    if (-not [StMobileAtomicStateFile]::MarkDeleteOnClose($legacyOwnerStream.SafeFileHandle.DangerousGetHandle())) {
      $ownerDeleteError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      throw (New-Object ComponentModel.Win32Exception($ownerDeleteError))
    }
    $legacyOwnerStream.Dispose()
    $legacyOwnerStream = $null

    $unexpectedEntries = @(Get-ChildItem -LiteralPath $legacyLockDir -Force -ErrorAction Stop)
    if ($unexpectedEntries.Count -gt 0) {
      throw "Refusing to release owned state lock with unexpected contents: $legacyLockDir"
    }
    $null = Retire-LegacyDirectoryForDeletion $legacyDirectoryHandle 'Owned state-lock release'
    if (-not [StMobileAtomicStateFile]::CloseHandle($legacyDirectoryHandle)) {
      $directoryCloseError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      throw (New-Object ComponentModel.Win32Exception($directoryCloseError))
    }
    $legacyDirectoryHandle = [IntPtr](-1)
  } catch {
    $cleanupError = $_
  }

  if ($null -ne $cleanupError) {
    if (-not $commitPublished) { throw $cleanupError }
    [Console]::Error.WriteLine("POST_COMMIT_LOCK_CLEANUP_PRESERVED: $($cleanupError.Exception.Message)")
  }
  if ($commitPublished) {
    [Console]::Out.WriteLine('COMMITTED')
  } else {
    [Console]::Out.WriteLine('RELEASED')
  }
  [Console]::Out.Flush()
} finally {
  try { if ($null -ne $legacyOwnerStream) { $legacyOwnerStream.Dispose() } } catch { }
  try { if ($legacyDirectoryHandle -ne [IntPtr](-1)) { $null = [StMobileAtomicStateFile]::CloseHandle($legacyDirectoryHandle) } } catch { }
  try { if ($stateDirectoryHandle -ne [IntPtr](-1)) { $null = [StMobileAtomicStateFile]::CloseHandle($stateDirectoryHandle) } } catch { }
  try { if ($held) { $mutex.ReleaseMutex() } } catch { }
  try { $mutex.Dispose() } catch { }
}`;
    const child = spawn(powershell, [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
      '-ExecutionPolicy', 'Bypass', '-Command',
      '$h=$env:ST_MOBILE_MUTEX_HELPER_SCRIPT;Remove-Item Env:ST_MOBILE_MUTEX_HELPER_SCRIPT -ErrorAction SilentlyContinue;&([ScriptBlock]::Create($h))',
    ], {
      windowsHide: true,
      env: { ...process.env, ST_MOBILE_MUTEX_HELPER_SCRIPT: helperScript },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const childClosePromise = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    void childClosePromise.catch(() => {});
    const waitForMarker = (marker, timeoutMs, context) => new Promise((resolve, reject) => {
      let settled = false;
      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.stdout.off('data', onData);
        child.off('error', onError);
        child.off('close', onClose);
        callback(value);
      };
      const onData = () => {
        if (stdout.includes(marker)) {
          finish(resolve);
        }
      };
      const onError = (error) => finish(reject, error);
      const onClose = (code) => {
        finish(reject, new Error(`Windows state mutex helper exited ${code} during ${context}: ${stderr.trim()}`));
      };
      const timer = setTimeout(() => {
        child.kill();
        finish(reject, new Error(`Timed out during ${context} for Windows state mutex helper: ${windowsMutexName}`));
      }, timeoutMs);
      child.stdout.on('data', onData);
      child.once('error', onError);
      child.once('close', onClose);
      onData();
    });
    await waitForMarker('LOCKED', lockTimeoutMs + 5_000, 'acquisition');
    let finished = false;
    const finishCommand = async (command, marker, context) => {
      if (finished) {
        throw new Error(`Windows state mutex helper already finished before ${context}.`);
      }
      if (child.exitCode !== null) {
        throw new Error(`Windows state mutex helper exited ${child.exitCode} before ${context}: ${stderr.trim()}`);
      }
      const markerPromise = waitForMarker(marker, lockTimeoutMs + 5_000, context);
      child.stdin.end(command);
      await markerPromise;
      const { code, signal } = await childClosePromise;
      finished = true;
      if (code !== 0) {
        throw new Error(`Windows state mutex helper closed with code ${code} signal ${signal ?? 'none'} during ${context}: ${stderr.trim()}`);
      }
      if (stderr.trim()) {
        process.stderr.write(`[st-mobile-state-helper] ${stderr.trim()}\n`);
      }
    };
    return {
      stateFile: canonicalStateFile,
      async commit(text) {
        const payload = Buffer.from(text, 'utf8').toString('base64');
        await finishCommand(`COMMIT\n${payload}\n`, 'COMMITTED', 'commit');
      },
      async release() {
        if (!finished) {
          await finishCommand('RELEASE\n', 'RELEASED', 'owner release');
        }
      },
    };
  }

  async function acquirePortableFailClosedLock() {
    await ensureDir();
    const startedAt = Date.now();
    const ownerToken = crypto.randomUUID();
    let attempts = 0;
    while (true) {
      try {
        await mkdir(lockDir, { mode: 0o700 });
        await writeFile(path.join(lockDir, 'owner.json'), `${JSON.stringify({
          pid: process.pid,
          ownerToken,
          createdAt: new Date().toISOString(),
          stateFile,
        }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
        let released = false;
        return {
          stateFile,
          async commit(text) {
            if (released) {
              throw new Error(`Portable state lock was released before commit: ${lockDir}`);
            }
            const tmpFile = `${stateFile}.${process.pid}.${Date.now()}.${crypto.randomUUID()}.tmp`;
            await writeFile(tmpFile, text, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
            await removeStaleTempFiles(tmpFile);
            await renameWithRetry(tmpFile, stateFile);
          },
          async release() {
            if (released) return;
            const current = await readLockMetadata();
            if (current?.ownerToken !== ownerToken || Number(current?.pid) !== process.pid) {
              throw new Error(`Portable state lock ownership changed before release: ${lockDir}`);
            }
            await rm(lockDir, { recursive: true, force: false });
            released = true;
          },
        };
      } catch (error) {
        if (error.code !== 'EEXIST') {
          throw error;
        }
      }
      if (Date.now() - startedAt > lockTimeoutMs) {
        throw new Error(`Timed out waiting for state lock: ${lockDir}`);
      }
      attempts += 1;
      await sleep(Math.min(250, 20 + attempts * 10));
    }
  }

  async function acquireLock() {
    if (process.platform === 'win32') {
      return acquireWindowsMutex();
    }
    // The product's supported desktop is Windows. Other platforms retain a
    // fail-closed owner-token lock and never perform unsafe stale takeover.
    return acquirePortableFailClosedLock();
  }

  async function withLock(fn) {
    const lock = await acquireLock();
    try {
      return await fn(lock);
    } finally {
      await lock.release();
    }
  }

  async function load() {
    return readStateFile();
  }

  async function save(state) {
    return withLock(async (lock) => {
      const serialized = serializeNextState(state);
      await lock.commit(serialized.text);
      return serialized.next;
    });
  }

  async function update(mutator) {
    const run = async () => {
      return withLock(async (lock) => {
        const state = await readStateFile(lock.stateFile);
        const before = JSON.stringify(normalizeState(state));
        const result = await mutator(state);
        const after = JSON.stringify(normalizeState(state));
        if (after !== before) {
          const serialized = serializeNextState(state);
          await lock.commit(serialized.text);
        }
        return result;
      });
    };
    const next = updateQueue.then(run, run);
    updateQueue = next.catch(() => {});
    return next;
  }

  return {
    stateDir,
    stateFile,
    lockDir,
    load,
    save,
    update,
  };
}
