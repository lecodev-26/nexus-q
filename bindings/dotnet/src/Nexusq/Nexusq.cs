// NEXUS-Q C# / .NET bindings.
//
// This is a thin P/Invoke wrapper over the stable C SDK. It does not
// reimplement cryptography or business logic; every operation delegates to
// libnexusq.
//
// The library is resolved from the NEXUSQ_LIBRARY environment variable when
// set, otherwise the OS loader default is used. Build the C SDK first:
// cargo build -p nexusq-c

using System.Runtime.InteropServices;

/// <summary>Error raised when a NEXUS-Q operation fails.</summary>
public class NexusqException : Exception
{
    public NexusqException(string? message) : base(string.IsNullOrWhiteSpace(message) ? "NEXUS-Q operation failed" : message) { }
}

/// <summary>NEXUS-Q SDK entry point.</summary>
public static partial class Nexusq
{
    private const string LibraryName = "nexusq";

    static Nexusq()
    {
        // Resolve "nexusq" through NEXUSQ_LIBRARY when set; otherwise fall
        // back to the OS loader search.
        NativeLibrary.SetDllImportResolver(typeof(Nexusq).Assembly, (name, _, _) =>
            name == LibraryName && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NEXUSQ_LIBRARY"))
                ? NativeLibrary.Load(Environment.GetEnvironmentVariable("NEXUSQ_LIBRARY")!)
                : IntPtr.Zero);
    }

    // The C SDK takes and returns NUL-terminated UTF-8 strings; the marshalling
    // below pins that contract explicitly on every platform.
    [LibraryImport(LibraryName, EntryPoint = "nexusq_version", StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr version_ptr();

    [LibraryImport(LibraryName, EntryPoint = "nexusq_last_error_message", StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr last_error_ptr();

    [LibraryImport(LibraryName, EntryPoint = "nexusq_vault_create", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int vault_create(string path, string password, string? label);

    [LibraryImport(LibraryName, EntryPoint = "nexusq_vault_format_version", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int vault_format_version(string path);

    private static string PtrToString(IntPtr p) => Marshal.PtrToStringUTF8(p) ?? "";

    /// <summary>Returns the library version string.</summary>
    public static string Version() => PtrToString(version_ptr());

    /// <summary>Returns the last error message on the calling thread, or null.</summary>
    public static string? LastError()
    {
        IntPtr p = last_error_ptr();
        return p == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(p);
    }

    /// <summary>A NEXUS-Q vault created on disk.</summary>
    /// <param name="path">Path of the vault file on disk.</param>
    /// <param name="formatVersion">Format version byte of the vault (currently 1).</param>
    public sealed record Vault(string Path, int FormatVersion)
    {
        /// <summary>
        /// Creates a new vault at <paramref name="path"/> with the given
        /// <paramref name="password"/>. <paramref name="label"/> is optional.
        /// Throws <see cref="NexusqException"/> when the operation fails; the
        /// message is borrowed from the library's last error.
        /// </summary>
        public static Vault Create(string path, string password, string? label = null)
        {
            int rc = vault_create(path, password, label);
            if (rc != 0)
            {
                throw new NexusqException(LastError());
            }
            int formatVersion = vault_format_version(path);
            if (formatVersion < 0)
            {
                throw new NexusqException(LastError());
            }
            return new Vault(path, formatVersion);
        }
    }
}
