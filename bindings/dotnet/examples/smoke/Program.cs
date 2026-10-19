// Smoke test for the NEXUS-Q .NET SDK.
//
// Run from the repository root:
//   NEXUSQ_LIBRARY=target/debug/libnexusq.so dotnet run --project bindings/dotnet/examples/smoke

Console.WriteLine($"nexusq version: {Nexusq.Version()}");

string dir = Path.Combine(Path.GetTempPath(), $"nexusq_dotnet_smoke_{Path.GetRandomFileName()}");
Directory.CreateDirectory(dir);
string path = Path.Combine(dir, "vault.nqv");

Nexusq.Vault vault = Nexusq.Vault.Create(path, "dotnet-test", "dotnet-smoke");
if (!File.Exists(path)) { Console.Error.WriteLine("vault file was not created"); return 1; }
if (vault.Path != path) { Console.Error.WriteLine("vault.Path does not match input"); return 1; }
if (vault.FormatVersion != 1) { Console.Error.WriteLine($"format_version must be 1, got {vault.FormatVersion}"); return 1; }

Console.WriteLine($"vault created at {vault.Path}");
Console.WriteLine($"vault format version: {vault.FormatVersion}");

bool raised = false;
try
{
    Nexusq.Vault.Create(Path.Combine(dir, "no", "parent", "vault.nqv"), "x");
}
catch (NexusqException e) when (!string.IsNullOrWhiteSpace(e.Message))
{
    raised = true;
}
if (!raised) { Console.Error.WriteLine("creating a vault under a missing directory must fail with a message"); return 1; }

Console.WriteLine("error propagation: ok");
Console.WriteLine("smoke test passed");
return 0;
