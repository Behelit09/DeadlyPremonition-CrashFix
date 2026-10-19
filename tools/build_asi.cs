using System;
using System.Diagnostics;
using System.IO;

class Program {
    static int Main(string[] args) {
        if (args.Length < 2) {
            Console.WriteLine("Usage: build_asi.exe <source.c> <output.asi> [extra_libs...]");
            return 1;
        }

        string srcFile = Path.GetFullPath(args[0]);
        string outFile = Path.GetFullPath(args[1]);
        string extraLibs = args.Length > 2 ? string.Join(" ", args, 2, args.Length - 2) : "";

        string root = AppDomain.CurrentDomain.BaseDirectory;
        string cwd = Directory.GetCurrentDirectory();
        string zigExe = Environment.GetEnvironmentVariable("ZIG_EXE");

        if (string.IsNullOrEmpty(zigExe) || !File.Exists(zigExe)) {
            string[] candidates = new string[] {
                Path.Combine(cwd, "..\\.zig\\zig.exe"),
                Path.Combine(cwd, ".zig\\zig.exe"),
                Path.Combine(root, "..\\..\\.zig\\zig.exe"),
                Path.Combine(root, "..\\.zig\\zig.exe"),
                Path.Combine(root, ".zig\\zig.exe"),
                "C:\\zig\\zig.exe"
            };
            foreach (var cand in candidates) {
                if (File.Exists(cand)) {
                    zigExe = Path.GetFullPath(cand);
                    break;
                }
            }
        }

        if (string.IsNullOrEmpty(zigExe) || !File.Exists(zigExe)) {
            Console.WriteLine("[!] zig.exe not found. Set ZIG_EXE environment variable.");
            return 1;
        }

        string zigDir = Path.GetDirectoryName(zigExe);
        string includeDir = Path.Combine(zigDir, "lib\\libc\\include\\any-windows-any");
        string cacheDir = Path.Combine(Path.GetDirectoryName(outFile), ".zig-cache");

        if (!Directory.Exists(cacheDir)) Directory.CreateDirectory(cacheDir);

        string tmpDir = Path.Combine(cacheDir, "tmp");
        string hDir = Path.Combine(cacheDir, "h");
        string expectedObj = Path.Combine(tmpDir, Path.GetFileNameWithoutExtension(srcFile) + ".obj");
        string directObj = Path.ChangeExtension(srcFile, ".obj");

        if (File.Exists(expectedObj)) try { File.Delete(expectedObj); } catch { }
        if (File.Exists(directObj)) try { File.Delete(directObj); } catch { }
        if (Directory.Exists(hDir)) {
            foreach (var f in Directory.GetFiles(hDir)) {
                try { File.Delete(f); } catch { }
            }
        }

        // Step 1: Compile .c to .obj
        string compileArgs = string.Format("cc -target x86-windows -nostdlib -I\"{0}\" -O2 -shared \"{1}\" -o \"{2}\"",
            includeDir, srcFile, outFile);

        var psi = new ProcessStartInfo {
            FileName = zigExe,
            Arguments = compileArgs,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.EnvironmentVariables["ZIG_GLOBAL_CACHE_DIR"] = cacheDir;
        psi.EnvironmentVariables["ZIG_LOCAL_CACHE_DIR"] = cacheDir;

        var proc = Process.Start(psi);
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();

        string objToLink = null;
        if (File.Exists(directObj)) {
            objToLink = directObj;
        } else if (File.Exists(expectedObj)) {
            objToLink = expectedObj;
        } else {
            Console.WriteLine("[!] Compilation failed:\n" + stderr);
            return 1;
        }

        // Step 2: Link .obj to .asi
        string linkArgs = string.Format("cc -target x86-windows -nostdlib -shared -Wl,-e,DllMain@12 \"{0}\" -o \"{1}\" -lkernel32 -luser32 -lgdi32 {2}",
            objToLink, outFile, extraLibs);

        var linkPsi = new ProcessStartInfo {
            FileName = zigExe,
            Arguments = linkArgs,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        linkPsi.EnvironmentVariables["ZIG_GLOBAL_CACHE_DIR"] = cacheDir;
        linkPsi.EnvironmentVariables["ZIG_LOCAL_CACHE_DIR"] = cacheDir;

        var linkProc = Process.Start(linkPsi);
        string linkStdout = linkProc.StandardOutput.ReadToEnd();
        string linkStderr = linkProc.StandardError.ReadToEnd();
        linkProc.WaitForExit();

        if (linkProc.ExitCode != 0) {
            Console.WriteLine("[!] Linking failed:\n" + linkStderr);
            return 1;
        }

        Console.WriteLine("[*] Successfully built: " + outFile);
        return 0;
    }
}
