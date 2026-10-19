# Deadly Premonition: The Director's Cut - CrashFix & CrashLogger

Crash prevention and diagnostic logging plugins for Deadly Premonition: The Director's Cut (DP.exe).

Note: This project is currently in Beta (v0.9.0-beta). Fixes are actively tested and added throughout playthroughs. Version 1.0 will be tagged once a full playthrough is completed without unhandled crashes.

## Overview

The project is split into two independent ASI plugins:

1. CrashFix (CrashFix.asi)
A lightweight patch plugin that hooks into the game process at runtime to prevent known engine crashes, invalid state transitions, and out-of-bounds navigation table memory access.

2. CrashLogger (CrashLogger.asi)
A diagnostic crash reporter that captures unhandled exceptions, writes minidump files (.dmp), records register states, walks stack backtraces, and logs file access breadcrumbs. Does not modify any game code.

## Current Fixes (v0.9.0-beta)

### Episode 2 Part 1 Art Gallery Cutscene Crash
In the vanilla game, exiting the art gallery cutscene causes an invalid AI state transition for normal NPCs:
- The game assigns an uninitialized waypoint index (-1 / 0xFFFF) to the NPC and sets its state to walk.
- The NPC attempts to navigate towards an invalid destination, causing rotation anomalies and triggering waypoint arrival logic.
- The arrival logic overwrites the NPC's world position with null coordinates (0, 0, 0).
- Subsequent navigation queries dereference invalid memory offsets or null pointers, causing an access violation crash (0x005E1F3D or 0x0047F1CB).

CrashFix resolves this via a three-layer guard:
- Layer 1 (AI State Validation): Prevents NPCs with invalid waypoint indices (-1) from entering walk states; falls back to idle and retains existing position.
- Layer 2 (Position Protection): Guards waypoint arrival handlers against zeroing NPC coordinates when destination queries fail.
- Layer 3 (NavTable Bounds Checking): Hooks 16 navigation table access functions to validate indices against active bounds. Returns writable dummy node structures instead of null pointers, safely handling game functions that perform bitwise operations on returned pointers.

## Requirements

- Deadly Premonition: The Director's Cut (PC / Steam / GOG)
- Ultimate ASI Loader (installed as d3d9.dll in the game root folder)

## Installation

1. Download the latest release from the Releases page.
2. Extract the contents into your game directory:
   - Place CrashFix.asi and CrashFix.ini into the scripts/ folder.
   - Place CrashLogger.asi and CrashLogger.ini into the scripts/ folder.
3. Start the game normally.

Log files and crash reports will be written to scripts/CrashLogs/.

## Configuration

### CrashFix.ini
- Episode2CutsceneWaypointFix (default: 1): Enables AI state and waypoint guards.
- NavTableBoundsFix (default: 1): Enables bounds validation across navigation table methods.
- LogPreventedCrashes (default: 1): Logs prevented invalid memory accesses to scripts/CrashLogs/CrashFix.log.
- MaxPreventedLogs (default: 100): Maximum number of prevented crash entries per session.

### CrashLogger.ini
- Enabled (default: 1): Enables exception filters and minidump generation.
- WriteMiniDump (default: 1): Generates .dmp files compatible with Visual Studio and WinDbg.
- MiniDumpType (default: MiniDumpNormal): Memory dump verbosity level.
- TrackBreadcrumbs (default: 1): Tracks recent file I/O operations for context.

## Building from Source

### Prerequisites
- Windows 7 or newer
- Zig compiler (0.11 or newer) or standard C compiler
- .NET Framework 4.0 or newer (for build helper)

### Build Command
Run build.bat from the repository root:

    build.bat

The compiled binaries (CrashFix.asi and CrashLogger.asi) and configuration files will be generated in the dist/ directory.

## License

MIT License. See LICENSE for details.
