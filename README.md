# RDPWrapOffsetFinder

Automatically find offsets needed by rdpwrap.ini

## Usage

For 32bit termsrv.dll, use 32bit version. And if it's 64bit termsrv.dll, use 64bit version.

Pass the path of termsrv.dll as command line argument. If not provided, default to current system's termsrv.dll in System32 directory.

## Compile

1. This project depends on [zydis](https://github.com/zyantific/zydis), you needed to build DLL version of zydis first

2. Add `<zydis path>\include;<zydis path>\dependencies\zycore\include;<zydis path>\msvc` as additional include directories

3. Add `<zydis path>\msvc\bin\[Debug/Release]X64\Zydis.lib;Dbghelp.lib` as additional link libraries

4. Build solution

5. After build, copy `dbghelp.dll` `symsrv.dll` `symsrv.yes` (you can find them in Windows SDK) and `Zydis.dll` (also `Zydis.pdb` if you want to debug) to the same directory of the EXE file

## Notes

- Windows 8 Consumer Preview (SLPolicyFunc=New_Win8SL_CP) is currently not supported

- 32bit versions are not widely tested and may return wrong result

- PDB symbol of termsrv.dll is needed. If the program outputs nothing, check your Internet connection to Microsoft symbol server. You can manually set environment variable `_NT_SYMBOL_PATH` to use a symbol proxy
