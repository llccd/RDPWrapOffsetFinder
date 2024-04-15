@echo off
FOR %%f IN (*_x86.dll) DO (
	echo %%f
	..\x64\Release\RDPWrapOffsetFinder.exe %%f > 1.txt
	findstr ERROR 1.txt
	if errorlevel 1 (
	echo Test2: OK
	) ELSE (
	echo Test2: NG
	)
)
FOR %%f IN (*_x64.dll) DO (
	echo %%f
	..\x64\Release\RDPWrapOffsetFinder.exe %%f > 1.txt
	..\x64\Release\RDPWrapOffsetFinder_nosymbol.exe %%f > 2.txt
	fc 1.txt 2.txt > nul
	if errorlevel 1 (
	echo Test1: NG
	) ELSE (
	echo Test1: OK
	)
	findstr ERROR 2.txt
	if errorlevel 1 (
	echo Test2: OK
	) ELSE (
	echo Test2: NG
	)
)
del 1.txt 2.txt