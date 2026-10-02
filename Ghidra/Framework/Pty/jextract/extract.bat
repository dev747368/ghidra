:: ###
:: IP: GHIDRA
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.
:: ##
::Run this from this same directory
@echo off
:: After extraction, manual edits are required to implement the captureState for LastError

call C:\Software\jextract-25\bin\jextract ^
  --output ..\src\main\java ^
  --target-package com.microsoft.win32 ^
  win32.h ^
  --include-function AssignProcessToJobObject ^
  --include-function CloseHandle ^
  --include-function ClosePseudoConsole ^
  --include-function ConnectNamedPipe ^
  --include-function CreateNamedPipeW ^
  --include-function CreatePipe ^
  --include-function CreateFileW ^
  --include-function CreateJobObjectW ^
  --include-function CreateProcessW ^
  --include-function CreatePseudoConsole ^
  --include-function DisconnectNamedPipe ^
  --include-function SetNamedPipeHandleState ^
  --include-function FlushFileBuffers ^
  --include-function FormatMessageW ^
  --include-function GetExitCodeProcess ^
  --include-function InitializeProcThreadAttributeList ^
  --include-function LocalFree ^
  --include-function ReadFile ^
  --include-function ResizePseudoConsole ^
  --include-function TerminateJobObject ^
  --include-function UpdateProcThreadAttribute ^
  --include-function WaitForSingleObject ^
  --include-function WaitNamedPipeW ^
  --include-function WriteFile ^
  --include-struct _COORD ^
  --include-struct _PROCESS_INFORMATION ^
  --include-struct _STARTUPINFOW ^
  --include-struct _STARTUPINFOEXW ^
  --include-typedef DWORD ^
  --include-typedef UINT ^
  --include-typedef HANDLE ^
  --include-typedef HRESULT ^
  --include-typedef LPWSTR ^
  --include-constant S_OK ^
  --include-constant CREATE_UNICODE_ENVIRONMENT ^
  --include-constant ERROR_BROKEN_PIPE ^
  --include-constant ERROR_PIPE_CONNECTED ^
  --include-constant ERROR_PIPE_LISTENING ^
  --include-constant EXTENDED_STARTUPINFO_PRESENT ^
  --include-constant FORMAT_MESSAGE_FROM_SYSTEM ^
  --include-constant FORMAT_MESSAGE_IGNORE_INSERTS ^
  --include-constant FORMAT_MESSAGE_ARGUMENT_ARRAY ^
  --include-constant FORMAT_MESSAGE_ALLOCATE_BUFFER ^
  --include-constant PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE ^
  --include-constant STARTF_USESTDHANDLES ^
  --include-constant STILL_ACTIVE ^
  --include-constant WAIT_ABANDONED ^
  --include-constant WAIT_FAILED ^
  --include-constant WAIT_OBJECT_0 ^
  --include-constant WAIT_TIMEOUT ^
  --include-constant GENERIC_WRITE ^
  --include-constant OPEN_EXISTING ^
  --include-constant PIPE_READMODE_MESSAGE ^
  --include-constant PIPE_ACCESS_DUPLEX ^
  --include-constant PIPE_TYPE_MESSAGE ^
  --include-constant PIPE_WAIT ^
  --include-constant PIPE_UNLIMITED_INSTANCES ^
  --include-constant ERROR_NO_DATA ^
  --include-constant ERROR_INVALID_HANDLE ^
  --include-constant INVALID_HANDLE_VALUE ^
  --include-constant ERROR_SEM_TIMEOUT ^
  --library Kernel32

call C:\Software\jextract-25\bin\jextract ^
  --output ..\src\main\java ^
  --target-package com.microsoft.win32 ^
  win32_sddl.h ^
  --include-function ConvertStringSecurityDescriptorToSecurityDescriptorW ^
  --include-struct _SECURITY_ATTRIBUTES ^
  --include-constant SECURITY_DESCRIPTOR_REVISION ^
  --library Advapi32
  