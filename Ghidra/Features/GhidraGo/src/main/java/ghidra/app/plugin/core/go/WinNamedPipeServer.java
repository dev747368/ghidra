/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.go;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.*;
import com.sun.jna.platform.win32.WinBase.SECURITY_ATTRIBUTES;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

import ghidra.app.plugin.core.go.NamedPipe.MessageConsumer;

/**
 * Windows named pipe server / listener.  Uses JNA to call Windows named pipe Kernel methods.
 * <p>
 * Windows named pipes must be located under the special windows \\.\pipe\ path.
 */
public class WinNamedPipeServer extends NamedPipeServer {

	private HANDLE handle;

	public WinNamedPipeServer(File pipeFile, File lockFile, MessageConsumer msgConsumer) {
		super(pipeFile, lockFile, msgConsumer);
	}

	@Override
	public void close() {
		if (listenThread != null) {
			listenThread.interrupt();
			try {
				listenThread.join(LISTEN_THREAD_INTR_MAXWAIT_MS);
			}
			catch (InterruptedException e) {
				// we tried
			}
			listenThread = null;
		}
		if (handle != null) {
			pipeFile.delete(); // kicks any blocked ConnectNamedPipe() calls
			Kernel32.INSTANCE.CloseHandle(handle);
			handle = null;
		}
	}

	@Override
	protected void listenerReadLoopMethod() throws IOException {

		// Lock down the named pipe so that only the current user can use it:
		// SDDL string: "D:(A;;FRFWFXSD;;;OW)"
		// allow the "Owner Rights" (OW) identity to read, write, and execute, modify perms
		SECURITY_ATTRIBUTES secAttrs = createSecurityAttributesFromSddl("D:(A;;FRFWFXSD;;;OW)");
		try {
			//@formatter:off
			HANDLE newHandle = Kernel32.INSTANCE.CreateNamedPipe(
				pipeFile.getPath(),
				WinBase.PIPE_ACCESS_DUPLEX,
				WinBase.PIPE_TYPE_MESSAGE | WinBase.PIPE_READMODE_MESSAGE | WinBase.PIPE_WAIT,
				WinBase.PIPE_UNLIMITED_INSTANCES,
				4096,
				4096,
				0,
				secAttrs);
			//@formatter:on

			if (newHandle == null || WinBase.INVALID_HANDLE_VALUE.equals(newHandle)) {
				throw new IOException("Unable to start named pipe server for %s, error=%d"
						.formatted(pipeFile, Kernel32.INSTANCE.GetLastError()));
			}
			handle = newHandle;
		}
		finally {
			Kernel32.INSTANCE.LocalFree(secAttrs.lpSecurityDescriptor);
		}

		listenThreadReadyLatch.countDown(); // signal start() we are ready to accept connections

		Thread thisThread = Thread.currentThread();
		HANDLE localHandle = handle;

		while (!thisThread.isInterrupted()) {
			boolean connected = Kernel32.INSTANCE.ConnectNamedPipe(localHandle, null);
			if (!connected && Kernel32.INSTANCE.GetLastError() != WinError.ERROR_PIPE_CONNECTED) {
				throw new IOException("Failed to connect named pipe %s, error=%d"
						.formatted(pipeFile, Kernel32.INSTANCE.GetLastError()));
			}

			byte[] buffer = new byte[WinNamedPipe.WIN_MAX_PIPE_MSG_LENGTH];

			IntByReference bytesRead = new IntByReference();
			boolean readOk =
				Kernel32.INSTANCE.ReadFile(localHandle, buffer, buffer.length, bytesRead, null);
			if (!readOk) {
				int lastError = Kernel32.INSTANCE.GetLastError();
				if (lastError != WinError.ERROR_BROKEN_PIPE &&
					lastError != WinError.ERROR_NO_DATA &&
					lastError != WinError.ERROR_INVALID_HANDLE) {
					throw new IOException("Failed to read from named pipe %s, error=%d"
							.formatted(pipeFile, lastError));
				}
				continue;
			}

			try {
				int intBytesRead = bytesRead.getValue();
				if (intBytesRead > 0) {
					String msg = new String(buffer, 0, intBytesRead, StandardCharsets.UTF_8);
					processReceivedMessage(msg);
				}
			}
			finally {
				Kernel32.INSTANCE.DisconnectNamedPipe(localHandle);
			}
		}
	}

	public static SECURITY_ATTRIBUTES createSecurityAttributesFromSddl(String sddl)
			throws IOException {
		WString sddlPtr = new WString(sddl);

		PointerByReference pSD = new PointerByReference();

		boolean success =
			ExtraAdvapi32.INSTANCE.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddlPtr,
				WinNT.SECURITY_DESCRIPTOR_REVISION, pSD, null);

		if (!success) {
			int lastError = Kernel32.INSTANCE.GetLastError();
			throw new IOException("SDDL Conversion failed. Windows Error Code: " + lastError);
		}

		Pointer securityDescriptor = pSD.getValue();

		SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
		sa.lpSecurityDescriptor = securityDescriptor;
		sa.bInheritHandle = false;

		return sa;
	}

	public interface ExtraAdvapi32 extends StdCallLibrary {
		ExtraAdvapi32 INSTANCE =
			com.sun.jna.Native.load("Advapi32", ExtraAdvapi32.class, W32APIOptions.DEFAULT_OPTIONS);

		boolean ConvertStringSecurityDescriptorToSecurityDescriptorW(
				WString StringSecurityDescriptor, int StringSDRevision,
				PointerByReference SecurityDescriptor, Pointer OutputSecurityDescriptorLength);
	}
}
