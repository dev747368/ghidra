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

import static ghidra.app.plugin.core.go.WinNamedPipe.WIN_MAX_PIPE_MSG_LENGTH;

import java.io.File;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import com.microsoft.win32._SECURITY_ATTRIBUTES;
import com.microsoft.win32.win32_h;
import com.microsoft.win32.win32_sddl_h;

import ghidra.app.plugin.core.go.NamedPipe.MessageConsumer;
import ghidra.pty.windows.Handle;
import ghidra.pty.windows.Win32Err;

/**
 * Windows named pipe server / listener.  Uses java native to call Windows named pipe Kernel methods.
 * <p>
 * Windows named pipes must be located under the special windows \\.\pipe\ path.
 */
public class WinNamedPipeServer extends NamedPipeServer {

	public WinNamedPipeServer(File pipeFile, File lockFile, MessageConsumer msgConsumer) {
		super(pipeFile, lockFile, msgConsumer);

	}

	@Override
	public void close() {
		if (listenThread != null) {
			listenThread.interrupt();
			pipeFile.delete(); // kicks any blocked ConnectNamedPipe() calls

			try {
				listenThread.join(LISTEN_THREAD_INTR_MAXWAIT_MS);
			}
			catch (InterruptedException e) {
				// we tried
			}
			listenThread = null;
		}
	}

	@Override
	protected void listenerReadLoopMethod() throws IOException {
		Thread thisThread = Thread.currentThread();
		Handle handle = null;

		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);

			byte[] javabuffer = new byte[WIN_MAX_PIPE_MSG_LENGTH];

			MemorySegment winbuffer = arena.allocate(javabuffer.length);
			MemorySegment dwBytesRead = arena.allocate(win32_h.DWORD);
			MemorySegment lpName =
				arena.allocateFrom(pipeFile.getPath(), StandardCharsets.UTF_16LE);

			// Lock down the named pipe so that only the current user can use it:
			// SDDL string: "D:(A;;FRFWFXSD;;;OW)"
			// allow the "Owner Rights" (OW) identity to read, write, and execute, modify perms
			_SECURITY_ATTRIBUTES secAttrs =
				createSecurityAttributesFromSddl(arena, cs, "D:(A;;FRFWFXSD;;;OW)");

			try {
				//@formatter:off
				MemorySegment createPipeResult = win32_h.CreateNamedPipeW(cs,
					lpName,
					win32_h.PIPE_ACCESS_DUPLEX(),
					win32_h.PIPE_TYPE_MESSAGE() | win32_h.PIPE_READMODE_MESSAGE() | win32_h.PIPE_WAIT(),
					win32_h.PIPE_UNLIMITED_INSTANCES(),
					4096,
					4096,
					0,
					secAttrs.getMemorySegment() );
				//@formatter:on

				if (createPipeResult.address() == 0 ||
					createPipeResult.address() == win32_h.INVALID_HANDLE_VALUE_RAW) {
					int lastError = Win32Err.getLastError(cs);
					throw new IOException("Unable to create named pipe %s, error=%d (%s)"
							.formatted(pipeFile, lastError, Win32Err.formatMessage(lastError)));
				}
				handle = new Handle(createPipeResult);
			}
			finally {
				win32_h.LocalFree(secAttrs.getSecurityDescriptor());
			}

			listenThreadReadyLatch.countDown(); // signal start() we are ready to accept connections

			while (!thisThread.isInterrupted()) {
				int bConnected =
					win32_h.ConnectNamedPipe(cs, handle.asSegment(), MemorySegment.NULL);
				if (bConnected == 0) {
					int lastError = Win32Err.getLastError(cs);
					if (lastError != win32_h.ERROR_PIPE_CONNECTED()) {
						throw new IOException("Failed to connect named pipe %s, error=%d (%s)"
								.formatted(pipeFile, lastError, Win32Err.formatMessage(lastError)));
					}
				}

				int bReadSuccess = win32_h.ReadFile(cs, handle.asSegment(), winbuffer,
					javabuffer.length, dwBytesRead, MemorySegment.NULL);
				if (bReadSuccess == 0) {
					int lastError = Win32Err.getLastError(cs);
					if (lastError != win32_h.ERROR_BROKEN_PIPE() &&
						lastError != win32_h.ERROR_NO_DATA() &&
						lastError != win32_h.ERROR_INVALID_HANDLE()) {
						throw new IOException("Failed to read from named pipe %s, error=%d (%s)"
								.formatted(pipeFile, lastError, Win32Err.formatMessage(lastError)));
					}
					continue;
				}
				try {
					int bytesRead = dwBytesRead.get(win32_h.DWORD, 0);
					if (bytesRead > 0) {
						MemorySegment.copy(winbuffer, ValueLayout.JAVA_BYTE, 0, javabuffer, 0,
							bytesRead);
						String msg = new String(javabuffer, 0, bytesRead, StandardCharsets.UTF_8);
						processReceivedMessage(msg);
					}
				}
				finally {
					win32_h.DisconnectNamedPipe(cs, handle.asSegment());
				}
			}
		}
		finally {
			if (handle != null) {
				handle.close();
			}
		}
	}

	private static _SECURITY_ATTRIBUTES createSecurityAttributesFromSddl(Arena arena,
			MemorySegment cs, String sddl) throws IOException {

		MemorySegment sddlStringPtr = arena.allocateFrom(sddl, StandardCharsets.UTF_16LE);
		MemorySegment ppSecurityDescriptor = arena.allocate(ValueLayout.ADDRESS);

		//@formatter:off
		if (win32_sddl_h.ConvertStringSecurityDescriptorToSecurityDescriptorW(cs,
			sddlStringPtr,
			win32_sddl_h.SECURITY_DESCRIPTOR_REVISION(),
			ppSecurityDescriptor,
			MemorySegment.NULL) == 0) {
		//@formatter:on
			int lastError = Win32Err.getLastError(cs);
			throw new IOException("SDDL conversion failed: %d (%s)".formatted(lastError,
				Win32Err.formatMessage(lastError)));
		}
		MemorySegment pSecurityDescriptor = ppSecurityDescriptor.get(ValueLayout.ADDRESS, 0);
		_SECURITY_ATTRIBUTES result = _SECURITY_ATTRIBUTES.of(arena, pSecurityDescriptor);
		return result;
	}

}
