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
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import com.microsoft.win32.win32_h;

import ghidra.pty.windows.Handle;
import ghidra.pty.windows.Win32Err;

/**
 * Windows named pipe implementation.  Uses java native to call Windows named pipe Kernel methods.
 * <p>
 * Windows named pipes must be located under the special windows \\.\pipe\ path.
 */
public class WinNamedPipe extends NamedPipe {
	public static final int WIN_MAX_PIPE_MSG_LENGTH = 4096; // could be more

	public static File createPipeFilepath(String pipeName) {
		return new File("\\\\.\\pipe\\" + pipeName);
	}

	private static final int PIPEEXISTS_WAIT_MS = 50;

	public WinNamedPipe(File pipeFile, File lockFile) {
		super(pipeFile, lockFile);
	}

	@Override
	public boolean pipeObjectExists() {
		try (Arena arena = Arena.ofConfined()) {
			// don't care about lasterror because we are only testing presence of pipe object
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			return win32_h.WaitNamedPipeW(cs,
				arena.allocateFrom(pipeFile.getPath(), StandardCharsets.UTF_16LE),
				PIPEEXISTS_WAIT_MS) != 0;
		}
	}

	@Override
	public NamedPipeServer createServer(MessageConsumer msgConsumer) {
		return new WinNamedPipeServer(pipeFile, lockFile, msgConsumer);
	}

	@Override
	public void writeMessage(String message, Duration timeout) throws IOException {
		long startMS = System.currentTimeMillis();
		long endMS = timeout != null ? startMS + timeout.toMillis() : 0;
		int nTimeOut = timeout != null ? (int) timeout.toMillis() : PIPEEXISTS_WAIT_MS;
		byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
		if (messageBytes.length > WIN_MAX_PIPE_MSG_LENGTH) {
			throw new IOException(
				"Unable to write overly long message via pipe: " + message.length());
		}

		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			MemorySegment lpName =
				arena.allocateFrom(pipeFile.getPath(), StandardCharsets.UTF_16LE);
			MemorySegment dwMode = arena.allocate(win32_h.DWORD);
			MemorySegment dwBytesWritten = arena.allocate(win32_h.DWORD);
			MemorySegment buf = arena.allocate(messageBytes.length);
			MemorySegment.copy(messageBytes, 0, buf, ValueLayout.JAVA_BYTE, 0, messageBytes.length);

			int retryCount = 0;
			do {
				if (win32_h.WaitNamedPipeW(cs, lpName, nTimeOut) == 0) {
					int lastError = Win32Err.getLastError(cs);
					if (lastError != win32_h.ERROR_SEM_TIMEOUT()) {
						// if it wasn't a timeout error, perform our own delay to avoid retrying
						// too quickly
						try {
							Thread.sleep(PIPEEXISTS_WAIT_MS);
						}
						catch (InterruptedException e) {
							break;
						}
					}
					continue;
				}

				MemorySegment createFileResults = win32_h.CreateFileW(
					cs,                           // for lasterror 
					lpName,                       // lpFileName, must be UTF16LE
					win32_h.GENERIC_WRITE(),      // dwDesiredAccess
					0,                            // dwShareMode
					MemorySegment.NULL,           // lpSecurityAttributes - N/A
					win32_h.OPEN_EXISTING(),      // dwCreationDisposition
					0,                            // dwFlagsAndAttributes
					MemorySegment.NULL            // hTemplateFile - N/A
				);

				if (createFileResults.address() == MemorySegment.NULL.address() ||
					createFileResults.address() == win32_h.INVALID_HANDLE_VALUE().address()) {
					// don't care about lasterror, file didn't exist or other error, try again
					continue;
				}

				try (Handle handle = new Handle(createFileResults)) {
					dwMode.set(win32_h.DWORD, 0, win32_h.PIPE_READMODE_MESSAGE());
					if (win32_h.SetNamedPipeHandleState(
						cs,                    // for last error
						handle.asSegment(),    // hNamedPipe
						dwMode,                // lpMode
						MemorySegment.NULL,    // lpMaxCollectionCount - N/A
						MemorySegment.NULL     // lpCollectDataTimeout - N/A
					) == 0) {
						int lastError = Win32Err.getLastError(cs);
						throw new IOException("Unable to set named pipe mode, error=%d (%s)"
								.formatted(lastError, Win32Err.formatMessage(lastError)));
					}

					if (win32_h.WriteFile(
						cs,                        // for lasterror
						handle.asSegment(),        // hFile
						buf,                       // lpBuffer
						messageBytes.length,       // nNumberOfBytesToWrite
						dwBytesWritten,            // Out: ptr to lpNumberOfBytesWritten
						MemorySegment.NULL         // lpOverlapped - N/A
					) == 0) {
						int lastError = Win32Err.getLastError(cs);
						throw new IOException("Write failed, error=%d (%s)".formatted(lastError,
							Win32Err.formatMessage(lastError)));
					}
					int bytesWritten = dwBytesWritten.get(win32_h.DWORD, 0);
					if (bytesWritten != messageBytes.length) {
						throw new IOException("Failed to write complete message: %d of %d"
								.formatted(bytesWritten, messageBytes.length));
					}
					return; // success
				}
			}
			while (retryCount++ < MAX_SEND_RETRY_COUNT && System.currentTimeMillis() < endMS);

			long elapsed = System.currentTimeMillis() - startMS;
			throw new IOException(
				"Unable to write message, retried %d, elapsed %d".formatted(retryCount, elapsed));
		}
	}

}
