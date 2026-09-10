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
import java.time.Duration;

import com.sun.jna.platform.win32.*;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;

/**
 * Windows named pipe implementation.  Uses JNA to call Windows named pipe Kernel methods.
 * <p>
 * Windows named pipes must be located under the special windows \\.\pipe\ path.
 */
public class WinNamedPipe extends NamedPipe {
	public static final int WIN_MAX_PIPE_MSG_LENGTH = 4096; // could be more

	private static final int PIPEEXISTS_WAIT_MS = 50;

	public WinNamedPipe(File pipeFile, File lockFile) {
		super(pipeFile, lockFile);
	}

	@Override
	public boolean pipeObjectExists() {
		return Kernel32.INSTANCE.WaitNamedPipe(pipeFile.getPath(), PIPEEXISTS_WAIT_MS);
	}

	@Override
	public NamedPipeServer createServer(MessageConsumer msgConsumer) {
		return new WinNamedPipeServer(pipeFile, lockFile, msgConsumer);
	}

	@Override
	public void writeMessage(String message, Duration timeout) throws IOException {
		long endMS = timeout != null ? System.currentTimeMillis() + timeout.toMillis() : 0;
		int nTimeOut = timeout != null ? (int) timeout.toMillis() : PIPEEXISTS_WAIT_MS;
		byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
		if (messageBytes.length > WIN_MAX_PIPE_MSG_LENGTH) {
			throw new IOException(
				"Unable to write overly long message via pipe: " + message.length());
		}

		int retryCount = 0;
		do {
			if (!Kernel32.INSTANCE.WaitNamedPipe(pipeFile.getPath(), nTimeOut)) {
				continue;
			}

			//@formatter:off
			HANDLE handle = Kernel32.INSTANCE.CreateFile(
				pipeFile.getPath(),
				WinNT.GENERIC_WRITE,
				0,
				null,
				WinNT.OPEN_EXISTING,
				0,
				null);
			//@formatter:on

			if (handle == null || WinBase.INVALID_HANDLE_VALUE.equals(handle)) {
				continue;
			}

			try {
				IntByReference mode = new IntByReference(WinBase.PIPE_READMODE_MESSAGE);
				if (!Kernel32.INSTANCE.SetNamedPipeHandleState(handle, mode, null, null)) {
					throw new IOException("Unable to set named pipe mode, lastError=" +
						Kernel32.INSTANCE.GetLastError());
				}

				IntByReference bytesWritten = new IntByReference();
				if (!Kernel32.INSTANCE.WriteFile(handle, messageBytes, messageBytes.length,
					bytesWritten, null)) {
					throw new IOException(
						"Write failed, lastError=" + Kernel32.INSTANCE.GetLastError());
				}
				if (bytesWritten.getValue() != messageBytes.length) {
					throw new IOException("Failed to write complete message: %d of %d"
							.formatted(bytesWritten.getValue(), messageBytes.length));
				}
				return; // success
			}
			finally {
				Kernel32.INSTANCE.CloseHandle(handle);
			}
		}
		while (retryCount++ < MAX_SEND_RETRY_COUNT && System.currentTimeMillis() < endMS);

		throw new IOException("Unable to write message");
	}

}
