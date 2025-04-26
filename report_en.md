# DCCNET Emulator Report

## 1. Introduction

This document discusses the implementation of the DCCNET emulator for two modes: `md5` mode and `xfer` (file transfer) mode. The emulator was fully implemented in Python using the `asyncio` library, aiming for high interoperability with other language implementations as required. The final solution prioritizes robustness in framing, concurrent data transmission and reception, and adherence to the DCCNET protocol specifications.

## 2. Challenges and Difficulties

The main challenges faced during the development were:

- **Framing Recovery**: Correctly detecting the beginning and end of frames based only on a SYNC pattern.
- **Concurrent Send and Receive**: Allowing data to flow simultaneously in both directions without blocking the event loop.
- **Timeout Handling**: Ensuring the transmitter resends frames if ACKs are not received within a reasonable window.
- **Cooperativity with Asyncio**: Preventing starvation by frequently yielding control to the event loop (`await asyncio.sleep(0)`).
- **Interoperability**: Guaranteeing compatibility with external DCCNET implementations, especially in strict adherence to checksum validation and frame formats.

Unexpectedly, managing the end-of-transmission (EOF) without prematurely closing connections required careful handling of `END` flags and ACK synchronization.

## 3. Mechanisms for Framing Recovery After Errors

The system implements framing recovery through a robust re-synchronization mechanism based on the DCCNET `SYNC` constant:

1. **SYNC Search**: During reception, the reader continuously searches the buffer for the double SYNC pattern.
2. **Partial Frame Handling**: If a SYNC is found but the rest of the header or payload is missing, the system waits for additional data.
3. **Checksum Verification**: After identifying a frame, the checksum is recalculated ignoring the received checksum field to validate frame integrity.
4. **Error Recovery**: If any step fails (SYNC mismatch, checksum error, incomplete frame), the buffer slides one byte forward and continues searching for a valid SYNC.

This approach minimizes data loss in cases of network errors or corruptions.

## 4. Parallel Transmission and Reception

Transmission and reception occur concurrently using separate `asyncio` tasks:

- **Sending Task**: Reads chunks from the input file, frames them into DCCNET frames, and sends them. Each data frame requires an ACK before proceeding.
- **Receiving Task**: Continuously listens for incoming frames, verifies their integrity, acknowledges them, and writes valid data into the output file.
- **Reader Loop and Demuxer**: A reader task reads raw bytes from the socket, reconstructs frames, and dispatches them into appropriate queues (ACKs or Data).

The use of `await asyncio.sleep(0)` between transmissions ensures that both sending and receiving tasks have equal opportunities to progress, avoiding monopolization of the event loop.

The sending flow uses a retry mechanism (up to 16 times) if ACKs are not received, ensuring reliable data delivery. If a frame is duplicated, it is detected by comparing the last received frame's ID and checksum, and ACKs are resent without reprocessing the data.

## 5. Application Interface with DCCNET Implementation

The emulator provides a Command-Line Interface (CLI) with two primary modes:

- **Server Mode (`-s`)**:

  - Listens on all available interfaces (supporting IPv6).
  - Waits for incoming connections.
  - Sends the content of an input file while simultaneously receiving and saving the remote file.

- **Client Mode (`-c`)**:
  - Actively connects to a remote server.
  - Sends the content of an input file.
  - Simultaneously receives and saves the content sent by the server.

Example usage:

```bash
# Start server
python dccnet_emulator.py -s 7777 server_input.txt server_output.txt

# Start client
python dccnet_emulator.py -c 127.0.0.1:7777 client_input.txt client_output.txt
```

The application internally manages framing, retries, ACKs, END flags, and re-synchronization, abstracting all DCCNET protocol complexity from the user.

## 6. AI Tool Contributions

AI tools, such as ChatGPT and GitHub Copilot, were significantly helpful in:

- Designing a clean concurrency model using `asyncio` for bidirectional file transfer.
- Writing repetitive boilerplate code such as frame serialization (`pack`) and deserialization (`unpack`).
- Debugging and suggesting improvements in timeout and retransmission mechanisms.
- Explaining subtle networking problems like "connection reset by peer" or starvation of asyncio tasks.

The tools were not directly used to generate final solutions but played a critical role in brainstorming ideas, explaining tricky parts, and suggesting best practices, especially in concurrent network programming.

## 7. Conclusion

The DCCNET emulator fulfills the requirements of the assignment:

- It interoperates with external servers and clients.
- It supports robust error handling and framing recovery.
- It handles bidirectional, concurrent transmission and reception.
- It provides a clean, user-friendly command-line interface.

Although the project involved complex aspects of network protocol implementation, proper use of asyncio primitives, careful error management, and modular code structure led to a reliable final solution.
