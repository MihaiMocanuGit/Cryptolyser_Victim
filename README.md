# The Cryptolyser project:

This project successfully exposed cache-timing vulnerabilities in the widely-used lightweight AES implementation known
as [tiny-AES-c](https://github.com/kokke/tiny-AES-c). The attack is orchestrated using two physical machines: a victim
and an attacker.

Following the principles laid out by Bernstein in his cache-timing attack, this attack collects encryption timing data
from a server running on the victim device, which is accessed remotely over the network.

The Cryptolyser project is a modern revisit of Bernstein's original cache-timing attack. It is designed as a
bundle consisting of four primary components:

* [Cryptolyser_Victim](https://github.com/MihaiMocanuGit/Cryptolyser_Victim): is a minimal UDP server that performs AES
  encryption on incoming data and returns the
  corresponding encryption timing information. It uses a secret key not shared with the attacker.

* [Cryptolyser_Doppelganger](https://github.com/MihaiMocanuGit/Cryptolyser_Doppelganger): is a near-exact replica of the victim's implementation. However, it differs in that
  it receives the encryption key along with the data, allowing the attacker to correlate observed timing behavior with
  known key combinations.

* [Cryptolyser_Attacker](https://github.com/MihaiMocanuGit/Cryptolyser_Attacker): coordinates the side-channel attack.
  It communicates with the victim, sends crafted data
  inputs, receives timing responses, and performs statistical correlation analysis to infer the secret key.

* [Cryptolyser_Common](https://github.com/MihaiMocanuGit/Cryptolyser_Common): contains shared utility code and header
  files used across the other three modules to
  facilitate interoperability and reduce redundancy.

## Running the apps
Note: This project has been developed as a Linux only bundle of applications.

### Cryptolyser_Victim:
**Command:** `./run.sh [debug | release] 'x0 x1 x2 x3 x4 ... xF'`

Note:
* 'x0 x1 x2 x3 x4 ... xF' represents the 16 byte long key, written in hex.
* SUDO access is needed to lock the process to a set core in performance mode. If this is not desired, remove the
  associated lines in run.sh. If this change results in noisy timing values, fallback to the UNIX timer in
  Cryptolyser_Common/cycle_timer.h
* default port: 8081

### Cryptolyser_Doppelganger:
**Command:**  `./run.sh [debug | release]`

Note:
* SUDO access is needed to lock the process to a set core in performance mode. If this is not desired, remove the
  associated lines in run.sh. If this change results in noisy timing values, fallback to the UNIX timer in
  Cryptolyser_Common/cycle_timer.h
* default port: 8082

### Cryptolyser_Attacker:
**Command**  `./run.sh [debug | release]`

### Cryptolyser_Common:
**It is a git submodule used by the other apps, it cannot be executed.**

## Changing AES mode

The following AES confidentiality modes are supported: ECB/CBC/CTR.

To change from one mode to the other, the git branch associated with that mode needs to be checkout for every used
program.
Thus, the following git branches exist: main (EBC), CBC and CTR. 

Cryptolyser_Common has common_main (EBC) and common_IV (CBC and CTR)

## Changing the encryption library

The encryption library used by Cryptolyser_Victim and Cryptolyser_Doppelganger can changed by writing a source file that
implements the encryption API defined in src/AES/aes_interface.h

The next step is to link against this new source file by modifying the src/AES/CMakeLists.txt file.

Besides the tiny-AES-c implementation, OpenSSL is already supported. Its version can be modified in:
third-party/OpenSSL/CMakeLists.txt 
