The artifact consists of two scripts for identifying and analyzing divergences
in real-world projects containing known vulnerabilities. The first script
automates the execution of the selected vulnerability cases across different
compiler optimization levels and records the resulting runtime and sanitizer
behavior. The second script uses GDB to support a more detailed, manual
analysis of selected cases and their execution behavior.

Both scripts use the ARVO dataset as the source of the evaluated vulnerability
cases. The artifact is compatible with ARVO-Meta version 3.0.0, which contains
6,138 security issues. The required \texttt{arvo.db} database can be obtained
from the ARVO-Meta v3.0.0 release:
\url{https://github.com/n132/ARVO-Meta/releases/tag/v3.0.0}.

Docker must be installed on the machine.

