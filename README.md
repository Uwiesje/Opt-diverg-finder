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


Note:
However disk-space could be filled when running the experiments extensively. In my experience cleaning the space using
\texttt{docker system prune -a} will clean and empty the space, however it will not compact it. This causes windows to still assume the space used by wsl2 is full, meaning the memory is not usable for the host.-For linux users however the command should be enough, since it is assumed that the OS can access that memory directly.

Here is a step by step on how to clean the disk for windows wsl2 users:
\begin{enumerate}
\item Open the WSL2 terminal and remove unused Docker data using:
\begin{lstlisting}
docker system prune -a
\end{lstlisting}
if this doesnt work because the wsl doesnt react. Open powershell with admin rights and run the same command.

\item Shut down WSL2 from Windows PowerShell:
\begin{verbatim}
wsl --shutdown
\end{verbatim}

\item Locate the VHDX file belonging to the WSL2 Linux distribution. This file is typically named \texttt{ext4.vhdx} and is stored within the distribution's Windows application data directory.

\item close docker via task-manager
\item Open Windows PowerShell with administrator privileges and use DiskPart to compact the VHDX:
\begin{verbatim}
diskpart
select vdisk file="C:\path\to\ext4.vhdx"
attach vdisk
compact vdisk
detach vdisk
exit
\end{verbatim}
\item WSL2 can then be started again normally.
