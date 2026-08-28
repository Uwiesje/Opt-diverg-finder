import sqlite3
import subprocess
import os
import hashlib
import re

conn = sqlite3.connect("./avro/arvo.db")
c = conn.cursor()
c.execute("""
    SELECT localId, fuzz_target, crash_type, project
    FROM arvo
    WHERE localId="42475836"
""")
#openthread 37
# project="harfbuzz" AND
data = c.fetchall()


def run_cmd(cmd, binary=False):
    result = subprocess.run(cmd, capture_output=True)
    if binary:
        return result.stdout, result.returncode
    return (
        result.stdout.decode(errors="replace"),
        result.returncode
    )


def build_and_run(localId, flag, fuzz_target):
    os.makedirs("asan_reports", exist_ok=True)
    
    script = f"""
set +e

echo "stack limit:"
ulimit -s 65536

echo '=== BUILDING {flag} ==='

export SANITIZER=address
export FUZZING_LANGUAGE="${{FUZZING_LANGUAGE:-c++}}"

cat > /usr/local/bin/cc_wrapper.sh << 'EOF'
#!/bin/bash
exec "${{REAL_CC}}" "$@" "{flag}" "-g"
EOF
cat > /usr/local/bin/cxx_wrapper.sh << 'EOF'
#!/bin/bash
exec "${{REAL_CXX}}" "$@" "{flag}" "-g"
EOF
chmod +x /usr/local/bin/cc_wrapper.sh /usr/local/bin/cxx_wrapper.sh

export REAL_CC="${{CC:-clang}}"
export REAL_CXX="${{CXX:-clang++}}"
export CC=/usr/local/bin/cc_wrapper.sh
export CXX=/usr/local/bin/cxx_wrapper.sh

compile >/tmp/build.log 2>&1
BUILD_EXIT=$?
echo "build_exit=$BUILD_EXIT"

if [ $BUILD_EXIT -ne 0 ]; then
    echo "BUILD FAILED"
    tail -20 /tmp/build.log
    exit 1
fi


ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:color=always:halt_on_error=0 \
    /out/{fuzz_target} /tmp/poc > /reports/{localId}_{flag}_asan_NOLSAN_3.txt 2>&1

apt-get install -y gdb -qq 2>/dev/null

echo "set auto-load safe-path /" >> /root/.gdbinit
echo "set pagination off" >> /root/.gdbinit
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:halt_on_error=0 gdb -q \\
  -ex "handle SIGABRT stop nopass" \\
  -ex "handle SIGSEGV stop nopass" \\
  -ex "run /tmp/poc" \\
  /out/{fuzz_target}
"""
    cmd = [
        "docker", "run", "--rm", "-it",
        "-v", f"{os.path.abspath('asan_reports')}:/reports",
        f"n132/arvo:{localId}-vul",
        "/bin/bash", "-c", script
    ]

    subprocess.run(cmd)  


for localId, fuzz_target, crash_type, project in data[:1]:
    build_and_run(localId, "-O1", fuzz_target)


""" 
line 94 second parameter, change the optimization flags to the one needed analyzing. 
line 12 change the localId to the case needing analyzing.
line 7 change the path to the arvo database. 
line 68 to 71 write a report in you repository. remove if not necessary. 
line 36 sets limit of memory for the docker container. the Default is 8196 if the line is removed. 

""" 
