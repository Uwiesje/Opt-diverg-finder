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
    WHERE localId="42483745"  
""")

# possible by crashtype or localId any table from the arvo database.
# project="harfbuzz" AND
data = c.fetchall()

FLAGS = ["-O0", "-O1", "-O2", "-O3"]


def run_cmd(cmd, binary=False):
    result = subprocess.run(cmd, capture_output=True)
    if binary:
        return result.stdout, result.returncode
    return result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"), result.returncode


def build_and_run(localId, flag, fuzz_target):
    
    os.makedirs("binaries", exist_ok=True)
    
    script = f"""
set +e

echo '=== BUILDING {flag} ==='

export SANITIZER=address
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:color=always:halt_on_error=0
export FUZZING_LANGUAGE="${{FUZZING_LANGUAGE:-c++}}"


cat > /usr/local/bin/cc_wrapper.sh << 'EOF'
#!/bin/bash
exec "${{REAL_CC}}" "$@" "{flag}"
EOF
cat > /usr/local/bin/cxx_wrapper.sh << 'EOF'
#!/bin/bash
exec "${{REAL_CXX}}" "$@" "{flag}"
EOF


chmod +x /usr/local/bin/cc_wrapper.sh /usr/local/bin/cxx_wrapper.sh

export REAL_CC="${{CC:-clang}}"
export REAL_CXX="${{CXX:-clang++}}"
export CC=/usr/local/bin/cc_wrapper.sh
export CXX=/usr/local/bin/cxx_wrapper.sh

compile 

BUILD_EXIT=$? 
echo "build_exit=$BUILD_EXIT"

if [ $BUILD_EXIT -ne 0 ]; then
    echo "=== RUNTIME START ==="
    echo "BUILD FAILED"
    grep -E "error:|undefined|cannot|failed" /tmp/build.log | tail -20
    echo "--- LAST 20 LINES ---"
    tail -20 /tmp/build.log
    echo "=== RUNTIME END ==="
    exit 1
fi

echo "=== RUNTIME START ==="
echo "RUNNING: /out/{fuzz_target} /tmp/poc"
/out/{fuzz_target} /tmp/poc 2>&1
EXIT_CODE=$?
echo "EXIT:$EXIT_CODE"
echo "=== RUNTIME END ==="
"""
    cmd = [
        "docker", "run", "--rm",
        f"n132/arvo:{localId}-vul",
        "/bin/bash", "-c", script
    ]

    return run_cmd(cmd)
def extract_crash_signature(runtime_raw):
    """Pull out the semantically meaningful parts of an ASAN report."""
    sig = {}

    m = re.findall(r"(READ|WRITE) of size (\d+|\*)", runtime_raw, re.IGNORECASE)
    if m:
        sig["access"] = m[-1][0].upper()
        raw_size = m[-1][1]
        print("\n")
        print(raw_size)
        print("\n")
        sig["size"] = None if raw_size == "*" else int(raw_size)

    m = re.findall(r"ERROR: AddressSanitizer: ([\w\-]+)", runtime_raw, re.IGNORECASE)
    if m:
        sig["crash_type"] = m[-1]

    m = re.findall(r"#0 \S+ in (\S+)", runtime_raw)
    if m:
        sig["top_frame"] = m[-1]

    return sig

def extract_runtime(output):
    try:
        return output.split("=== RUNTIME START ===")[-1].split("=== RUNTIME END ===")[0]
    except Exception:
        return ""


def classify(runtime_raw, exit_code):
    r = runtime_raw.lower()

    if "addresssanitizer" in r or "asan:" in r:
        return "asan"

    if "segmentation fault" in r or "sigsegv" in r:
        return "segfault"

    if exit_code == 6 or ("abort" in r and "aborting" in r):
        return "abort"

    if "build failed" in r:
        print("BUILD LOG:")
        print(output[:3000])
        return "build_fail"

    if exit_code != 0:
        return "exit_nonzero"

    return "ok"



results = {}

i = 1
#[10:80] now it runs untill the data base is finished. add [:x] or [Y:X] to control the amount of cases tested. 
for localId, fuzz_target, crash_type, project in data:
    print(f"\n===== BUG {localId} ({crash_type}) =====")
    print(f"  fuzz_target: {fuzz_target}")
    print(f"project:: {project}")
    results[localId] = {}
    
    for flag in FLAGS:
        print(f"\n--- {flag} ---")

        output, code = build_and_run(localId, flag, fuzz_target)

        runtime_raw = extract_runtime(output)
        
        if "build failed" in runtime_raw.lower():
            with open("test.txt", "a", encoding="utf-8") as f:
                f.write(f"\n{localId}:{flag} build failed\n")
                #f.write(f"{output[:3000]}\n")
            continue
        
        """
        with open(f"{localId}_{flag}_asan.txt", "w") as f:
            f.write(runtime_raw)
        """
        
        behavior = classify(runtime_raw, code)
        
        results[localId][flag] = {
            "project": project,
            "behavior": behavior,
            "exit": code,
            "sig": extract_crash_signature(runtime_raw)
            #read or write
        }
        
        print("class =", behavior)
        print("preview =", runtime_raw[:2000])
    
    
    flag_results = results[localId]
    if not flag_results:
        i += 1
        continue
    

    with open("test.txt", "a", encoding="utf-8") as f:
        f.write(f"\nnum: {i}")
        i+=1
        behaviors = set(v["behavior"] for v in flag_results.values())
        run = ""
        project_name = next(iter(flag_results.values())).get("project", "unknown")
        f.write(f"\n{localId}: {project_name}\n")
        sizes = {
            flag: v["sig"].get("size")
            for flag, v in flag_results.items()
            if v.get("sig", {}).get("size") is not None
        }
        ptr_reads = {
            flag for flag, v in flag_results.items()
            if v.get("sig", {}).get("size") is None and v.get("sig", {}).get("access")
        }
        unique_sizes = set(sizes.values()) - {None}
        sigs = set(
            (v["sig"].get("crash_type"), v["sig"].get("size"), v["sig"].get("top_frame"))
            for v in flag_results.values()
        )
        
        #add write vs reads checks.
        
        if len(unique_sizes) > 1:
            f.write(f"  -> READ SIZE DIVERGENCE: {sizes}\n")
        if len(behaviors) > 1 or len(sigs) > 1:
            print(f"[!] {localId} DIVERGENCE DETECTED")
            
            if "asan" in behaviors or "segfault" in behaviors:
                run = "  -> STRONG UB SIGNAL (crash at some optimization levels)"
                f.write(run)
            elif "exit_nonzero" in behaviors:
                run = ("  -> WEAK UB SIGNAL (different failure paths)")
                f.write(run)
            else:
                run = ("  -> PURE EXECUTION DIVERGENCE (same class, different output)")
                f.write(run)
            
            for flag in FLAGS:
                if flag not in flag_results:
                    f.write(f"{flag} build failed: skip\n")
                    continue
                r = flag_results[flag]
                f.write(f"    {flag}: class={r['behavior']} exit={r['exit']} sig={r['sig']}\n")
        else:
            run = (f"[ ] {localId} stable across optimizations")
            f.write(f"{run}\n")
            
            
            
            
            
"""

line 7 give the correct path of the database. different on each pc.
line 147 to control how much data is being tested.

line 189 AND 160 specify the text.txt file where results will be written to.

remove comments from line 166 to enable the program to write an asan report in your repository.

"""
