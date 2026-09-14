"""Run `openssl speed -evp <cipher>` pinned to logical CPU 0 at HIGH priority (psutil), for
chacha20-poly1305 and aes-256-gcm, and print the 16 KiB-block throughput in GB/s.
Run: python tools/bench_openssl_pinned.py [seconds=3]
"""
import os, re, shutil, subprocess, sys
import psutil
secs = sys.argv[1] if len(sys.argv) > 1 else '3'
exe = shutil.which('openssl') or r'D:\Git\mingw64\bin\openssl.exe'
print('openssl:', exe, subprocess.run([exe, 'version'], capture_output=True, text=True).stdout.strip())
for cipher in ('chacha20-poly1305', 'aes-256-gcm'):
    proc = psutil.Popen([exe, 'speed', '-evp', cipher, '-seconds', secs], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        proc.cpu_affinity([0])
        if os.name == 'nt':
            proc.nice(psutil.HIGH_PRIORITY_CLASS)
    except Exception as e:
        print('pin failed:', e)
    out = proc.communicate()[0]
    line = [l for l in out.splitlines() if l.strip().startswith(cipher) or cipher.replace('-', '') in l.replace('-', '').lower()]
    print(out.strip().splitlines()[-2] if len(out.strip().splitlines()) >= 2 else out)
    m = re.findall(r'([\d.]+)k', out.splitlines()[-2] if out.strip() else '')
    if m:
        kb = [float(x) for x in m]
        print('%-20s 16 KiB blocks: %.3f GB/s   (1 KiB: %.3f, 8 KiB: %.3f)' % (cipher, kb[-1] * 1000 / 1e9, kb[3] * 1000 / 1e9, kb[4] * 1000 / 1e9))
