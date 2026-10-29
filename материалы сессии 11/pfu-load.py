import concurrent.futures, ssl, sys, time, urllib.request

URL = "https://example.com/"
N = 250

def one(_):
    t = time.time()
    try:
        with urllib.request.urlopen(URL, timeout=20) as r:
            r.read(1024)
        return 1, time.time() - t
    except Exception as e:
        return 0, str(e)[:60]

t0 = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=N) as ex:
    res = list(ex.map(one, range(N)))
ok = sum(1 for r in res if r[0] == 1)
errs = {}
for r in res:
    if r[0] == 0:
        errs[r[1]] = errs.get(r[1], 0) + 1
print(f"ok={ok}/{N} elapsed={time.time()-t0:.2f}s")
for e, c in list(errs.items())[:5]:
    print(f"  {c}x {e}")
