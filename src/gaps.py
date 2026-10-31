import csv,sys,glob
dirs=sys.argv[1:] or sorted(glob.glob("results/timed-v3/run*"))
for d in dirs:
    try:
        rows=list(csv.DictReader(open(d+"/send_packets.csv")))
    except OSError:
        continue
    a=[int(r["actual_ns"]) for r in rows]
    hits=[]
    for i in range(1,len(rows)):
        gap=(a[i]-a[i-1])/1e6
        if gap>2:
            r=rows[i]; p=rows[i-1]
            hits.append(f"  seq {r['seq']}: gap {gap:.2f} ms | late vs schedule {(int(r['actual_ns'])-int(r['scheduled_ns']))/1e6:.2f} ms | previous call took {(int(p['submit_done_ns'])-int(p['actual_ns']))/1e6:.2f} ms")
    print(d.split('/')[-1], "-", len(hits), "gaps over 2 ms")
    print("\n".join(hits))
