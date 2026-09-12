#!/usr/bin/env python3
"""Bounded, reproducible native-VM load measurements on the machine running it.

This measures actual verification/execution, not consensus or network throughput.
The output deliberately cannot satisfy the production-validator activation gate.
Run the same binary on proposed hardware, then attach block-level/operator
qualification separately. No tariff is automatically changed by a measurement.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import tempfile
import time


def percentile(values, q):
    s=sorted(values)
    return s[min(len(s)-1,max(0,int((len(s)-1)*q+0.5)))]


def measure(executable: Path, scenarios: Path, batch_size: int, batches: int, workers: int, max_batch_ms: float):
    if not 20<=batch_size<=10000 or not 5<=batches<=1000 or not 1<=workers<=min(32,os.cpu_count() or 1):
        raise ValueError('invalid bounded workload size')
    if max_batch_ms<=0:raise ValueError('an explicit positive workload latency budget is required')
    cases={row.split('\t')[0]:row for row in scenarios.read_text().splitlines()}
    selected=[cases[n] for n in ('openssl-auth-commitment','openssl-maxima','bad-signature-ignore-classic','canonical-partition')]
    cpu_before=resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory() as d:
        work=Path(d)/'load.tsv'
        work.write_text('\n'.join(selected[i%len(selected)] for i in range(batch_size))+'\n')
        def run(_):
            start=time.perf_counter_ns()
            result=subprocess.run([str(executable.resolve()),str(work)],capture_output=True,text=True,timeout=max(60,max_batch_ms/1000*10),check=True)
            elapsed=(time.perf_counter_ns()-start)/1e6
            rows=[line.split('\t') for line in result.stdout.splitlines()]
            if len(rows)!=batch_size:raise ValueError('workload did not execute every transaction')
            total_gas=0
            for row in rows:
                if len(row)!=7:raise ValueError('malformed execution result')
                expected=9 if row[0]=='canonical-partition' else 0
                verdict=0 if row[0]=='bad-signature-ignore-classic' else -1
                if int(row[1])!=expected or (expected==0 and int(row[3])!=verdict):raise ValueError('workload verification mismatch')
                total_gas+=int(row[2])
            return elapsed,total_gas
        start=time.perf_counter_ns()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results=list(pool.map(run,range(batches)))
        wall=(time.perf_counter_ns()-start)/1e9
        workload_hash=hashlib.sha256(work.read_bytes()).hexdigest()
    cpu_after=resource.getrusage(resource.RUSAGE_CHILDREN)
    times=[r[0] for r in results]
    return {'success':percentile(times,0.99)<=max_batch_ms, 'qualification':'native-emulator-load',
        'network_activation':False,'production_validator_qualified':False,
        'machine':{'system':platform.system(),'release':platform.release(),'machine':platform.machine(),
                   'processor':platform.processor(),'logical_cpus':os.cpu_count()},
        'binary_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),'workload_sha256':workload_hash,
        'batch_size':batch_size,'batches':batches,'workers':workers,'executions':batch_size*batches,
        'batch_ms':{'p50':percentile(times,0.5),'p95':percentile(times,0.95),'p99':percentile(times,0.99),'max':max(times)},
        'max_batch_ms_budget':max_batch_ms,'wall_seconds':wall,'executions_per_second':batch_size*batches/wall,
        'child_cpu_seconds':(cpu_after.ru_utime+cpu_after.ru_stime)-(cpu_before.ru_utime+cpu_before.ru_stime),
        'child_maxrss_platform_units':cpu_after.ru_maxrss,'total_gas':sum(r[1] for r in results),
        'scope':'isolated native VM executions including process startup; not block production, finality or networking'}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--executable',type=Path,required=True)
    p.add_argument('--scenarios',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--batch-size',type=int,default=100);p.add_argument('--batches',type=int,default=20)
    p.add_argument('--workers',type=int,default=1);p.add_argument('--max-batch-ms',type=float,required=True)
    a=p.parse_args();report=measure(a.executable,a.scenarios,a.batch_size,a.batches,a.workers,a.max_batch_ms)
    a.out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    if not report['success']:raise SystemExit('native workload exceeds the explicit latency budget')


if __name__=='__main__':main()
