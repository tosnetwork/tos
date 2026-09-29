#!/usr/bin/env python3
"""Isolated M/Prometheus/Alertmanager/O kill-chain witness; never starts a node."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FLAGS = json.loads((ROOT/'deploy/prometheus/runtime-flags.json').read_text())
assert FLAGS['prometheus_required_argv'] == ['--rules.alert.resend-delay=15s']

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def put(path, value, private=False):
    path.write_text(value)
    if private:
        path.chmod(0o600)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def openssl(directory, *args):
    subprocess.run(['openssl', *args], cwd=directory, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)

def certificates(directory):
    openssl(directory, 'req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
            '-nodes','-keyout','ca.key','-out','ca.pem','-subj','/CN=c03-test-ca',
            '-days','1','-addext','basicConstraints=critical,CA:TRUE',
            '-addext','keyUsage=critical,keyCertSign,cRLSign')
    for name, extension in [('server','subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n'),
                            ('observer','extendedKeyUsage=clientAuth\n')]:
        openssl(directory, 'req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
                '-nodes','-keyout',f'{name}.key','-out',f'{name}.csr','-subj',f'/CN={name}')
        put(directory/f'{name}.ext', extension+'basicConstraints=CA:FALSE\n')
        openssl(directory, 'x509','-req','-in',f'{name}.csr','-CA','ca.pem','-CAkey','ca.key',
                '-set_serial', '1' if name=='server' else '2','-out',f'{name}.pem','-days','1',
                '-extfile',f'{name}.ext')
    put(directory/'observer-identity.pem',
        (directory/'observer.pem').read_text()+(directory/'observer.key').read_text(),True)

class Boundary(http.server.BaseHTTPRequestHandler):
    context = None
    def log_message(self, *_):
        pass
    def do_GET(self):
        if self.path != '/monitor':
            self.send_error(404); return
        request=urllib.request.Request(f'http://127.0.0.1:{self.context["manager_port"]}/v1/monitor/heartbeat',
                                       headers={'Authorization':'Bearer '+self.context['read_token']})
        try:
            with urllib.request.urlopen(request,timeout=2) as result:
                body=result.read(4096)
        except Exception:
            self.send_error(503); return
        self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_POST(self):
        if self.path != '/receiver':
            self.send_error(404); return
        length=int(self.headers.get('Content-Length','0'))
        if length>4096 or length<=0:
            self.send_error(413); return
        body=self.rfile.read(length)
        try:
            payload=json.loads(body)
            key=self.headers['Idempotency-Key']
            assert self.headers['Authorization']=='Bearer '+self.context['receiver_token']
            assert self.headers['Content-Type']=='application/json'
            assert self.headers['X-Content-SHA256']==hashlib.sha256(body).hexdigest()
            assert payload['idempotency_key']==key
            assert payload['observer_id']=='observer1'
            assert isinstance(payload['observed_at'],str)
        except Exception:
            self.send_error(400); return
        item={'received_monotonic':time.monotonic(),'received_utc':time.time(),'key':key,'payload':payload,
              'client_certificate':self.connection.getpeercert()['subject']}
        with self.context['lock']:
            self.context['notices'].append(item)
        reply=b'{"accepted":true}'
        self.send_response(202);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(reply)))
        self.end_headers();self.wfile.write(reply)

def fetch(url, token):
    req=urllib.request.Request(url,headers={'Authorization':'Bearer '+token})
    with urllib.request.urlopen(req,timeout=2) as response:
        return json.load(response)

def until(predicate, seconds, message):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            result=predicate()
            if result:return result
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(1)
    raise AssertionError(message)

def replay(port_number, token, epoch):
    body=json.dumps({'version':'4','alerts':[{'status':'firing',
        'labels':{'alertname':'Watchdog','monitor_id':'monitor1'},
        'annotations':{'monitor_epoch':epoch,'evaluation_sequence':'1'},
        'fingerprint':'old-fixture','startsAt':'2026-09-29T00:00:00Z'}]}).encode()
    req=urllib.request.Request(f'http://127.0.0.1:{port_number}/v1/watchdog/pipeline',data=body,
                               headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=2) as result:
        return json.load(result)['accepted_sequences']

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--prometheus',type=Path,required=True)
    parser.add_argument('--alertmanager',type=Path,required=True)
    parser.add_argument('--health-state',type=Path,required=True)
    parser.add_argument('--health-watchdog',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    processes={};logs={};events=[]
    def event(kind,**fields):
        row={'kind':kind,'monotonic':time.monotonic(),'utc':time.time(),**fields}
        events.append(row);print(json.dumps(row),flush=True)
    def start(name,command):
        log=open(args.output/f'{name}.log','ab',buffering=0);logs[name]=log
        process=subprocess.Popen([str(item) for item in command],stdin=subprocess.DEVNULL,
                                 stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        processes[name]=process;event('start',process=name,pid=process.pid,argv=[str(item) for item in command])
    def advances():
        path=args.output/'health-watchdog.log'
        if not path.exists():return []
        return [(int(sequence),int(received)/1000) for sequence,received in
                re.findall(r'watchdog pipeline advanced epoch=[^ ]+ sequence=(\d+) received_unix_ms=(\d+)',
                           path.read_text(errors='replace'))]
    def healthy_after(unix_seconds):
        path=args.output/'health-watchdog.log'
        if not path.exists():return False
        rows=re.findall(r'watchdog status process_unavailable=false pipeline_unavailable=false observed_unix_ms=(\d+)',
                        path.read_text(errors='replace'))
        return bool(rows and int(rows[-1])/1000>unix_seconds)
    def stop(name):
        process=processes.pop(name)
        process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill();process.wait(timeout=5)
        event('stop',process=name,returncode=process.returncode)
    try:
        with tempfile.TemporaryDirectory(prefix='nhm-c03-runtime-') as temp:
            t=Path(temp);certificates(t)
            manager_port,observer_port,proxy_port,prom_port,am_port=[port() for _ in range(5)]
            tokens={'ingest':'i'*32,'read':'r'*32,'pipeline':'p'*32,'receiver':'o'*32}
            for name,value in tokens.items():put(t/f'{name}.token',value,True)
            context={'manager_port':manager_port,'read_token':tokens['read'],
                     'receiver_token':tokens['receiver'],'notices':[],'lock':threading.Lock()}
            Boundary.context=context
            server=http.server.ThreadingHTTPServer(('127.0.0.1',proxy_port),Boundary)
            ssl_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(t/'server.pem',t/'server.key')
            ssl_context.load_verify_locations(t/'ca.pem')
            ssl_context.verify_mode=ssl.CERT_REQUIRED
            server.socket=ssl_context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            development=json.loads((ROOT/'config/health-state.development.json').read_text())
            development.update(control_db=str(t/'control.db'),evidence_db=str(t/'evidence.db'),
                listen=f'127.0.0.1:{manager_port}',ingest_token_file=str(t/'ingest.token'),
                read_token_file=str(t/'read.token'),receiver=None)
            put(t/'manager.json',json.dumps(development))
            observer={'monitor_url':f'https://localhost:{proxy_port}/monitor',
                'receiver_url':f'https://localhost:{proxy_port}/receiver',
                'ca_file':str(t/'ca.pem'),'identity_file':str(t/'observer-identity.pem'),
                'monitor_token_file':str(t/'read.token'),'receiver_token_file':str(t/'receiver.token'),
                'observer_id':'observer1','monitor_id':'monitor1',
                'pipeline_listen':f'127.0.0.1:{observer_port}',
                'pipeline_token_file':str(t/'pipeline.token')}
            put(t/'observer.json',json.dumps(observer))
            prom=f'''global:\n  scrape_interval: 5s\n  evaluation_interval: 5s\nalerting:\n  alertmanagers:\n  - static_configs:\n    - targets: ['127.0.0.1:{am_port}']\nrule_files:\n- '{ROOT/'deploy/prometheus/rules.yml'}'\nscrape_configs:\n- job_name: health-state\n  metrics_path: /metrics\n  authorization:\n    credentials_file: '{t/'read.token'}'\n  static_configs:\n  - targets: ['127.0.0.1:{manager_port}']\n'''
            put(t/'prometheus.yml',prom)
            wait=FLAGS['alertmanager_group_wait']
            interval=FLAGS['alertmanager_group_interval']
            repeat=FLAGS['alertmanager_repeat_interval']
            alertmanager=f'''route:\n  receiver: no-customer-destination\n  group_by: [alertname, node, scope, rule]\n  group_wait: {wait}\n  group_interval: {interval}\n  repeat_interval: {repeat}\n  routes:\n  - matchers: ['alertname="Watchdog"']\n    receiver: independent-watchdog\n    group_by: [alertname, monitor_id, monitor_epoch]\n    group_wait: {wait}\n    group_interval: {interval}\n    repeat_interval: {repeat}\nreceivers:\n- name: no-customer-destination\n- name: independent-watchdog\n  webhook_configs:\n  - url: http://127.0.0.1:{observer_port}/v1/watchdog/pipeline\n    send_resolved: false\n    http_config:\n      authorization:\n        credentials_file: {t/'pipeline.token'}\n'''
            put(t/'alertmanager.yml',alertmanager)
            frozen={}
            for name,path in [
                ('runtime_script',Path(__file__)),('health_state',args.health_state),
                ('health_watchdog',args.health_watchdog),('prometheus',args.prometheus),
                ('alertmanager',args.alertmanager),('rules',ROOT/'deploy/prometheus/rules.yml'),
                ('runtime_flags',ROOT/'deploy/prometheus/runtime-flags.json'),
                ('manager_config',t/'manager.json'),('observer_config',t/'observer.json'),
                ('prometheus_config',t/'prometheus.yml'),('alertmanager_config',t/'alertmanager.yml'),
            ]:
                frozen[name]={'path':str(path),'sha256':sha(path)}
                if name.endswith('_config'):
                    shutil.copyfile(path,args.output/f'frozen-{path.name}')
            receipt={'source_at_start':frozen,'prometheus_required_argv':FLAGS['prometheus_required_argv'],
                     'alertmanager_route':{'group_wait':FLAGS['alertmanager_group_wait'],
                         'group_interval':FLAGS['alertmanager_group_interval'],
                         'repeat_interval':FLAGS['alertmanager_repeat_interval']},
                     'observer_process_deadline_seconds':FLAGS['observer_process_deadline_seconds'],
                     'observer_pipeline_deadline_seconds':FLAGS['observer_pipeline_deadline_seconds']}
            (args.output/'start-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
            event('start_receipt',sha256=sha(args.output/'start-receipt.json'))
            start('health-state',[args.health_state,t/'manager.json'])
            until(lambda:fetch(f'http://127.0.0.1:{manager_port}/v1/monitor/heartbeat',tokens['read']),15,'M did not start')
            start('health-watchdog',[args.health_watchdog,t/'observer.json'])
            start('alertmanager',[args.alertmanager,'--config.file='+str(t/'alertmanager.yml'),
                                  '--storage.path='+str(t/'am-data'),'--web.listen-address=127.0.0.1:'+str(am_port),
                                  '--cluster.listen-address=127.0.0.1:0'])
            start('prometheus',[args.prometheus,'--config.file='+str(t/'prometheus.yml'),
                                '--storage.tsdb.path='+str(t/'prom-data'),'--web.listen-address=127.0.0.1:'+str(prom_port),
                                *FLAGS['prometheus_required_argv']])
            until(lambda:urllib.request.urlopen(f'http://127.0.0.1:{prom_port}/-/ready',timeout=2).status==200,20,'Prometheus not ready')
            event('baseline_wait',seconds=115)
            time.sleep(115)
            baseline=advances()
            assert len(baseline)>=2 and baseline[-1][0]>baseline[0][0],baseline
            with context['lock']:assert not context['notices'],context['notices']
            epoch=fetch(f'http://127.0.0.1:{manager_port}/v1/monitor/heartbeat',tokens['read'])['process_epoch']
            stop('prometheus')
            event('prometheus_down')
            last_replay=time.monotonic()
            def prom_notice():
                nonlocal last_replay
                if time.monotonic()-last_replay>=10:
                    accepted=replay(observer_port,tokens['pipeline'],epoch)
                    event('old_sequence_replay',accepted=accepted)
                    assert accepted=='0'
                    last_replay=time.monotonic()
                with context['lock']:
                    return next((item for item in context['notices'] if item['payload']['pipeline_unavailable'] and not item['payload']['process_unavailable']),None)
            # Alertmanager may still drain one advancing annotation after Prom
            # exits. The deadline is measured from the last genuine advancement,
            # never from the kill timestamp or a replayed old sequence.
            first=until(prom_notice,165,'Prometheus stop did not trip O pipeline')
            replays=[row for row in events if row['kind']=='old_sequence_replay']
            assert replays and all(row['accepted']=='0' for row in replays),replays
            last_advance=advances()[-1]
            assert first['received_utc']-last_advance[1]>=99.0,('pipeline deadline not reached',last_advance)
            assert first['received_utc']-last_advance[1]<=116.0,('observer evaluation late',last_advance)
            event('prometheus_unavailable_delivered',key=first['key'])
            start('prometheus',[args.prometheus,'--config.file='+str(t/'prometheus.yml'),
                                '--storage.tsdb.path='+str(t/'prom-data'),'--web.listen-address=127.0.0.1:'+str(prom_port),
                                *FLAGS['prometheus_required_argv']])
            until(lambda: advances()[-1] if advances() and advances()[-1][0]>last_advance[0] else None,
                  65,'pipeline did not advance after Prometheus restart')
            event('prometheus_pipeline_restored',sequence=advances()[-1][0])
            until(lambda:healthy_after(first['received_utc']),30,
                  'O did not consume a healthy tick after Prometheus restart')
            event('observer_healthy_tick_after_prometheus')
            stop('alertmanager');event('alertmanager_down')
            old_key=first['key']
            def am_notice():
                with context['lock']:
                    return next((item for item in context['notices'] if item['key']!=old_key and item['payload']['pipeline_unavailable'] and not item['payload']['process_unavailable']),None)
            second=until(am_notice,125,'Alertmanager stop did not trip O pipeline')
            assert second['received_monotonic']>first['received_monotonic']
            event('alertmanager_unavailable_delivered',key=second['key'])
            before_am_restart=advances()[-1][0]
            start('alertmanager',[args.alertmanager,'--config.file='+str(t/'alertmanager.yml'),
                                  '--storage.path='+str(t/'am-data'),'--web.listen-address=127.0.0.1:'+str(am_port),
                                  '--cluster.listen-address=127.0.0.1:0'])
            until(lambda: advances()[-1] if advances() and advances()[-1][0]>before_am_restart else None,
                  65,'pipeline did not advance after Alertmanager restart')
            event('alertmanager_pipeline_restored',sequence=advances()[-1][0])
            until(lambda:healthy_after(second['received_utc']),30,
                  'O did not consume a healthy tick after Alertmanager restart')
            event('observer_healthy_tick_after_alertmanager')
            stop('health-state');event('health_state_down')
            def manager_notice():
                with context['lock']:
                    return next((item for item in context['notices'] if item['payload']['process_unavailable']),None)
            third=until(manager_notice,65,'health-state stop did not trip O process deadman')
            event('health_state_unavailable_delivered',key=third['key'])
            with context['lock']:
                notices=list(context['notices'])
            assert len({item['key'] for item in (first,second,third)})==3
            assert all(item['client_certificate'] for item in notices)
            assert all(sha(Path(item['path']))==item['sha256'] for item in frozen.values()), \
                'runtime source or config changed during run'
            (args.output/'timeline.json').write_text(json.dumps({'events':events,'notices':notices},indent=2)+'\n')
            server.shutdown();server.server_close()
    finally:
        for name in list(processes):stop(name)
        for log in logs.values():log.close()
        (args.output/'timeline-partial.json').write_text(json.dumps({'events':events},indent=2)+'\n')

if __name__=='__main__':main()
