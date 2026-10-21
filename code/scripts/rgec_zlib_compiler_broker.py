"""Root-supervised fixed real make commands. Experimental, no agent lease claim."""
import json
import os
import resource
import socket
import struct
import subprocess
import sys
import threading
import time

from modal_recipient_entry import ENV, drop
from rgec_backend_probe import ROOT, driver, key, watch
from rgec_native_effect_probe import observe, sha
from rgec_native_event_probe import events


class CompilerBroker:
    def __init__(self, project, mode, result):
        assert mode in ('native', 'wrapped-cold', 'replay', 'local-warm')
        self.project, self.mode, self.result = project, mode, result
        self.artifact = result['artifact_directory']
        self.allowed = json.load(open('/zlib-native-commands.json'))
        self.result.update(compiler_actions=[], compiler_mode=mode,
            admission_scope='Exact recorded complete zlib commands; no concurrent agents or general lease certificate')
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind('/rgec-zlib-compiler.sock')
        os.chmod('/rgec-zlib-compiler.sock', 0o666)
        self.socket.listen(1)
        self.thread = threading.Thread(target=self.serve)
        self.failure = None
        self.store = None
        if mode == 'local-warm':
            sys.path.insert(0,'/rgec-private/cache')
            from backend_recipe_store import BackendRecipeStore
            preload = json.load(open('/rgec-private/cache/preload.json'))
            def missing(profile, bound):
                raise RuntimeError('Preloaded real-workflow request did not authenticate: '+profile)
            self.store = BackendRecipeStore(preload['context'], missing)
            self.plans = preload['driver_plans']
            for receipt in preload['receipts']:
                packet = open('/rgec-private/cache/'+receipt['profile']+'.packet','rb').read()
                assert sha(packet) == receipt['packet_sha256']
                self.store.entries[(receipt['profile'],receipt['key_sha256'])] = (receipt,packet,self.store._tag(receipt))
            self.result['trusted_local_store_audit'] = self.store.audit

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        wake = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        wake.connect('/rgec-zlib-compiler.sock'); wake.shutdown(socket.SHUT_WR)
        wake.close(); self.thread.join(10); self.socket.close()
        assert not self.thread.is_alive()
        if self.failure: raise self.failure

    def save(self, filename, data):
        with open(self.artifact+'/'+filename, 'wb') as stream: stream.write(data)
        return sha(data)

    def serve(self):
        while True:
            connection, _ = self.socket.accept()
            try:
                parts = []
                while True:
                    part = connection.recv(65536)
                    if not part: break
                    parts.append(part)
                    assert sum(map(len, parts)) <= 65536
                if not parts: return
                pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                assert uid == gid == 65534 and os.readlink('/proc/'+str(pid)+'/cwd') == self.project
                args = json.loads(b''.join(parts).decode())
                assert args in self.allowed, args
                reply = self.compile(args, pid)
                connection.sendall(json.dumps(reply).encode())
            except Exception as error:
                self.failure = error
                connection.sendall(json.dumps({'returncode':125, 'stdout':'',
                    'stderr':('Broker error: '+repr(error)+'\n').encode().hex()}).encode())
            finally: connection.close()

    def compile(self, args, pid):
        label = 'compile-'+str(len(self.result['compiler_actions'])).zfill(2)
        argv = ['/usr/local/bin/clang'] + args
        is_compile = '-c' in args
        output = os.path.join(self.project, args[args.index('-o')+1])
        row = {'label':label, 'arguments':args, 'caller_pid':pid,
            'is_compile':is_compile, 'mode':self.mode, 'query_emitted':False,
            'output_path':output, 'before':observe(output)}
        self.result['compiler_actions'].append(row)
        compiler_env = dict(ENV)
        if is_compile and self.mode == 'local-warm':
            plan = next(plan for plan in self.plans if plan['arguments'] == args)
            argv = plan['wrapped_argv']; row['validated_driver_plan'] = True
        elif is_compile and self.mode != 'native': argv = driver(argv, self.project)
        if is_compile and self.mode in ('replay','local-warm'): compiler_env['RGEC_BACKEND_MODE'] = 'replay'
        fd = watch(self.project)
        before = resource.getrusage(resource.RUSAGE_CHILDREN); start = time.monotonic()
        process = subprocess.Popen(argv, executable='/usr/local/bin/clang', cwd=self.project,
            env=compiler_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, preexec_fn=drop)
        diagnostic = []
        reader = threading.Thread(target=lambda: diagnostic.append(process.stderr.read()))
        reader.start()
        prefix = b''
        if is_compile and self.mode in ('replay','local-warm'):
            prefix = process.stdout.read(6)
            if prefix == b'RGECQ1':
                length_bytes = process.stdout.read(8); assert len(length_bytes) == 8
                length = struct.unpack('<Q', length_bytes)[0]; assert length <= 128*1024*1024
                bound = process.stdout.read(length); assert len(bound) == length
                prefix += length_bytes + bound
                row['query_emitted'] = True
                row['query_sha256'] = self.save(label+'.query', bound)
                profile = args[args.index('-o')+1]
                if self.store:
                    packet = self.store.resolve(profile,bound)
                    row['store_route'] = self.store.audit[-1]['route']
                    self.save(label+'.reply',packet)
                else:
                    print(json.dumps({'phase':'query','label':label,'profile':profile,
                        'query_sha256':row['query_sha256']}),flush=True)
                    assert json.loads(sys.stdin.readline()) == {'op':'continue'}
                    packet = open(self.artifact+'/'+label+'.reply','rb').read()
                row['reply_sha256'] = sha(packet)
                process.stdin.write(packet); process.stdin.flush()
        process.stdin.close()
        control = prefix + process.stdout.read()
        process.wait(timeout=180); reader.join(10); assert not reader.is_alive()
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        stdout = control
        receipt = b''
        if is_compile and self.mode in ('replay','local-warm'):
            _, receipt = key(control); stdout = b''
        row.update(returncode=process.returncode, receipt=receipt.decode(), after=observe(output),
            events=events(fd),
            child_cpu_seconds=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
            helper_wall_seconds=time.monotonic()-start,
            control_sha256=self.save(label+'.control',control),
            stdout_sha256=self.save(label+'.stdout',stdout),
            stderr_sha256=self.save(label+'.stderr',diagnostic[0]))
        if os.path.isfile(output): row['output_sha256'] = self.save(label+'.output',open(output,'rb').read())
        return {'returncode':process.returncode, 'stdout':stdout.hex(), 'stderr':diagnostic[0].hex()}
