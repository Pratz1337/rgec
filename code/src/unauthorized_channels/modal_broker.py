"""Host-bound Modal tool interface with gated frozen cold compiler capture.

The orchestrator keeps this object/SDK on the host. Agent tools receive only
the exec command or exact request schema. No shared lookup is implemented.
"""

import concurrent.futures
import hashlib
import json
import threading
import tarfile
import uuid

from unauthorized_channels.build_broker import BuildResult
from unauthorized_channels.compiler_worker import CompilerAction


TARGETS = frozenset(('zlib-adler32', 'zlib-deflate', 'graphicsmagick-png'))
TRUSTED = '/rgec-trusted'


def collected(process):
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        out, error = pool.submit(process.stdout.read), pool.submit(process.stderr.read)
        process.wait()
        return BuildResult(process.returncode, out.result(), error.result())


class ModalBuildSession:
    def __init__(self, sandbox):
        self._sandbox = sandbox
        self._gate = threading.Lock()
        self.current_capture = None
        self.actor_ids = []
        self.captures = []

    def _launch(self, command, timeout):
        identity = uuid.uuid4().hex
        process = self._sandbox.exec('/usr/bin/python3', '-I',
            TRUSTED + '/modal_recipient_entry.py', 'exec', identity, command,
            text=False, timeout=timeout)
        self.actor_ids.append(identity)
        return process

    def _read(self, path):
        from modal_rgec_native import read
        return read(self._sandbox, path)

    def exec(self, command, *, timeout=180, input_bytes=None):
        # Lock through launch; a running command may leave descendants. Capture
        # stops those descendants separately while preventing any later exec.
        with self._gate:
            process = self._launch(command, timeout)
        if input_bytes is not None:
            process.stdin.write(input_bytes)
            process.stdin.write_eof()
            process.stdin.drain()
        result = collected(process)
        if result.returncode == 124:
            self.close()
        return result

    def build(self, payload):
        if payload != {'action': 'compile'}:
            raise ValueError('unsupported private full-build request')
        # Full scripts stay private and receive no frozen-input/cache claim.
        with self._gate:
            return collected(self._launch('cd /src/graphicsmagick && /bin/arvo compile', 1200))

    def request(self, payload, root, backend):
        # root/backend are trusted host bindings, never part of agent payload.
        if not isinstance(payload, dict) or set(payload) != {'action', 'target'} or \
                payload['action'] != 'compile' or not isinstance(payload['target'], str) or \
                payload['target'] not in TARGETS:
            raise ValueError('unsupported bound compiler request')
        with self._gate:
            identity = uuid.uuid4().hex
            directory = TRUSTED + '/requests/' + identity
            process = self._sandbox.exec('/usr/bin/python3', '-I',
                TRUSTED + '/modal_recipient_entry.py', 'capture', payload['target'],
                identity, text=True, bufsize=1, timeout=480)
            self._controller = process
            try:
                frames = iter(process.stdout)
                first = json.loads(next(frames))
                assert first['phase'] == 'captured'
                capture = first['capture']
                self.current_capture = capture
                (root / (identity + '.capture.json')).write_text(json.dumps(capture, indent=2), encoding='utf-8')
                if capture['candidate']:
                    rewritten = self._read(directory + '/input.c')
                    assert hashlib.sha256(rewritten).hexdigest() == capture['rewritten_sha256']
                    action = CompilerAction(rewritten, capture['source_path'],
                        capture['cwd'], capture['language'], tuple(capture['flags']))
                    manifest, out, error, object_bytes = backend(root, identity, action)
                    capture['sealed_backend'] = manifest
                    reply = {'op': 'finish', 'returncode': manifest['returncode'],
                        'stdout_hex': out.hex(), 'stderr_hex': error.hex(),
                        'object_hex': object_bytes.hex() if object_bytes is not None else None}
                else:
                    reply = {'op': 'private'}
                process.stdin.write(json.dumps(reply) + '\n')
                process.stdin.drain()
                terminal = json.loads(next(frames))
                assert terminal['phase'] == 'finished'
                process.wait()
                controller_error = process.stderr.read()
                assert process.returncode == 0, controller_error
                final = json.loads(self._read(directory + '/evidence.json'))
                final['sealed_backend'] = capture.get('sealed_backend')
                final['sandbox_id'] = self._sandbox.object_id
                self.captures.append(final)
                (root / (identity + '.json')).write_text(json.dumps(final, indent=2), encoding='utf-8')
                for name in ('result.stdout', 'result.stderr', 'input.c', 'observer.stdout',
                             'observer.stderr', 'preprocessor.stderr', 'source-capture.stderr'):
                    (root / (identity + '.' + name)).write_bytes(self._read(directory + '/' + name))
                if final['returncode'] == 0:
                    (root / (identity + '.object.o')).write_bytes(self._read(directory + '/object.o'))
                return BuildResult(final['returncode'],
                    self._read(directory + '/result.stdout'), self._read(directory + '/result.stderr'))
            except Exception as error:
                # Abort the entire namespace on an interrupted protocol; no
                # actor or compiler may keep mutating behind a later request.
                (root / (identity + '.controller-error.txt')).write_text(str(error), encoding='utf-8')
                if process.poll() is not None:
                    (root / (identity + '.controller.stderr')).write_text(process.stderr.read(), encoding='utf-8')
                self.close()
                raise
            finally:
                self.current_capture = None

    def close(self):
        self._sandbox.terminate()

    def backend_request(self, payload, root, store):
        """Experimental native continuation; store/root are trusted host objects."""
        if not isinstance(payload, dict) or set(payload) != {'action', 'target'} or \
                payload['action'] != 'compile' or payload['target'] not in \
                ('zlib-adler32', 'zlib-deflate', 'fuzzer-util',
                 'zlib-adler32-parametric', 'zlib-deflate-parametric', 'fuzzer-util-parametric',
                 'zlib-adler32-rewrite', 'zlib-deflate-rewrite', 'fuzzer-util-rewrite',
                 'zlib-adler32-nested', 'zlib-deflate-nested', 'fuzzer-util-nested'):
            raise ValueError('unsupported bound backend request')
        with self._gate:
            identity = uuid.uuid4().hex
            directory = TRUSTED + '/requests/' + identity
            process = self._sandbox.exec('/usr/bin/python3', '-I',
                TRUSTED + '/modal_backend_controller.py', payload['target'], identity,
                'replay', text=True, bufsize=1, timeout=480)
            try:
                frames = iter(process.stdout)
                terminal = json.loads(next(frames))
                if terminal['phase'] == 'query':
                    query = root / (identity + '.query.bin')
                    from modal_rgec_native import read, write
                    query.write_bytes(read(self._sandbox, directory + '/query.bin'))
                    bound = query.read_bytes()
                    assert len(bound) == terminal['key_bytes'] and hashlib.sha256(bound).hexdigest() == terminal['key_sha256']
                    packet = store.resolve(payload['target'], bound)
                    write(self._sandbox, directory + '/reply.packet', packet)
                    process.stdin.write(json.dumps({'op': 'continue'}) + '\n')
                    process.stdin.drain()
                    terminal = json.loads(next(frames))
                assert terminal['phase'] == 'finished'
                process.wait()
                assert process.returncode == 0, process.stderr.read()
                archive = root / (identity + '.tar.gz')
                self._sandbox.filesystem.copy_to_local(directory + '.tar.gz', archive)
                assert hashlib.sha256(archive.read_bytes()).hexdigest() == terminal['archive_sha256']
                target = root / identity
                target.mkdir()
                with tarfile.open(archive) as stream:
                    for member in stream:
                        assert member.isfile() and '/' not in member.name and '\\' not in member.name
                        (target / member.name).write_bytes(stream.extractfile(member).read())
                final = json.loads((target / 'trace.json').read_text())
                final['sandbox_id'], final['request_id'] = self._sandbox.object_id, identity
                self.captures.append(final)
                return BuildResult(final['returncode'], (target / 'result.stdout').read_bytes(),
                                   (target / 'result.stderr').read_bytes())
            except Exception:
                self.close()
                raise
