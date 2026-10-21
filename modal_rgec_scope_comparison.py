"""Compare real recipient-context scopes with identical native prefix and packets."""
import json
from pathlib import Path
import sys

import modal
from modal_rgec_native import execute, sha
from modal_rgec_residual import collect


def main(root):
    prior_root = Path('runs/rgec-modal-authenticated-prefix-history-2026-10-05-v22')
    prior = json.loads((prior_root / 'evidence.json').read_text())
    audit = json.loads((prior_root / 'independent-read-store-audit.json').read_text())
    assert sha((prior_root / 'evidence.json').read_bytes()) == audit['manifest_sha256']
    assert audit['prefix_backend_warning_interaction_verified']
    assert all(row['cleanup_returncode'] == 137 for row in prior['sandboxes'])
    tools = prior['sandboxes'][0]['tool_sha256']
    root.mkdir(parents=True, exist_ok=False)
    sources = [Path(__file__), Path('modal_rgec_native.py'), Path('modal_rgec_residual.py'),
        Path('scripts/rgec_scope_comparison_probe.py'), Path('src/unauthorized_channels/backend_recipe_store.py')]
    sources += [Path('scripts') / name for name in ('rgec_backend_probe.py', 'rgec_native_effect_probe.py',
                                                 'rgec_native_event_probe.py')]
    sources += [Path('src/unauthorized_channels/modal_recipient_entry.py')]
    for path in sources: (root / path.name).write_bytes(path.read_bytes())
    context = {'protocol': 'RGECB3', 'image_id': prior['sandboxes'][0]['image_id'],
        'backend_sha256': tools['/rgec-backend'], 'compiler_sha256': tools['/usr/local/bin/clang']}
    preload = {'context': context, 'prior_hex': (prior_root / 'prior.o').read_bytes().hex(), 'profiles': []}
    profiles = [('zlib-adler32-rewrite', '/src/zlib', 'adler32.c'),
                ('zlib-deflate-rewrite', '/src/zlib', 'deflate.c'),
                ('fuzzer-util-rewrite', '/src/libfuzzer', 'FuzzerUtil.cpp')]
    for profile, cwd, source in profiles:
        row = next(row for row in prior['comparisons'] if row['label'] ==
                   profile + '-A-prefix-ignored-separate-producer-miss')
        request = prior_root / row['actual']['request_id']
        bound = (request / 'query.bin').read_bytes()
        packet = (request / 'reply.packet').read_bytes()
        origin = next(item['origin'] for item in prior['store_audit'] if item['profile'] == profile and
                      item['origin']['captured_context_sha256'] == sha(bound))
        offset = 8
        import struct
        count = struct.unpack_from('<Q', bound)[0]; arguments = []
        for _ in range(count):
            size = struct.unpack_from('<Q', bound, offset)[0]; offset += 8
            arguments.append(bound[offset:offset + size].decode()); offset += size
        receipt = {'version': 1, 'context': context, 'profile': profile, 'binding': 'computation',
            'key_sha256': origin['computation_key_sha256'], 'packet_sha256': sha(packet),
            'origin': origin, 'complete_closure_certified': False}
        preload['profiles'].append({'profile': profile, 'cwd': cwd, 'source': source,
            'full_context_sha256': sha(bound), 'arguments': arguments,
            'delivery_hex': packet.hex(), 'receipt': receipt,
            'ignored_source_hex': (prior_root / (source + '-prefix-ignored.source')).read_bytes().hex(),
            'warning_source_hex': (prior_root / (source + '-prefix-warning.source')).read_bytes().hex(),
            'map_hex': (prior_root / (source + '-A.yaml')).read_bytes().hex()})
    (root / 'preload.json').write_text(json.dumps(preload, separators=(',', ':')), encoding='utf-8')
    evidence = {'platform': 'Modal', 'cpu_per_sandbox': 2, 'memory_mib': 4096, 'gpu': None,
        'prior_root': prior_root.as_posix(), 'prior_manifest_sha256': audit['manifest_sha256'],
        'preload_sha256': sha((root / 'preload.json').read_bytes()),
        'source_sha256': {str(path): sha(path.read_bytes()) for path in sources}, 'tool_sha256': tools,
        'blocks_per_worker': 2, 'sandboxes': [], 'scope': 'Same seeded native packets, private service, native cc1 arguments and effect machinery. Full-context additional equality guard; misses compute natively without filling. No superiority claim over Riker or general effectful memoization.',
        'complete_closure_certified': False, 'adaptive_noninterference_proved': False}
    image = modal.Image.from_id(prior['sandboxes'][0]['image_id'])
    for path in sources[3:]: image = image.add_local_file(str(root / path.name), '/' + path.name, copy=True)
    image = image.add_local_file(str(root / 'preload.json'), '/rgec-private/scope/preload.json', copy=True)
    image = image.run_commands('chmod 700 /rgec-private /rgec-private/scope')
    def persist(): (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    app = modal.App('rgec-native-context-scope-comparison')
    try:
        with modal.enable_output(), app.run():
            for worker in range(3):
                sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
                    cpu=2, memory=4096, timeout=1800, block_network=True)
                row = {'worker': worker, 'id': sandbox.object_id, 'image_id': image.object_id}
                evidence['sandboxes'].append(row); persist()
                print('Bound actual scope-comparison worker', sandbox.object_id, flush=True)
                try:
                    code, out, error = execute(sandbox, '/usr/bin/sha256sum', *tools.keys())
                    actual = {line.split()[1]: line.split()[0] for line in out.decode().splitlines()}
                    assert code == 0 and actual == tools, error
                    row['tool_sha256'] = actual; persist()
                    code, out, error = execute(sandbox, '/usr/bin/python3', '-I',
                        '/rgec_scope_comparison_probe.py', '2', timeout=1500)
                    row['returncode'] = code
                    (root / ('worker-' + str(worker) + '.stdout')).write_bytes(out)
                    (root / ('worker-' + str(worker) + '.stderr')).write_bytes(error)
                    row['raw_archive_sha256'] = collect(sandbox, root, 'worker-' + str(worker), '/rgec-private/scope')
                    persist(); assert code == 0, error[-6000:]
                    print('worker', worker, 'native observations match for both scopes', flush=True)
                finally:
                    sandbox.terminate()
                    try: sandbox.wait()
                    except (modal.exception.SandboxTerminatedError, modal.exception.SandboxTimeoutError): pass
                    row['cleanup_returncode'] = sandbox.returncode; persist()
    except Exception as error: evidence['error'] = repr(error); persist(); raise
    finally: persist()


if __name__ == '__main__': main(Path(sys.argv[1]))
