"""Recover only an uncollected native slice worker from the frozen experiment."""
import json
from pathlib import Path
import sys

import modal
from modal_rgec_native import execute, sha
from modal_rgec_residual import collect


def main(prior_root, root):
    original = (prior_root / 'evidence.json').read_bytes(); prior = json.loads(original)
    assert 'error' in prior and len(prior['sandboxes']) == 5
    completed = prior['sandboxes'][:4]
    assert all(row['returncode'] == 0 and row['cleanup_returncode'] == 137 for row in completed)
    assert not prior['sandboxes'][4].get('raw_archive_sha256')
    for row in completed:
        assert sha((prior_root / row['phase'] / 'raw.tar.gz').read_bytes()) == row['raw_archive_sha256']
    root.mkdir(parents=True, exist_ok=False)
    for path, digest in prior['source_sha256'].items():
        data = (prior_root / Path(path).name).read_bytes(); assert sha(data) == digest
        (root / Path(path).name).write_bytes(data)
    (root / 'native-build.py').write_bytes((prior_root / 'native-build.py').read_bytes())
    (root / 'interrupted-attempt-evidence.json').write_bytes(original)
    evidence = {key: value for key, value in prior.items() if key not in ('error', 'sandboxes')}
    evidence['sandboxes'] = [dict(row, artifact_root=prior_root.name) for row in completed]
    evidence['recovered_from_root'] = prior_root.name
    evidence['recovered_from_manifest_sha256'] = sha(original)
    evidence['interrupted_worker'] = prior['sandboxes'][4]
    evidence['recovery_scope'] = 'Only replay-2 rerun; completed original capture, producer and two recipient workers are reused without alteration. Interrupted evidence remains retained and excluded from complete observations.'
    evidence['source_sha256'][Path(__file__).name] = sha(Path(__file__).read_bytes())
    (root / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    def persist(): (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    persist(); app = modal.App('rgec-generated-slice-missing-worker-recovery')
    try:
        with modal.enable_output(), app.run():
            image_id = completed[0]['image_id']; image = modal.Image.from_id(image_id)
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
                cpu=2, memory=4096, timeout=1800, block_network=True)
            row = {'phase': 'replay-2', 'id': sandbox.object_id, 'image_id': image_id}
            evidence['sandboxes'].append(row); persist()
            print('Recovering actual missing worker', sandbox.object_id, flush=True)
            try:
                tools = completed[0]['tool_sha256']
                status, out, error = execute(sandbox, '/usr/bin/sha256sum', *tools.keys())
                actual = {line.split()[1]: line.split()[0] for line in out.decode().splitlines()}
                assert status == 0 and actual == tools, error
                row['tool_sha256'] = actual; persist()
                for phase in ('capture', 'producer'):
                    archive = prior_root / phase / 'raw.tar.gz'; remote = '/transfer-' + phase + '.tar.gz'
                    sandbox.filesystem.copy_from_local(archive, remote)
                    status, out, error = execute(sandbox, '/usr/bin/sha256sum', remote)
                    assert status == 0 and out.decode().split()[0] == sha(archive.read_bytes()), error
                    status, out, error = execute(sandbox, '/usr/bin/python3', '-I', '-c',
                        "import os,sys,tarfile; target=sys.argv[2]; os.mkdir(target); "
                        "t=tarfile.open(sys.argv[1]); members=t.getmembers(); "
                        "assert all(m.isfile() and m.name.startswith('raw/') and os.path.basename(m.name)==m.name[4:] for m in members); "
                        "[open(target+'/'+os.path.basename(m.name),'wb').write(t.extractfile(m).read()) for m in members]",
                        remote, '/transfer-' + phase)
                    assert status == 0, error
                status, out, error = execute(sandbox, '/usr/bin/python3', '-I',
                    '/rgec_generated_slice_probe.py', 'replay', timeout=1500)
                row['returncode'] = status
                (root / 'replay-2.stdout').write_bytes(out); (root / 'replay-2.stderr').write_bytes(error)
                row['raw_archive_sha256'] = collect(sandbox, root, 'replay-2'); persist()
                assert status == 0, error[-6000:]
            finally:
                sandbox.terminate()
                try: sandbox.wait()
                except (modal.exception.SandboxTerminatedError, modal.exception.SandboxTimeoutError): pass
                row['cleanup_returncode'] = sandbox.returncode; persist()
    except Exception as error: evidence['error'] = repr(error); persist(); raise
    finally: persist()


if __name__ == '__main__': main(Path(sys.argv[1]), Path(sys.argv[2]))
