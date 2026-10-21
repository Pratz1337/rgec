"""Inspect a released native CAS-capable baseline on Modal; no fake compiles."""
import json
import sys
from pathlib import Path
import modal
from modal_rgec_native import execute, sha


def main(root):
    root.mkdir(parents=True, exist_ok=False)
    source = Path(__file__)
    (root / source.name).write_bytes(source.read_bytes())
    image = modal.Image.from_registry('swift:6.4.0-noble').apt_install('python3', 'g++', 'binutils')
    result = {'platform': 'Modal', 'gpu': None, 'experiment_cases': 0,
        'purpose': 'Verify released native CAS baseline availability before real comparisons.',
        'official_distribution': 'https://www.swift.org/install/linux/ubuntu/24_04/',
        'image_reference': 'swift:6.4.0-noble', 'source_sha256': sha(source.read_bytes())}
    try:
        with modal.enable_output(), modal.App('rgec-real-cas-baseline-toolchain').run() as app:
            sb = modal.Sandbox.create('/bin/sleep', 'infinity', app=app,
                image=image, cpu=2, memory=4096, timeout=600, block_network=True)
            result.update(sandbox_id=sb.object_id, image_id=image.object_id)
            try:
                status, out, error = execute(sb, '/bin/sh', '-c', 'command -v clang')
                assert status == 0, error
                compiler = out.decode().strip(); result['compiler'] = compiler
                for label, args in (('version', ['--version']), ('driver-help', ['--help-hidden']),
                                     ('cc1-help', ['-cc1', '-help'])):
                    status, out, error = execute(sb, compiler, *args)
                    (root / (label + '.stdout')).write_bytes(out)
                    (root / (label + '.stderr')).write_bytes(error)
                    assert status == 0, error
                    result[label + '_sha256'] = sha(out)
                    if label == 'version': result['version'] = out.decode()
                    else: result[label + '_cache_options'] = [s.strip() for s in out.decode().splitlines()
                        if any(word in s.lower() for word in ('cas-', 'cache-compile', 'depscan'))]
                status, out, error = execute(sb, '/usr/bin/sha256sum', compiler)
                assert status == 0, error
                result['compiler_sha256'] = out.decode().split()[0]
            finally:
                sb.terminate()
                try: sb.wait()
                except modal.exception.SandboxTerminatedError: pass
                result['cleanup_returncode'] = sb.returncode
    except Exception as error:
        result['error'] = str(error)
        raise
    finally:
        (root / 'evidence.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == '__main__':
    main(Path(sys.argv[1]))
