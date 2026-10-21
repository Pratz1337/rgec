"""Host-authorized frozen capture and cold recipient publication on Modal.

Known checks do not certify closure. This experimental path has no cache API.
"""

import hashlib
import json
import os
import subprocess
import sys

from modal_recipient_entry import ENV, RECIPIENT, TRUSTED, drop, native
from recipient_lease import RecipientLease


FLAGS = ['-O1', '-fno-omit-frame-pointer', '-gline-tables-only',
         '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION', '-fsanitize=address',
         '-fsanitize-address-use-after-scope', '-fsanitize=fuzzer-no-link']
PROFILES = {
    'zlib-adler32': ('/src/zlib', 'adler32.c', [], FLAGS + ['-fPIC']),
    'zlib-deflate': ('/src/zlib', 'deflate.c', [], FLAGS + ['-fPIC']),
    'graphicsmagick-png': ('/src/graphicsmagick', 'coders/png.c',
        ['-DHAVE_CONFIG_H', '-I.', '-I.', '-I/work/include'], FLAGS + ['-Wall']),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main(profile, request_id):
    cwd, source, pp_flags, flags = PROFILES[profile]
    directory = TRUSTED + '/requests/' + request_id
    os.mkdir(directory, 0o700)
    row = {'profile': profile, 'request_id': request_id, 'cwd': cwd,
           'source_path': cwd + '/' + source, 'flags': flags, 'language': 'c',
           'complete_closure_certified': False, 'shared_lookup_calls': 0,
           'phases': []}
    lease, publisher = None, None

    def save(name, value):
        with open(directory + '/' + name, 'wb') as stream:
            stream.write(value)

    try:
        lease = RecipientLease().acquire()
        row['lease_audit'], row['stopped_actors'] = lease.audit, lease.stopped
        row['phases'].append('recipient-stopped')
        # Reading as the recipient avoids a root-only source symlink becoming
        # an input or digest oracle. The source pathname comes from the profile.
        code, original, source_error = native(['/usr/bin/python3', '-I', '-c',
            "import os,stat,sys; p=" + repr(source) + "; f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW); "
            "assert stat.S_ISREG(os.fstat(f).st_mode); sys.stdout.buffer.write(os.fdopen(f,'rb').read())"], cwd)
        row['source_capture_returncode'] = code
        save('source-capture.stderr', source_error)
        row['source_sha256'] = sha(original) if code == 0 else None
        common = ['/usr/local/bin/clang'] + pp_flags + flags
        plugin_code, plugin_out, plugin_error = native(common + ['-Xclang', '-load',
            '-Xclang', '/rgec-closure.so', '-Xclang', '-add-plugin', '-Xclang',
            'rgec-closure', '-fsyntax-only', source], cwd)
        save('observer.stdout', plugin_out)
        save('observer.stderr', plugin_error)
        row['observer_returncode'] = plugin_code
        try:
            observation = json.loads(plugin_out.decode())
        except ValueError:
            observation = None
        row['observation'] = observation
        pp_code, rewritten, pp_error = native(common + ['-E', '-frewrite-includes', source], cwd)
        save('input.c', rewritten)
        save('preprocessor.stderr', pp_error)
        row['preprocessor_returncode'] = pp_code
        row['rewritten_sha256'] = sha(rewritten)
        row['known_candidate'] = bool(code == plugin_code == pp_code == 0 and observation and
            not (observation['macro_dependencies'] or observation['inline_assembly'] or
                 observation['syntax_errors'] or pp_error))
        # A warning-bearing preprocess goes privately: concatenating its
        # diagnostics with a rewritten compile can duplicate native warnings.
        row['phases'].append('immutable-input-captured')
        row['candidate'] = row['known_candidate']
        if row['candidate']:
            publisher = subprocess.Popen(['/usr/bin/python3', '-I', TRUSTED +
                '/modal_recipient_entry.py', 'publisher'], preexec_fn=drop, close_fds=True,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=ENV, universal_newlines=True)
            ready = json.loads(publisher.stdout.readline())
            row['recipient_begin'] = ready
            row['candidate'] = ready['eligible']
            if not row['candidate']:
                publisher.wait(timeout=10)
                publisher = None
        row['phases'].append('candidate-begin' if row['candidate'] else 'private-before-lookup')
        with open(directory + '/capture.json', 'w') as stream:
            json.dump(row, stream, indent=2)
        print(json.dumps({'phase': 'captured', 'capture': row}), flush=True)
        reply = json.loads(sys.stdin.readline())
        if row['candidate']:
            assert set(reply) == {'op', 'returncode', 'stdout_hex', 'stderr_hex', 'object_hex'}
            assert reply['op'] == 'finish'
            rc, out, error = reply['returncode'], bytes.fromhex(reply['stdout_hex']), bytes.fromhex(reply['stderr_hex'])
            assert (reply['object_hex'] is not None) == (rc == 0)
            publisher.stdin.write(json.dumps({'object_hex': reply['object_hex']}) + '\n')
            publisher.stdin.flush()
            publisher.stdin.close()
            publisher.wait(timeout=20)
            publish_error = publisher.stderr.read()
            assert publisher.returncode == 0, publish_error
            publisher = None
            row['phases'].append('isolated-cold-payload-published')
        else:
            assert reply == {'op': 'private'}
            rc, out, error = native(common + ['-c', source, '-o', RECIPIENT + '/action.o'], cwd)
            row['phases'].append('whole-action-private')
        save('result.stdout', out)
        save('result.stderr', error)
        row['returncode'] = rc
        row['stdout_sha256'], row['stderr_sha256'] = sha(out), sha(error)
        if rc == 0:
            code, object_bytes, read_error = native(['/usr/bin/python3', '-I', '-c',
                "import sys; sys.stdout.buffer.write(open(" + repr(RECIPIENT + '/action.o') + ",'rb').read())"], cwd)
            assert code == 0, read_error
            save('object.o', object_bytes)
            row['object_sha256'] = sha(object_bytes)
        with open(directory + '/result.json', 'w') as stream:
            json.dump(row, stream, indent=2)
    except Exception as error:
        row['error'] = str(error)
        raise
    finally:
        if publisher:
            publisher.kill()
            publisher.wait()
        if lease:
            lease.release()
        row['phases'].append('recipient-released')
        with open(directory + '/evidence.json', 'w') as stream:
            json.dump(row, stream, indent=2)
    print(json.dumps({'phase': 'finished', 'returncode': row['returncode']}), flush=True)
