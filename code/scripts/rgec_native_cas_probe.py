"""Actual released Clang CAS cold/hit behavior under native output authority."""
import json
import os
import subprocess
import sys

sys.path.insert(0, '/')
from modal_recipient_entry import drop
from rgec_backend_probe import ROOT, reset, watch, queue_signature
from rgec_native_effect_probe import observe, sha, signature
from rgec_native_event_probe import events


def main(quiet=False):
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    result = {'cases': [], 'cache_hit_confirmed': 0, 'cache_remarks_enabled': not quiet, 'noninterference_certified': False,
        'scope': 'Same released Clang native/CAS comparison. Cache remarks are instrumentation; raw streams are retained without rewriting.'}
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': ROOT}
    def command(argv, cwd, cache=None):
        active = dict(env)
        if cache: active['XDG_CACHE_HOME'] = cache
        p = subprocess.Popen(argv, cwd=cwd, env=active, preexec_fn=drop, close_fds=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, error = p.communicate(timeout=180)
        return p.returncode, out, error
    code, out, error = command(['/usr/bin/clang', '-O1', '-fPIC', '-c', 'deflate.c',
                               '-o', ROOT + '/prior.o'], '/src/zlib')
    assert code == 0, error
    prior = open(ROOT + '/prior.o', 'rb').read()
    def save(name, data):
        open(ROOT + '/' + name, 'wb').write(data)
        return sha(data)
    try:
        for cwd, source in (('/src/zlib','adler32.c'),('/src/zlib','deflate.c'),('/src/libfuzzer','FuzzerUtil.cpp')):
            compiler = '/usr/bin/clang++' if source.endswith('.cpp') else '/usr/bin/clang'
            flags = ['-O1'] + (['-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])
            for kind in (('missing-parent',) if quiet else ('hardlink', 'readonly-output', 'missing-parent')):
                name = source + '-' + kind
                folder = ROOT + '/action-' + name
                cache = ROOT + '/cas-' + name
                os.mkdir(cache); os.chown(cache,65534,65534)
                cold_cache = cache + '-cold';os.mkdir(cold_cache);os.chown(cold_cache,65534,65534)
                rows = []
                # Prime the same command/output identity with ordinary writable
                # authority, then challenge the actual recipient state.
                output = reset(folder, 'regular', prior)
                if kind == 'missing-parent':
                    os.mkdir(folder + '/missing'); os.chown(folder + '/missing',65534,65534)
                    output = folder + '/missing/action.o'
                cached = [compiler] + flags + ['-fdepscan=inline', '-Xclang', '-fcache-compile-job',
                    ] + ([] if quiet else ['-Rcompile-job-cache']) + ['-c', source, '-o', output]
                code, out, error = command(cached,cwd,cache)
                prime = {'returncode':code,'stdout_sha256':save(name+'-prime.stdout',out),
                    'stderr_sha256':save(name+'-prime.stderr',error)}
                assert code == 0, error
                for mode in ('native','cas-cold','cas-hit'):
                    output = reset(folder,kind,prior)
                    paths = [output,folder+'/alias.o',folder+'/target.o']
                    before = {p:observe(p) for p in paths}
                    held = os.open(output,os.O_RDONLY) if os.path.isfile(output) else None
                    fd = watch(folder)
                    argv = [compiler] + flags + ([] if quiet else ['-Rcompile-job-cache']) + ['-c',source,'-o',output] if mode=='native' else cached
                    code,out,error = command(argv,cwd,cold_cache if mode=='cas-cold' else cache if mode=='cas-hit' else None)
                    queued = events(fd)
                    label = name+'-'+mode
                    row = {'case':label,'mode':mode,'returncode':code,'paths':paths,'before':before,
                        'after':{p:observe(p) for p in paths},'directory_entries_after':sorted(os.listdir(folder)),
                        'events':queued,'stdout_sha256':save(label+'.stdout',out),
                        'stderr_sha256':save(label+'.stderr',error),
                        'held_fd_content_sha256':save(label+'.held.o',os.read(held,10000000)) if held is not None else None,
                        'object_sha256':save(label+'.object.o',open(output,'rb').read()) if os.path.isfile(output) else None,
                        'cache_trace':error.decode(errors='replace').splitlines()}
                    if held is not None:os.close(held)
                    rows.append(row)
                native,cold,replay=rows
                hit = any('cache hit' in s.lower() for s in replay['cache_trace'])
                result['cache_hit_confirmed'] += hit
                result['cases'].append({'name':name,'source':source,'kind':kind,'prime':prime,
                    'native':native,'cold':cold,'replay':replay,'cache_hit_confirmed':hit,
                    'cold_hit_status_match':cold['returncode']==replay['returncode'],
                    'status_match':native['returncode']==replay['returncode'],
                    'object_match':native['object_sha256']==replay['object_sha256'],
                    'structural_effects_match':signature(native)==signature(replay),
                    'queued_event_roles_match':queue_signature(native['events'])==queue_signature(replay['events'])})
                print(name,code,'confirmed hit',hit,flush=True)
    finally:
        open(ROOT+'/evidence.json','w').write(json.dumps(result,indent=2))


if __name__=='__main__':main(len(sys.argv)>1 and sys.argv[1]=='silent')
