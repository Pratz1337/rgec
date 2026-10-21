"""Challenge genuine backend-owned split-DWARF outputs on unchanged sources."""
import json
import os
import sys

sys.path.insert(0,'/')
import rgec_residual_probe as residual
from rgec_backend_probe import ROOT, packet_info, reset, run, queue_signature
from rgec_native_effect_probe import FLAGS, signature


def main():
    os.mkdir(ROOT);os.chown(ROOT,65534,65534)
    result={'cases':[],'complete_closure_certified':False,
        'scope':'Real internal split-DWARF output option, with and without genuine symbol-map reads; unchanged authentic project functions'}
    status,out,error=run(['/usr/local/bin/clang']+FLAGS+['-fPIC','-c','deflate.c','-o',ROOT+'/prior.o'],'/src/zlib')
    assert status==0,error
    prior=open(ROOT+'/prior.o','rb').read()
    try:
        for path,symbol in (('/src/zlib/adler32.c','adler32'),('/src/zlib/deflate.c','deflate'),
                            ('/src/libfuzzer/FuzzerUtil.cpp','_ZN6fuzzer14SimpleFastHashEPKhm')):
            cwd,source=os.path.dirname(path),os.path.basename(path)
            original=open(path,'rb').read();residual.save(source+'.original',original)
            for variant,mapped in (('direct-dwo',False),('map-direct-dwo',True),('map-driver-dwo',True)):
                name=source+'-'+variant
                side=ROOT+'/action-'+source+('/action.dwo' if variant=='map-driver-dwo' else '/native-side.dwo')
                case={'name':name,'source':source,'source_path':path,'cwd':cwd,
                    'compiler':'/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang',
                    'flags':FLAGS+(['-stdlib=libc++','-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])+
                        (['-g','-gsplit-dwarf'] if variant=='map-driver-dwo' else
                         ['-g','-Xclang','-enable-split-dwarf','-Xclang','-split-dwarf-file','-Xclang',side])}
                if mapped:
                    mapping=ROOT+'/rewrite-map.yaml'
                    contents=('function: { source: "'+symbol+'", target: "rgec_actual_direct_dwo" }\n').encode()
                    open(mapping,'wb').write(contents);os.chmod(mapping,0o644)
                    residual.save(name+'.yaml',contents);case['flags']+=['-frewrite-map-file',mapping]
                def snapshot(label):
                    data=open(side,'rb').read() if os.path.isfile(side) else None
                    return None if data is None else {'bytes':len(data),'sha256':residual.save(name+'-'+label+'.dwo',data)}
                native=residual.request(case,'native',prior);native_side=snapshot('native')
                record=residual.request(case,'record',prior);record_side=snapshot('record')
                assert native['returncode']==record['returncode']==0,(case,native,record)
                if variant=='map-driver-dwo':assert native_side and native_side['bytes']>0,(case,native_side)
                packet=None;producer_status=None
                if record['receipt']!='RGECP1':
                    bound=open(ROOT+'/'+name+'.key','rb').read()
                    reset(ROOT+'/action-'+source,'hardlink',prior)
                    producer_status,packet,error=run(['/rgec-backend','--rgec-produce-parametric'],cwd,None,bound)
                    residual.save(name+'.producer.packet',packet);residual.save(name+'.producer.stderr',error)
                    info=packet_info(packet);assert info['reusable']
                replay=residual.request(case,'replay',prior,packet);replay_side=snapshot('replay')
                checks={'status_stream_object_match':all(native[key]==replay[key] for key in
                    ('returncode','stdout_sha256','stderr_sha256','object_sha256')),
                    'side_output_matches':native_side==replay_side,
                    'structural_effects_match':signature(native)==signature(replay),
                    'event_roles_match':queue_signature(native['events'])==queue_signature(replay['events'])}
                result['cases'].append(dict(case,native=native,record=record,replay=replay,
                    native_side=native_side,record_side=record_side,replay_side=replay_side,
                    native_created_side_file=native_side is not None,
                    direct_side_stream_exercised=variant!='map-driver-dwo' and native_side is not None,
                    producer_returncode=producer_status,**checks))
                print(name,replay['receipt'],checks,flush=True)
            assert open(path,'rb').read()==original
    finally:
        with open(ROOT+'/evidence.json','w') as stream:json.dump(result,stream,indent=2)


if __name__=='__main__':main()
