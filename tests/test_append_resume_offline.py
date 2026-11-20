"""Hardware-free tests for additive FIPS205 message-signature capture."""
from __future__ import annotations

# Allow direct execution from the repository root or tests/ directory.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

import prf_capture_core as live
import signature_message_path as msg
import signature_sequence_capture as batch
import signature_prf_sequence as seq

PHASES = ("fors_signature",)


def create_fake_full_capture(
    output_dir: Path,
    signature_id: int,
    *,
    sk_seed: bytes,
    sk_prf: bytes,
    pk_seed: bytes,
    pk_root: bytes,
    seed_id: int,
    message_seed: int = 20260917,
    legacy: bool = False,
):
    output_dir.mkdir(parents=True, exist_ok=True)
    calls, info = msg.build_random_message_signing_prf_sequence(
        signature_id=signature_id,
        sk_prf=sk_prf, pk_seed=pk_seed, pk_root=pk_root,
        message_seed=message_seed, capture_phases=PHASES,
    )
    prefix = output_dir / 'capture'
    N = len(calls)
    np.save(str(prefix) + '_traces_random.npy', np.full((N, 11), float(signature_id), dtype=np.float32))
    np.save(str(prefix) + '_addrs_random.npy', np.asarray([list(c.case.addr) for c in calls], dtype=np.uint8))
    np.save(str(prefix) + '_params_random.npy', np.asarray([c.case.meta_row(0,0) for c in calls], dtype=np.uint64))
    meta = seq.encode_signature_metadata_rows_uint64(calls)
    if legacy:
        meta = meta.astype('int64')
    np.save(str(prefix) + '_signature_sequence_meta.npy', meta)
    np.save(str(prefix) + '_signature_sequence_meta_columns.npy', seq.SIGNATURE_META_COLUMNS)
    cfg = {
        'parameter_set':live.ACTIVE_PARAM_SET,
        'build':{'secret_seed_id':seed_id,'sk_seed_sha256':hashlib.sha256(sk_seed).hexdigest()}
    }
    Path(str(prefix) + '_capture_config.json').write_text(json.dumps(cfg),encoding='utf8')
    metadata = seq.describe_signature_metadata_encoding(info)
    metadata['message_helper_version'] = 'OLD_VERSION_TO_TEST_COMPATIBILITY'
    if legacy:
        metadata['signature_meta_dtype'] = 'int64'
    Path(str(prefix) + '_signature_sequence.json').write_text(json.dumps(metadata),encoding='utf8')
    return str(prefix), info


def main():
    live.select_parameter_set('128f')
    with tempfile.TemporaryDirectory() as td:
        basedir = Path(td)
        result_dir = basedir / 'results'
        param_root = result_dir / 'SLH_DSA_128f_sha2_message_signature_sequence'
        seed_dir = param_root / 'Os' / 'seed_000'
        firmware = basedir / 'firmware'
        firmware.mkdir()
        (firmware / 'slh_dsa_prf_target.c').write_text('fake',encoding='ascii')
        (firmware / 'Makefile').write_text('fake',encoding='ascii')
        (firmware / 'simpleserial-SLH-DSA-CW308_STM32F3.hex').write_text('fake',encoding='ascii')
        seed_manifest = param_root / 'shared_secret_seeds.json'
        pool, _ = live.load_or_create_secret_seed_manifest(seed_manifest,num_seeds=1,
            master_seed=424242,parameter_set='128f')
        sk_seed = pool[0]
        pk_seed = bytes(live.PUB_SEED)
        sk_prf = bytes(live.SK_PRF)
        pk_root, _ = msg.load_or_derive_pk_root_sha2(
            param_root / 'derived_pk_root_seed_000.json',sk_seed=sk_seed,pk_seed=pk_seed)
        old_manifest = {
            'format':'slh-dsa-fips205-random-message-signing-prf-capture-v3',
            'helper_version':'OLD_VERSION_TO_TEST_COMPATIBILITY',
            'parameter_set':'128f', 'mode':'sha2','message_seed':20260917,
            'message_length':32,'signing_variant':'hedged','addrnd_seed':20260918,
            'context_hex':'','pk_root_hex':pk_root.hex(),'capture_phases':list(PHASES),
            'num_signatures':3,'completed':[],
        }
        for sid in range(3):
            prefix,info=create_fake_full_capture(
                seed_dir / f'signature_{sid:03d}',sid,
                sk_seed=sk_seed,sk_prf=sk_prf,pk_seed=pk_seed,pk_root=pk_root,seed_id=0,
                legacy=True,
            )
            old_manifest['completed'].append({'signature_id':sid,'status':'completed-new-request',
                'capture_prefix':prefix})
        mf=seed_dir / 'signature_sequence_capture_manifest.json'
        mf.write_text(json.dumps(old_manifest,indent=2),encoding='utf8')
        sample_file = seed_dir / 'signature_000' / 'capture_traces_random.npy'
        previous_hash=hashlib.sha256(sample_file.read_bytes()).hexdigest()
        previous_mtime=sample_file.stat().st_mtime_ns
        original_manifest_hash=hashlib.sha256(mf.read_bytes()).hexdigest()
        pool_manifest_hash=hashlib.sha256(seed_manifest.read_bytes()).hexdigest()

        scan = msg.inspect_random_message_signature_resume(
            seed_dir,num_signatures=5,sk_prf=sk_prf,pk_seed=pk_seed,pk_root=pk_root,
            sk_seed=sk_seed,secret_seed_id=0,capture_phases=PHASES)
        assert scan['reused_signature_ids']==[0,1,2]
        assert scan['missing_signature_ids']==[3,4]
        assert previous_hash==hashlib.sha256(sample_file.read_bytes()).hexdigest()
        print('PASS: preflight detects 3 old + 2 missing without writes')

        captured=[]
        def fake_capture_one(scope,target,output_dir,**kwargs):
            sid=kwargs['signature_id']
            sid_secret=kwargs['sk_seed']
            expected_seed_id=0 if sid_secret==sk_seed else 1
            captured.append((expected_seed_id,sid))
            return create_fake_full_capture(
                Path(output_dir),sid,sk_seed=sid_secret,
                sk_prf=kwargs['sk_prf'], pk_seed=kwargs['pk_seed'],
                pk_root=kwargs['pk_root'],seed_id=expected_seed_id,
                message_seed=kwargs['message_seed'],legacy=False)

        scope=SimpleNamespace(adc=SimpleNamespace(samples=11))
        cw_fake=SimpleNamespace(program_target=lambda *a, **kw:None)
        fake_calibration=lambda *a, **kw:{'scope_samples':11,'trig_count':10}
        fake_reset=lambda *a, **kw:None
        with patch.dict(sys.modules,{'chipwhisperer':cw_fake}),\
                patch.object(msg,'capture_one_random_message_signing_prf_sequence',fake_capture_one),\
                patch.object(live,'reset_and_configure',fake_reset),\
                patch.object(live,'calibrate_and_set_samples',fake_calibration):
            state=batch.run_all_parameter_random_message_signature_captures_multiseed(
                scope,None,live,
                firmware_dir=firmware,results_base_dir=result_dir,
                param_sets=['128f'],compiler_opts=['Os'],
                signatures_per_param_set={'128f':5},num_secret_seeds=2,
                capture_phases=PHASES,
                build_firmware=False,program_target=False,
                resume=True,
            )
            assert captured==[(0,3),(0,4),(1,0),(1,1),(1,2),(1,3),(1,4)],captured
            assert state['conditions']['128f|Os|seed_000']['additional_signatures']==2
            assert state['conditions']['128f|Os|seed_001']['additional_signatures']==5
            assert hashlib.sha256(sample_file.read_bytes()).hexdigest()==previous_hash
            assert sample_file.stat().st_mtime_ns==previous_mtime
            backup_manifest = seed_dir / 'signature_sequence_capture_manifest.before_multiseed.json'
            assert hashlib.sha256(backup_manifest.read_bytes()).hexdigest()==original_manifest_hash
            backup_pool=param_root / 'shared_secret_seeds.before_multiseed.json'
            assert hashlib.sha256(backup_pool.read_bytes()).hexdigest()==pool_manifest_hash
            updated=json.loads(mf.read_text(encoding='utf8'))
            assert len(updated['completed'])==5
            assert (param_root/'Os'/'seed_001'/'signature_004'/'capture_traces_random.npy').exists()
            print('PASS: 2 existing-seed captures + 5 new-seed captures; old bytes and mtime unchanged')

            new_mf_mtime = mf.stat().st_mtime_ns
            state2=batch.run_all_parameter_random_message_signature_captures_multiseed(
                scope,None,live,
                firmware_dir=firmware,results_base_dir=result_dir,
                param_sets=['128f'],compiler_opts=['Os'],
                signatures_per_param_set={'128f':5},num_secret_seeds=2,
                capture_phases=PHASES,
                build_firmware=False,program_target=False,
            )
            assert len(captured)==7
            assert mf.stat().st_mtime_ns==new_mf_mtime
            assert state2['conditions']['128f|Os|seed_000']['status']=='completed-reused-disk'
            print('PASS: second run is idempotent (zero new captures, no manifest writes)')

            try:
                msg.inspect_random_message_signature_resume(
                    seed_dir,num_signatures=5,sk_prf=sk_prf,pk_seed=pk_seed,
                    pk_root=pk_root,sk_seed=sk_seed,secret_seed_id=0,
                    capture_phases=PHASES,message_seed=9999)
                raise AssertionError('mismatch should fail')
            except ValueError as exc:
                assert 'incompatible message_seed' in str(exc),str(exc)
            print('PASS: changed message_seed blocked before any overwrite')

            extra_dir=seed_dir/'signature_005'
            extra_dir.mkdir()
            (extra_dir/'capture_traces_random.npy').write_bytes(b'partial')
            try:
                msg.inspect_random_message_signature_resume(
                    seed_dir,num_signatures=6,sk_prf=sk_prf,pk_seed=pk_seed,
                    pk_root=pk_root,sk_seed=sk_seed,secret_seed_id=0,
                    capture_phases=PHASES)
                raise AssertionError('partial should fail')
            except FileExistsError:
                pass
            print('PASS: partial trace files blocked and preserved')

if __name__=='__main__':
    main()
