"""Small synthetic host fixtures ONLY; no real release/crypto claim."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

HERE=Path(__file__).resolve().parent
def module(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    result=importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result
P=module('produce_archive_inventory'); A=module('audit_archive_inventory'); B=module('run_snapshot')
IMPLEMENTATION={'test_only':'synthetic_fixture_not_runtime_identity'}

def ref(data): return dict(sha256=hashlib.sha256(data).hexdigest(),size=len(data))
def json_bytes(value): return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()

def zip_fixture(entries=None,method=zipfile.ZIP_DEFLATED,force64=False,stream=False):
    class Unseekable(io.BytesIO):
        def seek(self,*args): raise io.UnsupportedOperation('nonseekable synthetic fixture')
    target=Unseekable() if stream else io.BytesIO()
    with warnings.catch_warnings(),zipfile.ZipFile(target,'w',compression=method) as z:
        warnings.simplefilter('ignore',UserWarning)
        for name,content,mode in entries or [('SYSTEM/a',b'hello fixture',stat.S_IFREG|0o644)]:
            info=zipfile.ZipInfo(name); info.create_system=3; info.external_attr=mode<<16
            info.compress_type=method
            if force64:
                with z.open(info,'w',force_zip64=True) as f: f.write(content)
            else: z.writestr(info,content)
    return target.getvalue()

def wide_end(data):
    end=data.rfind(b'PK\x05\x06'); r=list(struct.unpack('<4s4H2IH',data[end:end+22]))
    wide=struct.pack('<4sQ2H2I4Q',b'PK\x06\x06',44,45,45,0,0,r[3],r[4],r[5],r[6])
    locator=struct.pack('<4sIQI',b'PK\x06\x07',0,end,1)
    r[3]=r[4]=65535; r[5]=r[6]=0xffffffff
    return data[:end]+wide+locator+struct.pack('<4s4H2IH',*r)+data[end+22:]

def change(data,offset,fmt,value):
    result=bytearray(data); struct.pack_into(fmt,result,offset,value); return bytes(result)

class Fixtures(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.releases=self.root/'releases'; self.releases.mkdir()
        self.full={}; self.archives={}
        for role,number,timestamp in [('predecessor','2026101101',1800000000),('successor','2026101102',1800000001)]:
            directory=self.releases/number/('release-frankel-'+number); directory.mkdir(parents=True)
            archive=zip_fixture([('SYSTEM/a',role.encode(),stat.S_IFREG|0o644)])
            path=directory/'frankel-target_files.zip'; path.write_bytes(archive); self.archives[role]=path
            full=dict(schema=4,kind='wonad-grapheneos-release',build=dict(number=number,timestamp=timestamp,
                      post_build='synthetic-only/'+number,datetime_utc='synthetic fixture'),target=P.TARGET,
                      source={'fixture':'synthetic'},grapheneos_lock={'fixture':'synthetic'},wonad_stage={'fixture':'synthetic'},
                      updater_stage={'update_url':'https://synthetic.invalid/update/'},apk_signer_sha256='a'*64,
                      artifacts={'signed_target_files':'frankel-target_files.zip'},phase1_provenance={'fixture':'synthetic'},
                      files={'frankel-target_files.zip':ref(archive)},generator={'fixture':'synthetic'},artifact_verifier={'fixture':'synthetic'})
            self.full[role]=full
        self.pair_path=self.releases/'2026101102'/'frankel-incremental-2026101101-2026101102-receipt.json'
        self.refresh()

    def refresh(self):
        pair=dict(schema=1,kind='wonad-grapheneos-incremental-pair',target='frankel',
                  incremental_ota={'fixture':'not checked by inventory selector'},official_delta_generator={'fixture':'synthetic'},
                  receipt_generator={'fixture':'synthetic'},pair_verifier={'fixture':'synthetic'})
        for role in self.full:
            full=self.full[role]; directory=self.archives[role].parent; data=json_bytes(full)
            (directory/'release-receipt.json').write_bytes(data)
            endpoint={k:full[k] for k in P.END_KEYS-{'number','receipt'}}
            number=full['build']['number']; endpoint['number']=number
            endpoint['receipt']=dict(path=f'{number}/release-frankel-{number}/release-receipt.json',**ref(data))
            pair[role]=endpoint
        self.pair=pair; self.write_pair()

    def write_pair(self):
        self.pair_path.write_bytes(json_bytes(self.pair)); self.pair_sha=ref(self.pair_path.read_bytes())['sha256']

    def archive_check(self,data,policy=None):
        p=self.root/'sample.zip'; p.write_bytes(data)
        options=P.POLICY if policy is None else policy
        actual=P.observe_archive(p,ref(data),'predecessor',options)
        independent=A.rederive_archive(p,ref(data),'predecessor',options)
        self.assertEqual(actual[:3],independent)
        return actual

    def rejected(self,data,policy=None):
        p=self.root/'bad.zip'; p.write_bytes(data); options=P.POLICY if policy is None else policy
        with self.assertRaises((P.InventoryError,OSError)): P.observe_archive(p,ref(data),'predecessor',options)
        with self.assertRaises((A.AuditError,OSError)): A.rederive_archive(p,ref(data),'predecessor',options)

    def produce(self):
        output=self.root/'observed'
        result=P.produce(self.pair_path,self.pair_sha,output,dict(IMPLEMENTATION,structural_policy=P.POLICY))
        return output,result

    def audit(self,output):
        receipt=output/'receipt.json'
        return A.audit(receipt,ref(receipt.read_bytes())['sha256'],self.pair_path,self.pair_sha,IMPLEMENTATION)

    def test_store_deflate_empty_unicode_directories_symlinks(self):
        entries=[('SYSTEM/',b'',stat.S_IFDIR|0o755),('SYSTEM/a',b'',stat.S_IFREG|0o644),
                 ('SYSTEM/\u03b1',b'payload',stat.S_IFREG|0o644),('SYSTEM/link',b'../../outside',stat.S_IFLNK|0o777),
                 ('SYSTEM/absolute',b'/absolute',stat.S_IFLNK|0o777),('SYSTEM/cycle',b'cycle',stat.S_IFLNK|0o777)]
        before=set(self.root.iterdir())
        for method in (0,8):
            with self.subTest(method=method):
                rows,raw,summary,_=self.archive_check(zip_fixture(entries,method))
                self.assertEqual(summary['symlink_count'],3); self.assertEqual(summary['directory_count'],1)
                self.assertEqual(next(r for r in rows if r['member']=='SYSTEM/link')['sha256'],ref(b'../../outside')['sha256'])
        self.assertEqual(set(self.root.iterdir())-before,{self.root/'sample.zip'})

    def test_local_zip64_end_zip64_and_data_descriptors(self):
        for force in (False,True):
            for stream in (False,True):
                for end64 in (False,True):
                    with self.subTest(force=force,stream=stream,end64=end64):
                        data=zip_fixture(force64=force,stream=stream)
                        rows,_,summary,_=self.archive_check(wide_end(data) if end64 else data)
                        self.assertEqual(summary['zip64'],end64); self.assertEqual(rows[0]['expanded_size'],13)

    def test_pair_producer_and_independent_auditor(self):
        output,result=self.produce(); answer=self.audit(output)
        self.assertEqual(answer['status'],'observed'); self.assertIs(answer['release_gate_closed'],False)
        self.assertEqual(result['pair']['sha256'],self.pair_sha)
        with self.assertRaises(P.InventoryError): P.produce(self.pair_path,self.pair_sha,output,IMPLEMENTATION)

    def test_pair_receipt_authentication_precedes_parsing(self):
        self.pair_path.write_bytes(b'not JSON')
        with patch.object(P,'decode',side_effect=AssertionError('must not parse')):
            with self.assertRaises(P.InventoryError): P.select_pair(self.pair_path,self.pair_sha)
        with patch.object(A,'parse_json',side_effect=AssertionError('must not parse')):
            with self.assertRaises(A.AuditError): A.independently_select(self.pair_path,self.pair_sha)

    def test_endpoint_and_pair_relabels_rejected(self):
        original=copy.deepcopy(self.pair)
        mutations=[lambda p:p.update(schema=True),lambda p:p.update(schema=1.0),
                   lambda p:p['predecessor']['build'].update(timestamp=1800000000.0),
                   lambda p:p['successor']['source'].update(fixture='foreign'),
                   lambda p:p['predecessor']['receipt'].update(path='../outside'),
                   lambda p:p['successor'].update(number='2026101101')]
        for change_pair in mutations:
            self.pair=copy.deepcopy(original); change_pair(self.pair); self.write_pair()
            with self.subTest(pair=self.pair):
                with self.assertRaises(P.InventoryError): P.select_pair(self.pair_path,self.pair_sha)
                with self.assertRaises(A.AuditError): A.independently_select(self.pair_path,self.pair_sha)

    def test_full_receipt_hostile_dates_and_artifact_role(self):
        original=copy.deepcopy(self.full)
        mutations=[lambda f:f['successor']['build'].update(timestamp=True),lambda f:f['successor']['build'].update(timestamp=1800000001.0),
                   lambda f:f['successor']['build'].update(timestamp=1800000000),lambda f:f['successor']['build'].update(timestamp=1799999999),
                   lambda f:f['successor']['artifacts'].update(signed_target_files='../different.zip'),
                   lambda f:f['successor']['updater_stage'].update(update_url='https://foreign.invalid/'),
                   lambda f:f['successor'].update(apk_signer_sha256='b'*64)]
        for mutate in mutations:
            self.full=copy.deepcopy(original); mutate(self.full); self.refresh()
            with self.subTest(full=self.full):
                with self.assertRaises(P.InventoryError): P.select_pair(self.pair_path,self.pair_sha)
                with self.assertRaises(A.AuditError): A.independently_select(self.pair_path,self.pair_sha)

    def test_json_duplicate_and_nonfinite(self):
        for raw in (b'{"schema":1,"schema":1}',b'{"schema":NaN}',b'{"schema":Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaises(P.InventoryError): P.decode(raw)
                with self.assertRaises(A.AuditError): A.parse_json(raw)

    def test_file_and_parent_symlinks_fifo_rejected_without_blocking(self):
        p=self.root/'filelink'; p.symlink_to(self.pair_path)
        d=self.root/'dirlink'; d.symlink_to(self.pair_path.parent,target_is_directory=True)
        fifo=self.root/'fifo'; os.mkfifo(fifo)
        for path in (p,d/self.pair_path.name,fifo):
            with self.subTest(path=path):
                with self.assertRaises((P.InventoryError,OSError)): P.ordinary_fd(path)
                with self.assertRaises((A.AuditError,OSError)): A.open_input(path)

    def test_canonical_member_names_and_duplicate_prefix_types(self):
        for name in ('../a','/a','a//b','a/./b','a/../b','a\\b','a\x01b','a\x85b','a//'):
            with self.subTest(name=name): self.rejected(zip_fixture([(name,b'x',stat.S_IFREG|0o644)]))
        for entries in ([('a',b'a',stat.S_IFREG),('a',b'b',stat.S_IFREG)],
                        [('a/',b'',stat.S_IFDIR),('a',b'b',stat.S_IFREG)],
                        [('a',b'b',stat.S_IFREG),('a/b',b'c',stat.S_IFREG)],
                        [('a',b'../b',stat.S_IFLNK),('a/b',b'c',stat.S_IFREG)]):
            with self.subTest(entries=entries): self.rejected(zip_fixture(entries))

    def test_special_and_contradictory_types_rejected(self):
        for mode in (stat.S_IFIFO,stat.S_IFSOCK,stat.S_IFCHR,stat.S_IFBLK,stat.S_IFDIR):
            with self.subTest(mode=mode): self.rejected(zip_fixture([('a',b'x',mode)]))
        self.rejected(zip_fixture([('a/',b'x',stat.S_IFDIR)]))
        self.rejected(zip_fixture([('a/',b'',stat.S_IFLNK)]))

    def test_preallocation_count_directory_name_limits(self):
        data=zip_fixture([('a',b'a',stat.S_IFREG),('b',b'b',stat.S_IFREG)])
        for key,value in (('entries',1),('central_bytes',46),('name_bytes',0)):
            p=self.root/'preflight.zip'; p.write_bytes(data); policy=dict(P.POLICY,**{key:value})
            with self.subTest(key=key),patch.object(zipfile,'ZipFile',side_effect=AssertionError('allocation forbidden')):
                with self.assertRaises(P.InventoryError): P.observe_archive(p,ref(data),'predecessor',policy)
                with self.assertRaises(A.AuditError): A.rederive_archive(p,ref(data),'predecessor',policy)
        end=data.rfind(b'PK\x05\x06'); data=change(change(data,end+8,'H',1),end+10,'H',1)
        self.rejected(data)

    def test_eocd_zip64_ranges_multidisk_and_appended_junk(self):
        data=zip_fixture(); end=data.rfind(b'PK\x05\x06')
        for bad in (data+b'junk',data[:-1],change(data,end+4,'H',1),change(data,end+16,'I',0xffffffff),
                    change(data,end+12,'I',0xffffffff),wide_end(data)[:-1]):
            with self.subTest(bad=bad[-30:]): self.rejected(bad)
        wide=wide_end(data); loc=wide.rfind(b'PK\x06\x07')
        self.rejected(change(wide,loc+16,'I',2))
        self.rejected(change(wide,loc+8,'Q',len(wide)+1))

    def test_unsupported_compression_encryption_local_fields_crc_and_truncation(self):
        data=zip_fixture(); cd=data.index(b'PK\x01\x02')
        bads=[change(data,cd+8,'H',1),change(data,cd+10,'H',12),change(data,8,'H',0),
              change(data,cd+16,'I',0),change(data,cd+16,'I',0xffffffff),change(data,14,'I',0),
              data[:30]+b'X'+data[31:]]
        for bad in bads:
            with self.subTest(bad=bad[:35]): self.rejected(bad)

    def test_underdeclared_deflate_size_is_not_hidden_by_zipfile(self):
        data=zip_fixture([('a',b'X'*4096,stat.S_IFREG)])
        cd=data.index(b'PK\x01\x02')
        for offset in (14,22,cd+16,cd+24): data=change(data,offset,'I',0)
        self.rejected(data)

    def test_true_stream_limits_empty_crc_and_small_chunks(self):
        data=zip_fixture([('a',b'x'*65536,stat.S_IFREG)])
        self.archive_check(data,dict(P.POLICY,chunk_bytes=31))
        for key,val in (('member_bytes',10),('total_bytes',10)):
            with self.subTest(key=key): self.rejected(data,dict(P.POLICY,**{key:val}))
        self.rejected(zip_fixture([('a',b'../outside',stat.S_IFLNK)]),dict(P.POLICY,symlink_bytes=2))
        self.archive_check(zip_fixture([('a',b'',stat.S_IFREG)]))

    def test_payload_aliases_and_physical_overlap(self):
        self.archive_check(zip_fixture([('a',b'same',stat.S_IFREG),('b',b'same',stat.S_IFREG)]))
        data=zip_fixture([('a',b'one',stat.S_IFREG),('a',b'one',stat.S_IFREG)])
        cds=[i for i in range(len(data)) if data[i:i+4]==b'PK\x01\x02']
        self.rejected(change(data,cds[1]+42,'I',0))

    def test_failure_preserves_owned_evidence_and_never_success(self):
        self.archives['successor'].write_bytes(b'changed archive')
        output=self.root/'failed'
        with self.assertRaises(P.InventoryError): P.produce(self.pair_path,self.pair_sha,output,IMPLEMENTATION)
        self.assertTrue((output/'failure.json').is_file()); self.assertFalse((output/'receipt.json').exists())
        self.assertTrue((output/'predecessor-members.jsonl').is_file()); self.assertTrue((output/'pair.json').is_file())

    def test_auditor_rejects_false_claims_counts_bool_integer_and_ledger_edits(self):
        output,result=self.produce(); receipt=output/'receipt.json'; original=copy.deepcopy(result)
        mutators=[lambda r:r.update(release_gate_closed=True),lambda r:r['endpoints']['predecessor']['zip_structure'].update(entry_count=True),
                  lambda r:r['endpoints']['predecessor']['build'].update(timestamp=1800000000.0),
                  lambda r:r['pair'].update(origin='/foreign'),lambda r:r['implementation'].update(test_only='foreign')]
        for mutate in mutators:
            r=copy.deepcopy(original); mutate(r); receipt.write_bytes(json_bytes(r))
            with self.subTest(r=r):
                with self.assertRaises(A.AuditError): self.audit(output)
        receipt.write_bytes(json_bytes(original))
        members=output/'predecessor-members.jsonl'; member_rows=[json.loads(x) for x in members.read_text().splitlines()]
        member_rows[0]['expanded_size']=True; members.write_bytes(b''.join(P.encoded(r) for r in member_rows))
        original['endpoints']['predecessor']['zip_structure']['member_inventory'].update(ref(members.read_bytes()))
        receipt.write_bytes(json_bytes(original))
        with self.assertRaises(A.AuditError): self.audit(output)

    def test_auditor_never_calls_producer_and_does_not_extract(self):
        output,_=self.produce()
        with patch.object(P,'observe_archive',side_effect=AssertionError('producer cannot prove itself')),\
             patch.object(P,'select_pair',side_effect=AssertionError('producer selector cannot prove itself')),\
             patch.object(zipfile.ZipFile,'extract',side_effect=AssertionError('no extraction')),\
             patch.object(zipfile.ZipFile,'extractall',side_effect=AssertionError('no extraction')):
            self.assertEqual(self.audit(output)['status'],'observed')

    def test_authenticated_snapshot_executes_captured_bytes_after_path_swap(self):
        source=self.root/'source.py'; source.write_bytes(b'def main(args): return 17\n')
        raw,identity=B.capture(source,1000)
        original_compile=compile
        def swap(*args,**kwargs):
            source.write_bytes(b'def main(args): return 99\n'); return original_compile(*args,**kwargs)
        with patch('builtins.compile',side_effect=swap):
            self.assertEqual(B.execute_snapshot(raw,source,{},[]),17)
        self.assertEqual(identity,dict(path=str(source),**ref(raw)))

    def test_nul_raw_name_and_bad_extra_tlv(self):
        data=zip_fixture([('abc',b'payload',stat.S_IFREG)])
        cd=data.index(b'PK\x01\x02'); bad=bytearray(data); bad[31]=0; bad[cd+47]=0
        self.rejected(bytes(bad))
        for extra in (b'\x01',b'\x02\x00\x02\x00x',b'\x02\x00\x00\x00\x02\x00\x00\x00'):
            with self.subTest(extra=extra):
                with self.assertRaises(P.InventoryError): P.extras(extra)
                with self.assertRaises(A.AuditError): A.unzip64(extra,[])

    def test_compressed_trailing_bytes_and_incomplete_stream_rejected(self):
        original=zip_fixture([('a',b'hello',stat.S_IFREG)])
        cd=original.index(b'PK\x01\x02'); local_name_size=struct.unpack_from('<H',original,26)[0]
        start=30+local_name_size; compressed=struct.unpack_from('<I',original,18)[0]
        # Insert bytes inside declared compressed payload, shift all CD offsets.
        end=original.rfind(b'PK\x05\x06')
        data=original[:cd]+b'junk'+original[cd:]
        data=change(data,18,'I',compressed+4); data=change(data,cd+4+20,'I',compressed+4)
        data=change(data,end+4+16,'I',cd+4)
        self.rejected(data)
        p=self.root/'stream.zip'; p.write_bytes(original)
        fd=P.ordinary_fd(p)
        try:
            row=dict(method=8,csize=compressed-1,usize=5)
            with self.assertRaises(P.InventoryError): list(P.payload_chunks(fd,start,row,2))
            with self.assertRaises(A.AuditError): list(A.independently_decompress(fd,start,compressed-1,8,5,2))
        finally: os.close(fd)

    def test_archive_hash_drift_and_inplace_mutation_rejected(self):
        data=zip_fixture(); path=self.root/'drift.zip'; path.write_bytes(data)
        with self.assertRaises(P.InventoryError): P.observe_archive(path,dict(ref(data),sha256='0'*64),'predecessor')
        with self.assertRaises(A.AuditError): A.rederive_archive(path,dict(ref(data),sha256='0'*64),'predecessor')
        initial=P.payload_chunks
        def mutate(fd,start,row,chunk):
            path.write_bytes(data+b'changed-after-read')
            yield from initial(fd,start,row,chunk)
        with patch.object(P,'payload_chunks',side_effect=mutate):
            with self.assertRaises(P.InventoryError): P.observe_archive(path,ref(data),'predecessor')

    def test_pathname_replacement_of_open_archive_rejected(self):
        data=zip_fixture(); path=self.root/'exchange.zip'; path.write_bytes(data)
        initial=P.payload_chunks
        def replace(fd,start,row,chunk):
            alternate=self.root/'alternate.zip'; alternate.write_bytes(data); os.replace(alternate,path)
            yield from initial(fd,start,row,chunk)
        with patch.object(P,'payload_chunks',side_effect=replace):
            with self.assertRaises(P.InventoryError): P.observe_archive(path,ref(data),'predecessor')
        initial_a=A.independently_decompress
        def replace_a(fd,start,compressed,method,expanded,chunk):
            alternate=self.root/'alternate-a.zip'; alternate.write_bytes(data); os.replace(alternate,path)
            yield from initial_a(fd,start,compressed,method,expanded,chunk)
        with patch.object(A,'independently_decompress',side_effect=replace_a):
            with self.assertRaises(A.AuditError): A.rederive_archive(path,ref(data),'predecessor')

    def test_first_archive_changes_before_final_publication(self):
        original=P.observe_archive
        def observe(path,*args,**kwargs):
            answer=original(path,*args,**kwargs)
            if path==self.archives['successor']: self.archives['predecessor'].write_bytes(b'changed after first scan')
            return answer
        output=self.root/'late-drift'
        with patch.object(P,'observe_archive',side_effect=observe):
            with self.assertRaises(P.InventoryError): P.produce(self.pair_path,self.pair_sha,output,IMPLEMENTATION)
        self.assertFalse((output/'receipt.json').exists()); self.assertTrue((output/'failure.json').is_file())

    def test_atomic_exclusive_evidence_bound_and_existing_output(self):
        directory=self.root/'atomic'; directory.mkdir()
        with self.assertRaises(P.InventoryError): P.write_sequence(directory,'oversize.jsonl',[b'a'*8,b'b'*8],10)
        self.assertEqual(list(directory.iterdir()),[])
        original=os.link
        def checked_link(source,target,**kwargs):
            self.assertFalse(Path(target).exists()); self.assertEqual(Path(source).read_bytes(),b'complete')
            return original(source,target,**kwargs)
        with patch.object(os,'link',side_effect=checked_link): P.write_new(directory,'complete.json',b'complete',100)
        with self.assertRaises(P.InventoryError): P.write_new(directory,'complete.json',b'overwrite',100)
        self.assertEqual((directory/'complete.json').read_bytes(),b'complete')

    def test_auditor_rejects_raw_listing_substitution_and_extra_rows(self):
        output,result=self.produce(); receipt=output/'receipt.json'; listing=output/'predecessor-raw.jsonl'
        rows=[json.loads(x) for x in listing.read_text().splitlines()]
        rows.append(copy.deepcopy(rows[0])); listing.write_bytes(b''.join(P.encoded(r) for r in rows))
        result['endpoints']['predecessor']['zip_structure']['raw_listing'].update(ref(listing.read_bytes()))
        receipt.write_bytes(json_bytes(result))
        with self.assertRaises(A.AuditError): self.audit(output)

    def test_auditor_rejects_receipt_snapshot_substitution(self):
        output,result=self.produce(); snapshot=output/'predecessor-release.json'
        raw=json.loads(snapshot.read_bytes()); raw['source']={'foreign':'identity'}; snapshot.write_bytes(json_bytes(raw))
        result['endpoints']['predecessor']['release_receipt']['snapshot'].update(ref(snapshot.read_bytes()))
        (output/'receipt.json').write_bytes(json_bytes(result))
        with self.assertRaises(A.AuditError): self.audit(output)

    def test_snapshot_source_drift_refused_before_compile(self):
        producer=ref((HERE/'produce_archive_inventory.py').read_bytes())['sha256']
        auditor=ref((HERE/'audit_archive_inventory.py').read_bytes())['sha256']
        with patch('builtins.compile',side_effect=AssertionError('bad source must not compile')):
            with self.assertRaises(ValueError): B.authenticated_sources(HERE,'0'*64,auditor)
            with self.assertRaises(ValueError): B.authenticated_sources(HERE,producer,'0'*64)

    def test_declared_zero_crc_cannot_disable_actual_crc_comparison(self):
        data=zip_fixture(); cd=data.index(b'PK\x01\x02')
        for declared in (0,0xffffffff):
            with self.subTest(declared=declared):
                self.rejected(change(change(data,14,'I',declared),cd+16,'I',declared))

    def test_actual_bootstrap_cli_on_synthetic_pair_only(self):
        producer=ref((HERE/'produce_archive_inventory.py').read_bytes())['sha256']
        auditor=ref((HERE/'audit_archive_inventory.py').read_bytes())['sha256']
        command=[sys.executable,'-B',str(HERE/'run_snapshot.py'),'produce',
                 '--expected-producer-sha256',producer,'--expected-auditor-sha256',auditor,'--',
                 '--pair-receipt',str(self.pair_path),'--expected-pair-receipt-sha256',self.pair_sha,
                 '--output',str(self.root/'cli-output')]
        outcome=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=20)
        self.assertEqual(outcome.returncode,0,outcome.stderr)
        receipt=self.root/'cli-output/receipt.json'; command[3]='audit'
        command=command[:command.index('--')+1]+['--inventory-receipt',str(receipt),
                '--expected-inventory-receipt-sha256',ref(receipt.read_bytes())['sha256'],
                '--pair-receipt',str(self.pair_path),'--expected-pair-receipt-sha256',self.pair_sha]
        outcome=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=20)
        self.assertEqual(outcome.returncode,0,outcome.stderr); self.assertFalse(json.loads(outcome.stdout)['release_gate_closed'])

if __name__=='__main__': unittest.main(verbosity=2)
