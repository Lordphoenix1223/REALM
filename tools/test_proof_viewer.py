"""Real HTTP + real Rust checker controls. Set REALM_CHECKER to the built binary."""
import http.client, json, os, subprocess, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class ViewerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary=os.environ['REALM_CHECKER']
        cls.server=subprocess.Popen([sys.executable,'-B',str(ROOT/'tools/proof_viewer.py'),'--checker',binary],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        line=cls.server.stdout.readline(); cls.port=int(line.strip().rsplit(':',1)[1]); cls.host=f'127.0.0.1:{cls.port}'
        _,data,_=cls.request('GET','/session');cls.token=json.loads(data)['token']
    @classmethod
    def tearDownClass(cls):
        cls.server.terminate();cls.server.communicate(timeout=5)
    @classmethod
    def request(cls,method,path,body=None,headers=None):
        connection=http.client.HTTPConnection('127.0.0.1',cls.port,timeout=5)
        connection.request(method,path,body,headers or {}); response=connection.getresponse(); data=response.read();h=dict(response.getheaders());connection.close();return response.status,data,h
    def check(self,data,extra=None):return self.request('POST','/api/check',data,{'X-Realm-Token':self.token,**(extra or {})})
    def test_real_cases_and_proof_boundaries(self):
        for name,expected,code in [('valid','VALID',0),('tampered','INVALID',1),('incomplete','INCOMPLETE',3)]:
            _,data,_=self.request('GET',f'/samples/{name}.realm');status,result,_=self.check(data);value=json.loads(result)
            self.assertEqual(status,200);self.assertEqual(value['checker_exit'],code);self.assertEqual(value['report']['status'],expected)
            self.assertEqual(value['report']['checks']['execution_authorization'],'NOT_CHECKED')
    def test_host_and_origin_and_token_are_required(self):
        for headers in [{'Host':'evil.example'},{'Origin':'https://evil.example'},{'X-Realm-Token':'forged'}]:
            self.assertEqual(self.check(b'garbage',headers)[0],403)
        self.assertEqual(self.request('POST','/api/check',b'garbage')[0],403)
        self.assertEqual(self.request('GET','/session',headers={'Host':'evil.example'})[0],403)
    def test_no_arbitrary_paths_or_chunked_input(self):
        for path in ['/../Cargo.toml','/samples/../../Cargo.toml','/api/check?path=/etc/passwd']:
            self.assertEqual(self.request('GET',path)[0],404)
        self.assertEqual(self.check(b'',{'Transfer-Encoding':'chunked'})[0],400)
    def test_empty_and_oversize_uploads(self):
        self.assertEqual(self.check(b'')[0],413)
        self.assertEqual(self.check(b'x',{'Content-Length':str(64*1024*1024+1)})[0],413)
    def test_malformed_input_is_checker_rejection_not_server_success_claim(self):
        status,data,_=self.check(b'<script>alert(1)</script>');value=json.loads(data)
        self.assertEqual(status,200);self.assertEqual(value['report']['status'],'INVALID');self.assertEqual(value['checker_exit'],1)
    def test_browser_headers(self):
        status,data,headers=self.request('GET','/')
        self.assertEqual(status,200);self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
        self.assertEqual(headers['X-Content-Type-Options'],'nosniff');self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertNotIn(b'<script>',data)
if __name__=='__main__':unittest.main()
