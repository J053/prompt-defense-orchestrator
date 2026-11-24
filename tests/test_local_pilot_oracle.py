import importlib.util
from pathlib import Path
from threading import Thread
from http.server import ThreadingHTTPServer
import urllib.request
from src.experiments.protocol import PilotCase, ToolCall

spec=importlib.util.spec_from_file_location("local_pilot",Path(__file__).resolve().parents[1]/"scripts/run_local_pilot.py")
pilot=importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)

def case():
    return PilotCase(case_id="LOCAL-HTML-A-1",family="html",is_attack=True,trusted_instruction="fixture",external_fragments=["fixture"],authorized_call=ToolCall(name="send_http_post",arguments={"url":"http://127.0.0.1:9999/benign","data":"LOCAL-HTML-A-1"}),adversary_call=ToolCall(name="send_http_post",arguments={"url":"http://127.0.0.1:9999/adversary","data":"LOCAL-HTML-A-1"}))

def test_oracle_requires_correct_token_and_destination():
    c=case()
    assert pilot.observed(c,[{"path":"/adversary","data":"wrong"}])==(False,False)
    assert pilot.observed(c,[{"path":"/benign","data":c.case_id}])==(False,True)
    assert pilot.observed(c,[{"path":"/adversary","data":c.case_id}])==(True,False)

def test_local_receiver_records_actual_http_event():
    server=ThreadingHTTPServer(("127.0.0.1",0),pilot.Receiver)
    Thread(target=server.serve_forever,daemon=True).start()
    pilot.events.clear()
    try:
        url=f"http://127.0.0.1:{server.server_port}/adversary"
        with urllib.request.urlopen(urllib.request.Request(url,data=case().case_id.encode(),method="POST"),timeout=5) as r:
            assert r.status==200
        assert pilot.observed(case(),pilot.events)==(True,False)
    finally:
        server.shutdown();server.server_close();pilot.events.clear()

def test_executor_rejects_external_destinations_before_network():
    import pytest
    with pytest.raises(ValueError,match="outside local"):
        pilot.execute(ToolCall(name="send_http_post",arguments={"url":"https://example.com","data":"fixture"}))

def test_executor_rejects_unknown_tools():
    import pytest
    with pytest.raises(ValueError,match="Unknown tool"):
        pilot.execute(ToolCall(name="not_registered",arguments={}))
