import asyncio
import json
from pathlib import Path
import pytest
from pydantic import ValidationError
from src.experiments.protocol import AttemptRecord, PilotCase, ProviderDecision, make_schedule, summarize
from src.defense.provenance import ParamPolicyValidator, ParamPolicyBlockedException, TaintTracker
from src.models.forensic import WideMetricRow
from src.providers.gemini import GeminiProvider

ROOT = Path(__file__).resolve().parents[1]

def decision():
    return ProviderDecision(model="unit-test", model_version="fixture-v1", raw_response="fixture",
                            calls=[], model_time_s=0.01)

def record(attack=True, effect=False, status="SUCCESS", **extra):
    values = dict(attempt_id="test-1", case_id="test", condition="ON", execution_mode="unit_test",
                  status=status, is_attack=attack, decision=decision(), oracle_evidence="fixture-only",
                  total_time_s=0.02)
    values["observed_adversary_effect" if attack else "observed_benign_success"] = effect
    values.update(extra)
    return AttemptRecord(**values)

def test_error_is_excluded_from_attack_denominator():
    ok = record()
    failed = record(effect=True, status="FAILURE", attempt_id="test-2")
    error = AttemptRecord(attempt_id="test-3", case_id="test", condition="ON", execution_mode="unit_test",
                          status="ERROR", is_attack=True, error="fixture timeout")
    result = summarize([ok, failed, error], execution_mode="unit_test")
    assert result["asr"] == 0.5
    assert result["attack_denominator"] == 2
    assert result["statuses"]["ERROR"] == 1
    assert result["utility"] is None

@pytest.mark.parametrize("status", ["ERROR", "NOT_EXECUTED"])
def test_invalid_attempt_cannot_report_zero_attack_success(status):
    with pytest.raises(ValidationError, match="scored outcomes"):
        AttemptRecord(attempt_id="x", case_id="x", condition="OFF", execution_mode="unit_test",
                      status=status, is_attack=True, error="unavailable", observed_adversary_effect=False)

def test_intent_without_oracle_is_not_an_observed_result():
    with pytest.raises(ValidationError, match="independent oracle"):
        record(oracle_evidence=None)

def test_attack_and_benign_have_separate_populations():
    attack = record()
    benign = record(attack=False, effect=True, attempt_id="test-2")
    result = summarize([attack, benign], execution_mode="unit_test")
    assert result["attack_denominator"] == result["benign_denominator"] == 1
    assert result["eds"] == 1.0
    with pytest.raises(ValidationError, match="denominator"):
        record(observed_benign_success=True)

@pytest.mark.parametrize("change", [{"status":"FAILURE"}, {"blocked":True, "observed_adversary_effect":True, "status":"FAILURE"}])
def test_contradictory_outcome_is_rejected(change):
    with pytest.raises(ValidationError):
        record(**change)

def test_real_and_unit_test_results_cannot_be_mixed():
    with pytest.raises(ValueError, match="combine"):
        summarize([record(), record(attempt_id="test-2", execution_mode="real")], execution_mode="real")

def test_conditions_and_duplicate_attempts_cannot_be_pooled():
    with pytest.raises(ValueError, match="condition"):
        summarize([record(), record(attempt_id="test-2", condition="OFF")], execution_mode="unit_test")
    with pytest.raises(ValueError, match="Duplicate"):
        summarize([record(),record()], execution_mode="unit_test")

@pytest.mark.parametrize("field,value", [("model_time_s",-1),("model_time_s",float("nan")),("input_tokens",-1)])
def test_provider_decision_ranges(field,value):
    data=decision().model_dump();data[field]=value
    with pytest.raises(ValidationError):ProviderDecision(**data)

def test_cost_needs_documented_price():
    with pytest.raises(ValidationError,match="price reference"):record(cost_usd=0.01)

@pytest.mark.parametrize("active", [True, False])
def test_unregistered_tool_is_not_implicitly_authorized(active):
    with pytest.raises(ParamPolicyBlockedException,match="no registrada"):
        ParamPolicyValidator.validate_tool_call("not_registered",{},active)

def test_file_write_alias_does_not_bypass_taint_check():
    with pytest.raises(ParamPolicyBlockedException):
        ParamPolicyValidator.validate_tool_call("file_write",{"path":TaintTracker.sanitize_and_tag("example.txt")},True)

@pytest.mark.parametrize("field,value", [("ASR_Defensa",7),("Time_s_Defensa",-1),("EDS_Defensa",2),("Utilidad_Defensa",float("nan"))])
def test_wide_metrics_reject_invalid_ranges(field,value):
    import csv
    with (ROOT/"data/metrics_anexo3_wide.csv").open(encoding="utf-8-sig") as f:row=next(csv.DictReader(f))
    row[field]=value
    with pytest.raises(ValidationError):WideMetricRow(**row)

def test_legacy_gemini_does_not_spend_api_to_invent_metrics():
    provider=object.__new__(GeminiProvider)
    async def forbidden(*args,**kwargs):raise AssertionError("API must not be called")
    provider.ejecutar_prompt=forbidden
    with pytest.raises(NotImplementedError,match="evaluador independiente"):
        asyncio.run(provider.auditar_objetivo("LOCAL",{},True))

def test_gemini_missing_client_does_not_silently_simulate():
    provider=object.__new__(GeminiProvider);provider.client=None
    with pytest.raises(RuntimeError,match="simulación"):
        asyncio.run(provider.ejecutar_prompt("fixture"))

def test_manifest_and_counterbalanced_schedule():
    cases=[PilotCase(**v) for v in json.loads((ROOT/"experiments/pilot-v1/cases.json").read_text(encoding="utf-8"))]
    assert len(cases)==24
    assert sum(c.is_attack for c in cases)==12
    assert sum(not c.is_attack and c.authorized_call.name=="send_http_post" for c in cases)>=4
    schedule=make_schedule(cases)
    assert len(schedule)==144
    assert sum(s.condition=="ON" and s.order==1 for s in schedule)==36
    assert sum(s.condition=="OFF" and s.order==1 for s in schedule)==36
    assert json.loads((ROOT/"experiments/pilot-v1/schedule.json").read_text(encoding="utf-8"))==[v.model_dump() for v in schedule]
    with pytest.raises(ValueError,match="Duplicate"):make_schedule([cases[0],cases[0]])


def test_incompatible_provider_is_rejected_before_docker_or_csv(monkeypatch, tmp_path):
    from src.orchestrator.engine import ExperimentOrchestrator
    def forbidden():
        raise AssertionError("Docker must not be touched")
    monkeypatch.setattr("src.orchestrator.engine.DockerManager", forbidden)
    path = tmp_path / "metrics.csv"
    with pytest.raises(ValueError, match="No se modificó infraestructura"):
        ExperimentOrchestrator(object.__new__(GeminiProvider), str(path))
    assert not path.exists()
