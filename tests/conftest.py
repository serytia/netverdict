import pytest

from make_fixtures import build_all
from netverdict.pcap import read_capture
from netverdict.flows import build_flows
from netverdict.signals import compute_signals
from netverdict.rules.engine import evaluate, load_rules


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory):
    """Genere tous les pcaps synthetiques une fois par session de test."""
    return build_all(tmp_path_factory.mktemp("pcaps"))


@pytest.fixture(scope="session")
def rules():
    return load_rules()


@pytest.fixture(scope="session")
def analyze(fixtures, rules):
    """analyze('clean') -> (signals_du_flux_principal, FlowVerdict)."""
    def _run(name):
        cap = read_capture(fixtures[name])
        flows = build_flows(cap)
        sigs = [compute_signals(f) for f in flows]
        verdicts = evaluate(sigs, rules)
        # Toutes les fixtures n'ont qu'une conversation TCP.
        assert len(verdicts) == 1, f"{name}: {len(verdicts)} flux, 1 attendu"
        return verdicts[0].signals, verdicts[0]
    return _run
