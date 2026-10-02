"""Offline publication-selection regressions; never queries a real provider."""
from __future__ import annotations

import datetime as dt
import importlib
import itertools
import json
import types

import pytest

provider = importlib.import_module('podfreeze.enrich')


@pytest.fixture(autouse=True)
def no_network_and_fixed_time(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('This test must not perform network I/O')

    class FixedDatetime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            value = cls(2026, 10, 2, 12, 0, tzinfo=dt.timezone.utc)
            return value.astimezone(tz) if tz else value.replace(tzinfo=None)

    monkeypatch.setattr(provider.urllib.request, 'urlopen', forbidden)
    monkeypatch.setattr(provider, '_get', forbidden)
    monkeypatch.setattr(provider, '_network_up', forbidden)
    monkeypatch.setattr(provider, '_dt', types.SimpleNamespace(
        datetime=FixedDatetime, timezone=dt.timezone))


def entry(name='5.21.7', created_at='2026-02-03 11:00:00 UTC'):
    return {'name': name, 'created_at': created_at}


def fetch_document(monkeypatch, document):
    raw = json.dumps(document).encode()
    calls = []

    def fake_get(url):
        calls.append(url)
        return raw

    monkeypatch.setattr(provider, '_get', fake_get)
    result = provider.fetch_trunk('FixturePod')
    assert calls == ['https://trunk.cocoapods.org/api/v1/pods/FixturePod']
    return result


def assert_unknown(result, count=None):
    name, date, total, error = result
    assert name is None and date is None
    assert error, 'Incomplete evidence must not produce an apparently successful latest release'
    if count is not None:
        assert total == count


def test_publication_order_is_independent_of_array_and_lexical_version_order(monkeypatch):
    versions = [entry('5.9.5', '2020-11-13 10:00:00 UTC'),
                entry('5.21.7'), entry('5.18.0', '2024-03-01T00:00:00Z')]
    for order in itertools.permutations(versions):
        assert fetch_document(monkeypatch, {'versions': list(order)}) == (
            '5.21.7', '2026-02-03', 3, None)


@pytest.mark.parametrize('later_label', ['5.22.0', '5.22.0-beta.1'])
def test_newer_backport_or_prerelease_beats_higher_semantic_version(monkeypatch, later_label):
    versions = [entry('6.0.0', '2025-01-01T00:00:00Z'), entry(later_label)]
    for order in itertools.permutations(versions):
        assert fetch_document(monkeypatch, {'versions': list(order)}) == (
            later_label, '2026-02-03', 2, None)


@pytest.mark.parametrize('older,newer,date', [
    ('2026-02-03 01:00:00 UTC', '2026-02-03 23:00:00 UTC', '2026-02-03'),
    ('2026-02-03T00:30:00+02:00', '2026-02-02T23:30:00Z', '2026-02-02'),
    ('2026-02-03T21:00:00Z', '2026-02-03T23:30:00-02:00', '2026-02-04'),
    ('2026-02-03T01:00:00.000001Z', '2026-02-03T01:00:00.000002Z', '2026-02-03'),
])
def test_full_timestamp_and_utc_date_boundary(monkeypatch, older, newer, date):
    versions = [entry('newer', newer), entry('older', older)]
    for order in itertools.permutations(versions):
        assert fetch_document(monkeypatch, {'versions': list(order)}) == ('newer', date, 2, None)


@pytest.mark.parametrize('timestamp', [
    '2026-02-03 11:00:00 UTC', '2026-02-03T11:00:00Z',
    '2026-02-03T13:00:00+02:00', '2026-02-03T06:00:00-05:00',
])
def test_supported_timestamp_formats(monkeypatch, timestamp):
    assert fetch_document(monkeypatch, {'versions': [entry(created_at=timestamp)]}) == (
        '5.21.7', '2026-02-03', 1, None)


def test_identical_duplicate_publications_do_not_create_ambiguity(monkeypatch):
    same = entry()
    assert fetch_document(monkeypatch, {'versions': [same, dict(same)]}) == (
        '5.21.7', '2026-02-03', 2, None)


def test_equivalent_instants_for_same_version_are_not_ambiguous(monkeypatch):
    versions = [entry(), entry(created_at='2026-02-03T13:00:00+02:00')]
    assert fetch_document(monkeypatch, {'versions': versions}) == ('5.21.7', '2026-02-03', 2, None)


def test_distinct_versions_tied_at_latest_instant_are_unknown_for_every_order(monkeypatch):
    versions = [entry('first'), entry('second', '2026-02-03T13:00:00+02:00')]
    results = [fetch_document(monkeypatch, {'versions': list(order)})
               for order in itertools.permutations(versions)]
    assert results[0] == results[1]
    assert_unknown(results[0], 2)
    assert 'ambiguous' in results[0][3].lower()


def test_old_tie_does_not_hide_unique_latest_publication(monkeypatch):
    versions = [entry('old1', '2020-01-01T00:00:00Z'),
                entry('old2', '2020-01-01T00:00:00Z'), entry()]
    for order in itertools.permutations(versions):
        assert fetch_document(monkeypatch, {'versions': list(order)}) == ('5.21.7', '2026-02-03', 3, None)


@pytest.mark.parametrize('timestamp', [
    None, '', 'not-a-date', 123, True, {}, [],
    '2026-02-03', '2026-02-03T11:00:00', '2026-02-03 11:00:00',
    '2026-02-30T11:00:00Z', '2026-02-03T11:00:00+25:00',
    '2026-02-03T11:00:00+01:99', '2026-02-03T11:00:00+00:60',
    '2026-02-03T11:00:00+24:00', '2026-02-03X11:00:00Z',
    '2026-02-03\n11:00:00Z', '2026-02-03T11:00:00.1234567Z',
    '2026-10-02T12:00:01Z',
])
def test_any_invalid_or_future_timestamp_prevents_false_certainty(monkeypatch, timestamp):
    versions = [entry(), entry('other', timestamp)]
    for order in itertools.permutations(versions):
        assert_unknown(fetch_document(monkeypatch, {'versions': list(order)}), 2)


def test_missing_timestamp_cannot_be_skipped(monkeypatch):
    for order in itertools.permutations([entry(), {'name': 'undated'}]):
        assert_unknown(fetch_document(monkeypatch, {'versions': list(order)}), 2)


def test_all_undated_publications_are_unknown(monkeypatch):
    assert_unknown(fetch_document(monkeypatch, {'versions': [{'name': 'one'}, {'name': 'two'}]}), 2)


def test_publication_at_current_instant_is_not_future(monkeypatch):
    assert fetch_document(monkeypatch, {'versions': [entry(created_at='2026-10-02T12:00:00Z')]}) == (
        '5.21.7', '2026-10-02', 1, None)


@pytest.mark.parametrize('label', [None, '', '  ', 123, True, {}, []])
def test_invalid_version_name_is_unknown(monkeypatch, label):
    assert_unknown(fetch_document(monkeypatch, {'versions': [entry(name=label)]}), 1)


@pytest.mark.parametrize('record', [None, False, 1, 'string', [], {}])
def test_malformed_version_entries_do_not_crash(monkeypatch, record):
    assert_unknown(fetch_document(monkeypatch, {'versions': [entry(), record]}), 2)


@pytest.mark.parametrize('document', [None, [], 'string', 1, {}, {'versions': None},
                                      {'versions': {}}, {'versions': 'string'}, {'versions': 3}])
def test_invalid_response_shapes_are_explicit_errors(monkeypatch, document):
    assert_unknown(fetch_document(monkeypatch, document))


@pytest.mark.parametrize('raw', [b'{', b'not json', b'\xff'])
def test_malformed_json_or_encoding_is_explicit_error(monkeypatch, raw):
    monkeypatch.setattr(provider, '_get', lambda url: raw)
    assert_unknown(provider.fetch_trunk('FixturePod'))


def test_empty_version_list_retains_no_published_versions_semantics(monkeypatch):
    assert fetch_document(monkeypatch, {'versions': []}) == (
        None, None, None, 'no published versions')


@pytest.mark.parametrize('network_up,expected', [
    (False, 'NETWORK UNAVAILABLE — lookup could not run'),
    (True, 'not found on trunk (or the API rejected the name)'),
])
def test_transport_failure_remains_distinct_from_not_found(monkeypatch, network_up, expected):
    monkeypatch.setattr(provider, '_get', lambda url: None)
    monkeypatch.setattr(provider, '_network_up', lambda: network_up)
    assert provider.fetch_trunk('FixturePod') == (None, None, None, expected)


def test_unknown_publication_ranks_after_known_and_never_renders_fake_latest(monkeypatch):
    from podfreeze.analyse import analyse
    from podfreeze.parser import parse
    from podfreeze.pro import _priority, render_pro
    import podfreeze.pro as pro
    from tests.fixtures import MIXED

    unknown_result = fetch_document(monkeypatch, {'versions': [entry(created_at=None)]})
    unknown = provider.Enrichment(pod='SDWebImage', latest_version=unknown_result[0],
                                 latest_published=unknown_result[1], error=unknown_result[3])
    known = provider.Enrichment(pod='Alamofire', latest_version='fixture',
                               latest_published='2020-01-01')
    assert _priority(unknown)[0] > _priority(known)[0]
    assert _priority(unknown)[1] == 'could not determine'
    monkeypatch.setattr(pro, 'enrich', lambda names: [unknown, known])
    report = analyse(parse(MIXED))
    output = render_pro(report, licensed=True)
    assert output.index('    Alamofire') < output.index('    SDWebImage')
    unknown_section = output.split('    SDWebImage', 1)[1].split('ORDER OF WORK', 1)[0]
    assert unknown.error in unknown_section
    assert 'latest on trunk' not in unknown_section
    assert 'assessment' not in unknown_section
    assert len(report.exposed) == 2, 'Enrichment uncertainty must not remove source exposure'


def test_all_unknown_pro_does_not_invent_an_active_publication_order(monkeypatch):
    from podfreeze.analyse import analyse
    from podfreeze.parser import parse
    import podfreeze.pro as pro
    from tests.fixtures import MIXED

    error = 'latest publication unknown: incomplete or invalid metadata'
    monkeypatch.setattr(pro, 'enrich', lambda names: [
        provider.Enrichment(pod=name, error=error) for name in names])
    output = pro.render_pro(analyse(parse(MIXED)), licensed=True)
    ordering = output.split('ORDER OF WORK', 1)[1].split('NOTE ON VULNERABILITY DATA', 1)[0]
    assert 'could not be determined' in ordering
    assert 'still shipping' not in ordering
    assert 'still publishing' not in ordering
    assert 'are ordered with recent releases first' not in ordering
    assert 'not evidence of inactivity or low priority' in ordering
    assert 'latest on trunk' not in output


@pytest.mark.parametrize('unreliable_date', ['2020-01-01', '2026-09-30'])
def test_audit_does_not_rehabilitate_error_metadata_into_a_reliable_date(unreliable_date):
    from pathlib import Path
    from podfreeze.audit import Audit, ProjectResult, render_markdown

    error = 'latest publication unknown: invalid provider metadata'
    audit = Audit(
        projects=[ProjectResult(path=Path('synthetic/Podfile.lock'), name='synthetic',
                                examined=1, exposed=['FixturePod'])],
        enrichment={'FixturePod': provider.Enrichment(
            pod='FixturePod', latest_version='unreliable-version',
            latest_published=unreliable_date, error=error)})
    output = render_markdown(audit, Path('synthetic'))
    assert '| Projects with trunk exposure | 1 |' in output
    assert '| Distinct exposed pods | 1 |' in output
    assert 'could not be determined for any pod' in output
    assert '**Not ranked' in output
    assert '| — still publishing' not in output
    assert '| — static 1–3 years' not in output
    assert '| — no observed publication for 3+ years' not in output
    assert unreliable_date not in output
    assert 'unreliable-version' not in output
    assert '| `FixturePod` | ' + error + ' | unknown |' in output


def test_audit_error_date_cannot_outrank_known_observation():
    from pathlib import Path
    from podfreeze.audit import Audit, ProjectResult, render_markdown

    audit = Audit(
        projects=[ProjectResult(path=Path('synthetic/Podfile.lock'), name='synthetic',
                                examined=2, exposed=['UnknownPod', 'KnownPod'])],
        enrichment={
            'UnknownPod': provider.Enrichment(pod='UnknownPod', latest_version='bad',
                                              latest_published='2026-09-30', error='metadata unreliable'),
            'KnownPod': provider.Enrichment(pod='KnownPod', latest_version='1.0.0',
                                            latest_published='2020-01-01'),
        })
    output = render_markdown(audit, Path('synthetic'))
    assert output.index('| `KnownPod` |') < output.index('| `UnknownPod` |')
    assert '| — still publishing (lose a live channel) | **0** |' in output
    assert '| — no observed publication for 3+ years | 1 |' in output
    assert '2026-09-30' not in output
    assert 'Unknown publication observations do not establish inactivity or low priority.' in output
