"""
OpenSearch connection — high-volume searchable security data (the
cowrie-logs / opencanary-logs / dionaea-logs / zeek-logs / suricata-alerts
indices that Filebeat writes to from System 2).

Used by app/workers/ingestion_worker.py to poll for new documents and by
app/api/routes/attacks.py for free-text search across raw events.
"""

from datetime import datetime, timezone

from opensearchpy import OpenSearch

from app.core.config import settings

_client = OpenSearch(
    hosts=[{"host": settings.OPENSEARCH_HOST, "port": settings.OPENSEARCH_PORT}],
    http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
    use_ssl=settings.OPENSEARCH_USE_SSL,
    verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
)


def get_client() -> OpenSearch:
    return _client


def poll_new_documents(index_pattern: str, since_iso: str, size: int = 500):
    """Returns documents in `index_pattern` (e.g. "cowrie-logs-*") with
    @timestamp after since_iso, oldest first. Used by the ingestion worker
    so it never re-processes the same event twice — see
    app/workers/ingestion_worker.py for how the checkpoint is advanced."""
    query = {
        "query": {"range": {"@timestamp": {"gt": since_iso}}},
        "sort": [{"@timestamp": "asc"}],
        "size": size,
    }
    response = _client.search(index=index_pattern, body=query)
    return [hit["_source"] for hit in response["hits"]["hits"]]


def index_document(index: str, document: dict):
    """Used for anything the backend itself wants searchable in OpenSearch
    (e.g. normalized events, for the dashboard's free-text search)."""
    document.setdefault("@timestamp", datetime.now(timezone.utc).isoformat())
    _client.index(index=index, body=document)


def search(index_pattern: str, query_string: str, size: int = 50):
    """Free-text search across raw honeypot/IDS documents — backs the
    dashboard's evidence search (Group 12: Evidence Search)."""
    query = {"query": {"query_string": {"query": query_string}}, "size": size}
    response = _client.search(index=index_pattern, body=query)
    return [hit["_source"] for hit in response["hits"]["hits"]]


