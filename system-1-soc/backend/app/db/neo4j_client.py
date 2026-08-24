"""
Neo4j connection — Group 8 (Attack Correlation & Campaign Analysis).

Handles the graph the master plan specifies:
    IP -[ATTACKED]-> Honeypot
    IP -[GENERATED]-> Session
    Session -[EXECUTED]-> Command
    Session -[TARGETED]-> Service
    IP -[ASSOCIATED_WITH]-> Campaign

Query-building logic lives in app/services/correlation.py — this module
is just the driver/connection wrapper.
"""

from app.core.config import settings

try:
    from neo4j import GraphDatabase
except ImportError:  # lets pure-logic modules that only need the query
    GraphDatabase = None  # builders (app.services.correlation) import this
    # file without requiring the driver to be installed — see get_driver().

_driver = None


def get_driver():
    """Lazy singleton: the driver is only created the first time something
    actually needs to run a query, not on import. Keeps this module
    importable (for correlation.py's pure query-builder functions) in
    environments where the `neo4j` package isn't installed yet."""
    global _driver
    if GraphDatabase is None:
        raise RuntimeError(
            "The 'neo4j' package is not installed — run `pip install neo4j` "
            "to use anything that executes Cypher queries. Query-builder "
            "functions in app.services.correlation don't need it."
        )
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
        )
    return _driver


def run_query(query: str, parameters: dict | None = None):
    """Runs a single Cypher query in its own session and returns the
    records as a list of dicts. Fine for the query volume this project
    generates; for high-throughput production use, switch to explicit
    session reuse per request instead of one session per call."""
    with get_driver().session() as session:
        result = session.run(query, parameters or {})
        return [record.data() for record in result]


def ensure_constraints():
    """Run once at startup — uniqueness constraints double as indexes,
    so repeated MERGEs on the same IP/session/command stay fast as the
    graph grows."""
    statements = [
        "CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
        "CREATE CONSTRAINT session_id IF NOT EXISTS FOR (s:Session) REQUIRE s.session_id IS UNIQUE",
        "CREATE CONSTRAINT honeypot_name IF NOT EXISTS FOR (h:Honeypot) REQUIRE h.name IS UNIQUE",
        "CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.campaign_id IS UNIQUE",
    ]
    with get_driver().session() as session:
        for stmt in statements:
            session.run(stmt)


def close_driver():
    if _driver is not None:
        _driver.close()


