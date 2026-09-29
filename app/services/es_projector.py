"""Projects canonical indicator records into the Elasticsearch document
shape. When ES_URL is configured, the projector bulk-indexes new/changed
indicators into the ES index. When ES_URL is not set, the projector is a
no-op (the canonical store is queried directly by the search API)."""

from app.services.es_search import indicator_es_doc, ES_INDEX_NAME


def project_indicator(indicator) -> dict:
    """Convert an Indicator ORM model into the ES document shape."""
    return indicator_es_doc(indicator)


def bulk_project(indicators) -> list[dict]:
    """Convert a list of indicators into ES documents for bulk indexing."""
    return [indicator_es_doc(i) for i in indicators]


def bulk_index_body(indicators) -> list[dict]:
    """Produce the NDLC body for a Bulk API request (index action + source doc)."""
    body = []
    for ind in indicators:
        doc = indicator_es_doc(ind)
        body.append({'index': {'_index': ES_INDEX_NAME, '_id': doc['id']}})
        body.append(doc)
    return body
