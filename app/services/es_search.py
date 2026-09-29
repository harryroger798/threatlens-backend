"""Elasticsearch-ready search: document shape, query DSL builder.
The search API routes to ES when ES_URL is configured; otherwise it queries
the canonical store directly (the ES seam)."""

ES_INDEX_NAME = 'threatlens-indicators'


def indicator_es_doc(indicator) -> dict:
    """Project an Indicator ORM model into the Elasticsearch document shape."""
    return {
        'id': indicator.id,
        'value': indicator.value,
        'type': indicator.type,
        'severity_score': indicator.severity_score,
        'confidence': indicator.confidence,
        'tlp': indicator.tlp,
        'status': indicator.status,
        'malware_family': indicator.malware_family,
        'description': indicator.description or '',
        'internal_sightings': indicator.internal_sightings,
        'first_seen': indicator.first_seen.isoformat() if indicator.first_seen else None,
        'last_seen': indicator.last_seen.isoformat() if indicator.last_seen else None,
        'tags': [t.tag.name for t in indicator.tags],
        'sources': [s.source_name for s in indicator.sources],
        'techniques': [t.technique.technique_id for t in indicator.techniques],
    }


ES_INDEX_MAPPING = {
    'settings': {'number_of_shards': 3, 'number_of_replicas': 1},
    'mappings': {
        'properties': {
            'id': {'type': 'keyword'},
            'value': {'type': 'text', 'analyzer': 'standard'},
            'type': {'type': 'keyword'},
            'severity_score': {'type': 'integer'},
            'confidence': {'type': 'integer'},
            'tlp': {'type': 'keyword'},
            'status': {'type': 'keyword'},
            'malware_family': {'type': 'keyword'},
            'description': {'type': 'text'},
            'internal_sightings': {'type': 'integer'},
            'first_seen': {'type': 'date'},
            'last_seen': {'type': 'date'},
            'tags': {'type': 'keyword'},
            'sources': {'type': 'keyword'},
            'techniques': {'type': 'keyword'},
        }
    },
}


def build_es_query(q=None, types=None, tags=None, sources=None,
                   techniques=None, min_score=None, max_score=None,
                   tlp=None, status='active', limit=50, offset=0) -> dict:
    """Build the Elasticsearch DSL query from search parameters."""
    must = []
    filter_clauses = []
    if q:
        must.append({'multi_match': {
            'query': q,
            'fields': ['value', 'description', 'malware_family'],
            'type': 'best_fields',
        }})
    if types:
        filter_clauses.append({'terms': {'type': types}})
    if tags:
        filter_clauses.append({'terms': {'tags': tags}})
    if sources:
        filter_clauses.append({'terms': {'sources': sources}})
    if techniques:
        filter_clauses.append({'terms': {'techniques': techniques}})
    if min_score is not None:
        filter_clauses.append({'range': {'severity_score': {'gte': min_score}}})
    if max_score is not None:
        filter_clauses.append({'range': {'severity_score': {'lte': max_score}}})
    if tlp:
        filter_clauses.append({'term': {'tlp': tlp}})
    if status:
        filter_clauses.append({'term': {'status': status}})
    return {
        'query': {'bool': {'must': must, 'filter': filter_clauses}},
        'from': offset,
        'size': limit,
        'sort': [{'severity_score': {'order': 'desc'}}],
    }
