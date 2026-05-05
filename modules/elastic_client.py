try:
    from elasticsearch import Elasticsearch  # type: ignore
except ImportError:
    Elasticsearch = None

try:
    import streamlit as st  # type: ignore
except ImportError:
    st = None

import logging

class SecurityElasticClient:
    def __init__(self, host="http://localhost:9200", api_key=None):
        # In production, use st.secrets or env vars
        if Elasticsearch is None:
            logging.error("Elasticsearch library is not installed. Please run 'pip install elasticsearch'.")
            self.client = None
            return
            
        try:
            self.client = Elasticsearch(host, api_key=api_key)
        except Exception as e:
            logging.error(f"Failed to initialize Elasticsearch client: {e}")
            self.client = None
            
    def fetch_logs(self, index_pattern="security-logs-*", query=None, size=100):
        """Fetch and cache logs from Elasticsearch."""
        # Define the inner logic for fetching logs
        def _do_fetch():
            if self.client is None:
                return []
            # ... existing search logic ...

        # Apply streamlit caching only if streamlit is available
        if st is not None:
            return st.cache_data(ttl=600)(self._execute_search)(index_pattern, query, size)
        return self._execute_search(index_pattern, query, size)

    def _execute_search(self, index_pattern, query, size):
        if self.client is None:
            return []
            
        if query is None:
            query = {"match_all": {}}
        
        try:
            response = self.client.search(
                index=index_pattern,
                query=query,
                size=size
            )
            return response['hits']['hits']
        except Exception as e:
            logging.error(f"Error fetching logs from ES: {e}")
            return []

    def check_connection(self):
        """Verify ES is reachable."""
        return self.client.ping() if self.client else False