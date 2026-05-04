from elasticsearch import Elasticsearch
import streamlit as st
import logging

class SecurityElasticClient:
    def __init__(self, host="http://localhost:9200", api_key=None):
        # In production, use st.secrets or env vars
        try:
            self.client = Elasticsearch(host, api_key=api_key)
        except Exception as e:
            logging.error(f"Failed to initialize Elasticsearch client: {e}")
            self.client = None
            
    @st.cache_data(ttl=600)
    def fetch_logs(self, index_pattern="security-logs-*", query=None, size=100):
        """Fetch and cache logs from Elasticsearch."""
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