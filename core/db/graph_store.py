import logging
from neo4j import GraphDatabase

class ArtifactGraph:
    def __init__(self, uri, user, password):
        # Connect to the Neo4j Database
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.logger = logging.getLogger("GraphStore")

    def close(self):
        self.driver.close()

    def ingest_session_data(self, app_name, artifacts_list):
        """
        Takes the list of artifacts and pushes them into the graph.
        """
        with self.driver.session() as session:
            # 1. Ensure App Node exists
            session.execute_write(self._create_app_node, app_name)
            
            count = 0
            for artifact in artifacts_list:
                # Skip system noise (fonts, libs) to keep the graph clean
                fp = artifact['filepath']
                if any(x in fp for x in ["/usr/share/fonts", "/usr/lib", "/etc/ld.so", ".cache"]):
                    continue

                # 2. Create the Artifact Node
                session.execute_write(self._create_artifact_node, artifact)
                
                # 3. Link Process -> Artifact
                # 'accessed_by' is a list of process names like ['mousepad', 'sed']
                for proc_name in artifact.get('accessed_by', []):
                    session.execute_write(self._link_process, app_name, proc_name, fp, artifact['interactions'])
                
                count += 1
            return count

    @staticmethod
    def _create_app_node(tx, app_name):
        tx.run("MERGE (a:Application {name: $name})", name=app_name)

    @staticmethod
    def _create_artifact_node(tx, artifact):
        filepath = artifact['filepath']
        metadata = artifact.get('metadata', {})
        
        # Handle case where metadata failed or is missing
        if not isinstance(metadata, dict):
            mime = "unknown"
        else:
            mime = metadata.get('mime_type', 'unknown')

        tx.run("""
            MERGE (f:Artifact {filepath: $path})
            ON CREATE SET f.mime = $mime, f.first_seen = timestamp()
            ON MATCH SET f.last_seen = timestamp()
        """, path=filepath, mime=mime)

    @staticmethod
    def _link_process(tx, app_name, proc_name, filepath, interactions):
        # 1. Process belongs to App
        tx.run("""
            MATCH (a:Application {name: $app_name})
            MERGE (p:Process {name: $proc_name})
            MERGE (a)-[:SPAWNS]->(p)
        """, app_name=app_name, proc_name=proc_name)

        # 2. Process touched File
        # interactions is a list like ["OPEN", "WRITE"]
        tx.run("""
            MATCH (p:Process {name: $proc_name})
            MATCH (f:Artifact {filepath: $path})
            MERGE (p)-[r:TOUCHED]->(f)
            SET r.types = $interactions
        """, proc_name=proc_name, path=filepath, interactions=interactions)

    def add_d3fend_classification(self, filepath, d3fend_data):
        """
        Updates the Artifact node with LLM intelligence.
        """
        with self.driver.session() as session:
            session.run("""
                MATCH (f:Artifact {filepath: $path})
                MERGE (d:D3FEND_Class {id: $did})
                ON CREATE SET d.label = $dlabel
                MERGE (f)-[r:CLASSIFIED_AS]->(d)
                SET r.confidence = $conf, r.reason = $reason
            """, path=filepath, 
                 did=d3fend_data.get('d3fend_id', 'DA0000'), 
                 dlabel=d3fend_data.get('d3fend_label', 'Unknown'),
                 conf=d3fend_data.get('confidence', 0.0),
                 reason=d3fend_data.get('reasoning', 'No reason provided'))