CREATE CONSTRAINT group_name IF NOT EXISTS ON (g:Group) ASSERT g.name IS UNIQUE;
CREATE CONSTRAINT domain_name IF NOT EXISTS ON (d:Domain) ASSERT d.name IS UNIQUE;
CREATE CONSTRAINT group_object_id IF NOT EXISTS ON (g:Group) ASSERT (g.objectid) IS UNIQUE;
CREATE CONSTRAINT ou_name IF NOT EXISTS ON (o:OU) ASSERT (o.name) IS UNIQUE;
CREATE CONSTRAINT domain_object_id IF NOT EXISTS ON (d:Domain) ASSERT (d.objectid) IS UNIQUE;
CREATE CONSTRAINT ou_object_id IF NOT EXISTS ON (o:OU) ASSERT (o.objectid) IS UNIQUE;
CREATE CONSTRAINT user_name IF NOT EXISTS ON (u:User) ASSERT (u.name) IS UNIQUE;
CREATE CONSTRAINT computer_objectid IF NOT EXISTS ON (c:Computer) ASSERT (c.objectid) IS UNIQUE;
CREATE CONSTRAINT computer_name IF NOT EXISTS ON (c:Computer) ASSERT (c.name) IS UNIQUE;
CREATE CONSTRAINT user_objectid IF NOT EXISTS ON (u:User) ASSERT (u.objectid) IS UNIQUE;
CREATE CONSTRAINT gpo_name IF NOT EXISTS ON (g:GPO) ASSERT (g.name) IS UNIQUE;


// Import from json
CALL apoc.import.json("https://raw.githubusercontent.com/neo4j-graph-examples/cybersecurity/main/data/cybersecurity-json-data.json");

MATCH (n) WHERE n.highvalue SET n:HighValue;

// Export to json
CALL apoc.export.json.all("all.json",{useTypes:true})

== Test data with simple queries

We will test the graph with some simple queries to get network objects information.

.List active sessions in the network.
[source,cypher]
----
// Get the path where there is an active HAS_SESSION relationship present and show all objects from path
MATCH p=(:Computer)-[r:HAS_SESSION]->(:User) 
RETURN p LIMIT 25;
----

Return all high value assets (we call them crownJewels) from the Network, also list what all groups, users have direct access to these high value objects.

These assets have an additional label `HighValue` that makes them easy to select and differentiate.

// TODO {highvalue:true} should be a label

[source,cypher]
----
MATCH (o:HighValue)<--(a)
WHERE a:User OR a:Group
RETURN o, a
----

Groups those have write (`WRITE_OWNER`) access to the domain object? Also find what all users have generic all access (full rights) from these groups

[source,cypher]
----
MATCH path=(d:Domain {name:'TestCompany.Local'})
  <-[:WRITE_OWNER]-(g:Group)-[:GENERIC_ALL]->(u:User)
RETURN path LIMIT 10
----

== More Advanced Analysis Queries

List all the machines where there are more than one active sessions running from different users.

[source,cypher]
----
// Match computers and users which have active HAS_SESSION relationship
MATCH (u:User)<-[:HAS_SESSION]-(c:Computer)

// Group user sessions by computer
WITH c, collect(distinct u.name) as users, 
     count(*) as sessions
// Condition of more than one active session
WHERE sessions > 1
RETURN c.name, users;
----

Get all users who have RDP access, and the computer where they have the access. 
Some Users have RDP access for self, some users have RDP access available through groups they are part of (inherited).

[source,cypher]
----
CALL
{
// Get users who have direct RDP access to machines
MATCH p=(:User)-[:CAN_RDP]->(:Computer) RETURN p

UNION ALL

// Users who got RDP access via groups (or group hierarchy) they are member of, this will check relationship levels upto 2 levels
MATCH p=(:User)-[:MEMBER_OF]->(:Group)
               -[:MEMBER_OF*0..2]->
        (:Group)-[:CAN_RDP]->(:Computer) 
RETURN p
}

// Return full paths
RETURN p LIMIT 50
----

== Analyzing possible attack paths

Cyber security nowadays is seeing a zero trust (trust no one) shift of network defense. 
This approach allows organization to restrict access controls to network, apps and environment without sacrificing performance and user experience. 

In a simple terms, we analyze any path that a user can take to reach to a high value resource in the network. 

_Is this access (path) necessary?_ 
If not, these unwanted access paths can be revoked or controlled. 

== Find possible attack paths

Let us take one particular user and check what all high value objects (or crown jewels) this user can reach directly or indirectly?

All these paths can be termed as possible attack paths.

For example: How many paths are possible from the user _"PiedadFlatley255@TestCompany.Local"_ to the high value resources like _Domain_, _Domain Controller_ and _Domain Admin_ group?

[source,cypher]
----
MATCH (u:User {name:'PiedadFlatley255@TestCompany.Local'})
// Match a high value object (we call it "crown jewel")
MATCH (crownJewel:HighValue)

MATCH path = shortestPath((u)-[*..100]->(crownJewel))

RETURN count(path)
----

That Cypher statement shows, that the user can reach out upto 4 high value assets either directly or indirectly.

Now, lets check what are these high value assets and what are these possible attack paths?

[source,cypher]
----
MATCH (u:User {name:'PiedadFlatley255@TestCompany.Local'})
MATCH (crownJewel:HighValue)

MATCH path = shortestPath((u)-[*..100]->(crownJewel))

RETURN path
----
.Attack paths from a user to a high value asset
== Analyze single attack path

Now, let us take a close look at one attack path. Check - How `"Piedad Flatley"` can reach upto `"ENTERPRISE DOMAIN CONTROLLERS"` group?

[source,cypher]
----
MATCH (u:User {name:'PiedadFlatley255@TestCompany.Local' })

// Match on object id of the ENTERPRISE DOMAIN CONTROLLERS Group
MATCH (crownJewel:Group:HighValue {objectid: "TestCompany.Local-S-1-5-9"})

MATCH path = shortestPath((u)-[*..100]->(crownJewel))

RETURN path
----

.Attack paths from a user to a high value asset
image::{img}/user-attack-path.svg[width=470]

We can see that the user _"Piedad Flatley"_ is a member of `"Domain Admins"` group, this group has admin access on computer `"FLLABDC@TestCompany.Local"`. 
And this computer is a member of `"ENTERPRISE DOMAIN CONTROLLERS"` group.

This is how we can picturize the possible impact paths and mitigate risk to avoid unexpected threats.

== Materializing attack paths data

We saw possible attack paths from one user. What is the possible extent of this analysis? We can check similar possible attack paths in whole network.

[source,cypher]
----
// Match a high value object
MATCH (crownJewel :Group {objectid:'S-1-5-21-883232822-274137685-4173207997-512'})

// Match all normal non-high value objects
MATCH (source) WHERE NOT source:HighValue

MATCH path = shortestPath((source)-[*..100]->(crownJewel))

// Pair one-one nodes from the path between crown jewel and normal object
UNWIND apoc.coll.pairsMin(nodes(path)) AS pair
WITH pair[0] AS a, pair[1] AS b
RETURN a.name, 'to', b.name LIMIT 10
----

In order to formalize this, for a possible risk mitigation,  we can materialize the attack paths by writing a relationship with name `"ATTACK_PATH"`

[source,cypher]
----
// Match a high value object
MATCH (crownJewel:Group {objectid:'S-1-5-21-883232822-274137685-4173207997-512'})

// Match all normal non-high value objects
MATCH (source) WHERE NOT source:HighValue

MATCH path = shortestPath((source)-[*..100]->(crownJewel))

// Pair one-one nodes from the path between crown jewel and normal object
UNWIND apoc.coll.pairsMin(nodes(path)) AS pair
WITH pair[0] AS a, pair[1] AS b

// Relationship -  path leading from a normal object to a high value object
MERGE (a)-[r:ATTACK_PATH]->(b)
RETURN count(r);
----

Check ATTACK_PATHS. 
[source,cypher]
----
MATCH p=()-[r:ATTACK_PATH]->() 
RETURN p LIMIT 25;
----

=== Betweenness Algorithm

////

[source,cypher]
----
CALL gds.graph.project('attackPaths','*','*')
----

Using "gds.graph.project.cypher" method, we will create a graph projection using cypher query. 
For finding attack paths, we have to include all nodes and relationships in GDS analysis.
So instead of explicitly specifying all node labels and relationship types, we have a provision to specify cypher queries which produce all nodes and relationships.

[source,cypher]
----
// Build projection
CALL gds.graph.project.cypher("attackPaths",

// Include all node labels
"MATCH (n) RETURN id(n) AS id",
   
// Include all relationship types
"MATCH (a)-[r]->(b) RETURN id(a) AS source, id(b) AS target"
);
----
////


We generated and materialized possible attack paths in the network. 
Now we must know what all nodes (network objects) are at high risk or can be part of most of the possible attack paths?

For this, we can apply a little more analytics to the ATTACK_PATH paths, we are going to project them into analytics graph projection, run it through the *Betweenness algorithm*.

Betweenness centrality is a way of detecting the amount of influence a node has over the flow of information in a graph. It is often used to find nodes that serve as a bridge from one part of a graph to another.

We will assign betweenness score to nodes on `ATTACK_PATH`. This score can help us in determining who from the nodes are heavy headers in attack paths.

* https://neo4j.com/docs/graph-data-science/current/algorithms/betweenness-centrality/[Betweenness Centrality^]

== Prepare Graph Projection

Below statement will prepare an in memory graph projection, named 'betweennessGraph' for our analysis. 

First, we will create an in-memory graph projection for this. We will consider *all* node labels and `ATTACK_PATH` relationship.

The documentation has more details on https://neo4j.com/docs/graph-data-science/current/management-ops/graph-catalog-ops/[in-memory graph projections^].

[source,cypher]
----
CALL gds.graph.project('betweennessGraph', 
  ['User', 'Group','Computer', 'Domain', 'GPO', 'OU'], 
  'ATTACK_PATH');
----

////
Second, we will estimate the memory usage for running this procedure on our projected data (nodes and relationships involved). 

[source,cypher]
----
CALL gds.betweenness.write.estimate('betweennessGraph', 
     { writeProperty: 'betweenness' })
YIELD nodeCount, relationshipCount, bytesMin, bytesMax, requiredMemory
----
////

Now we can run the betweenness procedure and stream results to see the weightage (betweenness score)

[source,cypher]
----
CALL gds.betweenness.stream('betweennessGraph')
YIELD nodeId, score
WITH gds.util.asNode(nodeId) AS n, score
RETURN n.name, labels(n), score 
ORDER BY score DESC 
LIMIT 100;
----

== Store and use betweenness scores

We can now materialize these weights by writing them as properties on respective nodes.

[source,cypher]
----
CALL gds.betweenness.write('betweennessGraph', 
     { writeProperty: 'betweenness' })
YIELD centralityDistribution, nodePropertiesWritten;
----

Finally, check users and groups which have much higher weights

[source,cypher]
----
MATCH (a)-[r:ATTACK_PATH]->(b)
WHERE a:User OR a:Group
RETURN a.name, labels(a), a.objectid, a.betweenness 
ORDER BY a.betweenness DESC 
LIMIT 25;
----

We can also visualize the attack paths and heavy weighed nodes in Neo4j Bloom to have some visual analytics over this data.

== Clear attack paths

Clear the attack paths and projection data using below cypher

[source,cypher]
----
// Drop graphs
CALL gds.graph.list() YIELD graphName
CALL gds.graph.drop(graphName) YIELD graphName AS dropped
RETURN count(*);

// Remove attack paths
MATCH ()-[r:ATTACK_PATH]->() DELETE r;
----






     

















                                   



















