# Complete RAG Implementation Guide
*From Simplest to Most Advanced - A Comprehensive Reference*

---

## Table of Contents
1. [RAG Fundamentals](#rag-fundamentals)
2. [RAG Implementation Levels (Simple → Advanced)](#rag-implementation-levels)
3. [What RAG Actually Is (Beyond Embeddings)](#what-rag-actually-is)
4. [Retrieval Methods Deep Dive](#retrieval-methods-deep-dive)
5. [Best Libraries for Each Retrieval Type](#best-libraries-for-each-retrieval-type)
6. [Production-Ready Agentic RAG Frameworks](#production-ready-agentic-rag-frameworks)
7. [Quick Reference Tables](#quick-reference-tables)

---

## RAG Fundamentals

RAG (Retrieval-Augmented Generation) is a pattern where you **retrieve relevant context from external sources** and **augment the LLM prompt** with that context before generating an answer.

### Core Pipeline
```
[Your Documents]
      ↓
  [RETRIEVAL]  ← Dense vectors, BM25, SQL, graph, or hybrid
      ↓
  [AUGMENT]    ← Stuff retrieved context into the LLM prompt
      ↓
  [GENERATION] ← LLM answers using that context
```

**Key Insight:** RAG is NOT just embeddings. The "Retrieve" part can use any method — vector search is just the most popular option.

---

## RAG Implementation Levels

Think of this as the same spectrum as **FastMCP → MCP → LangGraph**, but for RAG.

### Level 1 — Pure Python (Zero Frameworks)

The absolute minimum: load text, chunk it, embed with a small model, cosine-similarity search, stuff into a prompt.

```python
import ollama, numpy as np

def embed(text): 
    return ollama.embed("nomic-embed-text", input=text).embeddings[0]

def cosine(a, b): 
    return np.dot(a,b)/(np.linalg.norm(a)*np.linalg.norm(b))

chunks = open("doc.txt").read().split("\n")
db = [(c, embed(c)) for c in chunks]

query = "What is RAG?"
q_emb = embed(query)
best = sorted(db, key=lambda x: cosine(q_emb, x[1]), reverse=True)[:2]
context = "\n".join([b[0] for b in best])

response = ollama.chat("llama3", [{
    "role":"user",
    "content":f"Context:\n{context}\n\nQ:{query}"
}])
print(response)
```

**Complexity:** ⭐  
**Best for:** Learning the concept, no dependencies beyond `ollama` + `numpy`

---

### Level 2 — Direct Vector DB (No Framework)

Add a persistent vector store like **ChromaDB**, **Qdrant**, or **FAISS** directly — still no LangChain/LlamaIndex.

#### 2a. ChromaDB — Simplest, notebook-friendly

```python
import chromadb
from openai import OpenAI

client = OpenAI()
chroma = chromadb.Client()
col = chroma.create_collection("docs")

# Index
col.add(documents=["chunk1...", "chunk2..."], ids=["1","2"])

# Retrieve + Generate
results = col.query(query_texts=["your question"], n_results=2)
context = "\n".join(results["documents"][0])
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role":"user","content":f"Context: {context}\nQuestion: your question"}]
)
```

**Complexity:** ⭐⭐  
**Best for:** Quickest notebook RAG

---

#### 2b. Qdrant — In-memory or local folder (no server needed)

**Key advantage:** Same code runs locally AND on Qdrant Cloud — just change one line.

```python
from qdrant_client import QdrantClient, models
from sentence_transformers import SentenceTransformer

# In-memory (gone after script ends)
client = QdrantClient(":memory:")

# OR persistent to local folder on disk
# client = QdrantClient(path="./mydb")

encoder = SentenceTransformer("all-MiniLM-L6-v2")

client.create_collection(
    "docs", 
    vectors_config=models.VectorParams(size=384, distance=models.Distance.COSINE)
)

chunks = ["RAG uses retrieval...", "Qdrant is a vector DB..."]
client.upload_points("docs", points=[
    models.PointStruct(
        id=i, 
        vector=encoder.encode(chunk).tolist(), 
        payload={"text": chunk}
    )
    for i, chunk in enumerate(chunks)
])

hits = client.search(
    "docs", 
    query_vector=encoder.encode("your question").tolist(), 
    limit=3
)
context = "\n".join([h.payload["text"] for h in hits])
```

**Complexity:** ⭐⭐  
**Best for:** No-server, production-aligned — zero code change when scaling up

---

#### 2c. FAISS — Fastest for large local datasets

```python
import faiss, numpy as np

index = faiss.IndexFlatL2(384)
index.add(np.array(embeddings))

D, I = index.search(np.array([query_emb]), k=3)
results = [chunks[i] for i in I[0]]
```

**Complexity:** ⭐⭐  
**Best for:** Max local speed, no persistence by default

---

### Level 3 — LlamaIndex (Simplest Framework)

**The FastMCP of RAG** — 4 lines to a working pipeline, handles chunking/embedding/retrieval automatically.

```python
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader

docs = SimpleDirectoryReader("./docs").load_data()
index = VectorStoreIndex.from_documents(docs)
query_engine = index.as_query_engine()
print(query_engine.query("What is in my documents?"))
```

**Complexity:** ⭐⭐  
**Best for:** Fastest real RAG — recommended starting point

**Qdrant integration:**
```python
from llama_index.vector_stores.qdrant import QdrantVectorStore

vector_store = QdrantVectorStore(client=client, collection_name="docs")
index = VectorStoreIndex.from_documents(docs, vector_store=vector_store)
```

---

### Level 4 — LangChain RAG

More verbose but more control — good once you understand the pipeline. Uses LCEL (LangChain Expression Language) chains.

```python
from langchain_qdrant import QdrantVectorStore
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain.chains import RetrievalQA
from qdrant_client import QdrantClient

client = QdrantClient(":memory:")   # or path= for disk
vectorstore = QdrantVectorStore(
    client=client, 
    collection_name="demo", 
    embedding=OpenAIEmbeddings()
)
vectorstore.add_texts(chunks)

qa = RetrievalQA.from_chain_type(
    llm=ChatOpenAI(), 
    retriever=vectorstore.as_retriever()
)
qa.invoke("your question")
```

**Complexity:** ⭐⭐⭐  
**Best for:** Custom pipelines, integrates well with agents/memory/tools

---

### Level 5 — Advanced / Hybrid RAG

Combines **dense vector search + sparse BM25 keyword search** (hybrid), adds **re-ranking** (Cohere, cross-encoders), and query techniques like **HyDE** or **Multi-Query**.

#### Key additions:
- **Hybrid retrieval**: BM25 + vector search merged via Reciprocal Rank Fusion (RRF)
- **Re-ranking**: Use a cross-encoder to reorder retrieved chunks by relevance
- **Query rewriting**: HyDE (generate a hypothetical answer, then search with that), multi-query expansion
- **Metadata filtering**: Pre-filter by date, source, category before vector search

#### Hybrid Search Example (LangChain)

```python
from langchain.retrievers import BM25Retriever, EnsembleRetriever
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings

bm25 = BM25Retriever.from_texts(chunks)
bm25.k = 3

vectorstore = FAISS.from_texts(chunks, OpenAIEmbeddings())
dense = vectorstore.as_retriever(search_kwargs={"k": 3})

# RRF fusion happens automatically
hybrid = EnsembleRetriever(
    retrievers=[bm25, dense], 
    weights=[0.5, 0.5]
)
results = hybrid.invoke("your question")
```

**Note:** Qdrant, Weaviate, and Elasticsearch support hybrid search natively in one query.

**Complexity:** ⭐⭐⭐⭐  
**Best for:** Production accuracy

---

### Level 6 — Agentic RAG

The RAG system becomes an **autonomous agent** — it decides *when* to retrieve, *what* to search, *how many times*, and can use multiple tools/sources.

#### Key concepts:
- LLM decides retrieval strategy dynamically
- Can call web search, SQL, APIs, vector DB — not just one source
- Uses **CRAG** (Corrective RAG) to self-evaluate retrieval quality and retry
- **Adaptive RAG** routes queries: simple → direct answer, complex → multi-step retrieval

**Complexity:** ⭐⭐⭐⭐⭐  
**Best for:** Multi-source, adaptive retrieval  
**Best built with:** LangGraph, Agno, or PydanticAI for the orchestration loop

---

### Level 7 — GraphRAG / Modular RAG

The hardest — builds a **knowledge graph** from documents, enabling multi-hop reasoning across entities.

#### GraphRAG (Microsoft):
- Extracts entities/relationships from documents
- Builds a graph structure
- Traverses graph connections for answers
- Great for interconnected data
- Requires graph DBs like **Neo4j**

#### Modular RAG:
- Every component (chunker, embedder, retriever, reranker, generator) is a swappable module
- Fine-tuned sub-models for each stage
- Requires complex pipelines and significant infrastructure

**Complexity:** ⭐⭐⭐⭐⭐⭐  
**Best for:** Complex knowledge bases with interconnected facts

---

## Quick Progression Map

| Level | Tool/Approach | Complexity | Best For |
|---|---|---|---|
| 1 | Pure Python + Ollama | ⭐ | Learning the concept |
| 2a | ChromaDB + direct LLM | ⭐⭐ | Quickest notebook RAG |
| 2b | **Qdrant `:memory:` / `path=`** | ⭐⭐ | No-server, production-aligned |
| 2c | FAISS + direct LLM | ⭐⭐ | Max local speed |
| 3 | **LlamaIndex** | ⭐⭐ | **Fastest real RAG — start here** |
| 4 | LangChain + Qdrant/Chroma | ⭐⭐⭐ | Custom pipelines |
| 5 | Hybrid + Re-ranking | ⭐⭐⭐⭐ | Production accuracy |
| 6 | Agentic RAG (LangGraph/Agno) | ⭐⭐⭐⭐⭐ | Multi-source, adaptive |
| 7 | GraphRAG / Modular RAG | ⭐⭐⭐⭐⭐⭐ | Complex knowledge bases |

---

## What RAG Actually Is

### The Two Halves of RAG

```
[Documents] → [RETRIEVAL] → [AUGMENT] → [GENERATION]
```

People often focus only on the Generation part, but **Retrieval is fully interchangeable** — embeddings are just one option.

---

## Retrieval Methods Deep Dive

### 1. Dense Vector Search (Embeddings)

**How it works:** Text is converted to numerical vectors (embeddings), and similarity is measured by cosine/dot-product distance.

**Good for:**
- Meaning-based, fuzzy, semantic queries
- "What does this doc say about risks?"
- Paraphrases and synonyms

**Bad for:**
- Exact names, IDs, codes, legal clauses
- It "fuzzes" them out

**Tools:** Qdrant, ChromaDB, FAISS, Pinecone, Weaviate

---

### 2. Sparse / Keyword Search (BM25)

**How it works:** Old-school text search — ranks documents by term frequency + rarity. **No embeddings needed at all.**

**Good for:**
- Exact keywords, product names, codes, logs
- Legal/medical terms
- Proper nouns

**Bad for:**
- Paraphrases, synonyms, conceptual queries

**Tools:** Elasticsearch, Apache Lucene, BM25Retriever in LangChain

**Benchmark:** BM25 needs only 1 extra result (8 vs 7) to match OpenAI embedding recall — nearly equivalent for many use cases.

---

### 3. Hybrid Search (Dense + Sparse)

**How it works:** Runs both vector search AND BM25 simultaneously, then merges results using **Reciprocal Rank Fusion (RRF)**. Best of both worlds.

**Good for:**
- General production use
- When you need both semantic understanding AND exact keyword matching

**Tools:** Qdrant, Weaviate, Elasticsearch (all support natively in one query)

**Recommended:** This is the **recommended default** for production RAG.

---

### 4. SQL / Structured Retrieval

**How it works:** When your "documents" are actually a database, the LLM generates a SQL query to retrieve rows.

**Called:** Text-to-SQL RAG or Structured RAG

**Good for:**
- Dashboards, analytics
- Tabular data, business reports
- When data is already structured

**No chunks, no embeddings** — just natural language → SQL → results → LLM

---

### 5. Knowledge Graph Retrieval (GraphRAG)

**How it works:** Documents are parsed into **entities + relationships** stored in a graph DB (Neo4j). Retrieval traverses graph connections instead of matching vectors.

**Good for:**
- Multi-hop questions
- "Who reported to the CEO who approved the deal in Q3?"
- Handles *connections between facts*, not just individual chunks

**Bad for:**
- Simple factual lookups (overkill)

---

### 6. Hierarchical / Tree Retrieval (RAPTOR)

**How it works:** Chunks are recursively summarized into a tree — leaf nodes = raw chunks, parent nodes = summaries of summaries.

Retrieval picks the right *level* of detail:
- Specific chunk
- Section summary
- Full doc summary

**Good for:**
- Long structured documents
- Books, legal contracts, research papers
- When you need both high-level and detailed answers

---

### 7. LLM-Guided / Agentic Retrieval

**How it works:** No fixed retrieval method — the LLM itself decides *what* to search, *how*, and *when to stop*.

**Good for:**
- Complex, multi-step questions that need iterative lookups
- When different queries need different retrieval strategies

Can mix all the above methods dynamically per query.

---

## Retrieval Methods Quick Reference

| Retrieval Type | Finds by | Needs Embeddings? | Best For |
|---|---|---|---|
| Dense Vector | Meaning/semantics | ✅ Yes | Fuzzy conceptual queries |
| BM25 / Sparse | Exact keywords | ❌ No | Names, IDs, codes |
| Hybrid (RRF) | Both | ✅ Partly | General production use ⭐ |
| SQL | Database rows | ❌ No | Structured/tabular data |
| Graph | Entity relationships | ❌ No | Multi-hop, interconnected facts |
| RAPTOR | Tree of summaries | ✅ Yes | Long documents, right granularity |
| Agentic | LLM decides | ⚡ Dynamic | Complex, iterative queries |

---

## Best Libraries for Each Retrieval Type

### 1. Dense Vector Search (Semantic / Fuzzy)

**Best simple library:** `sentence-transformers` + `FAISS` or `Qdrant`

```python
from sentence_transformers import SentenceTransformer
import faiss, numpy as np

model = SentenceTransformer("all-MiniLM-L6-v2")   # tiny, fast, free

chunks = ["RAG is a technique...", "Embeddings are vectors...", "FAISS is fast..."]
embeddings = model.encode(chunks, normalize_embeddings=True).astype(np.float32)

index = faiss.IndexFlatIP(embeddings.shape[1])
index.add(embeddings)

query_vec = model.encode(["what is RAG?"], normalize_embeddings=True).astype(np.float32)
D, I = index.search(query_vec, k=2)
print([chunks[i] for i in I[0]])   # top 2 semantic matches
```

**Why this works:**
- `sentence-transformers` gives you free local embeddings — no API key needed
- Swap FAISS for `QdrantClient(":memory:")` when you need filtering + metadata

---

### 2. Sparse / Keyword Search (BM25)

**Best simple library:** `bm25s` — pure Python, no Java, no Elasticsearch, just `pip install bm25s`

```python
import bm25s

corpus = ["RAG uses retrieval to augment LLMs",
          "BM25 ranks by keyword frequency",
          "Embeddings capture semantic meaning"]

retriever = bm25s.BM25()
retriever.index(bm25s.tokenize(corpus))

query = "keyword ranking retrieval"
results, scores = retriever.retrieve(bm25s.tokenize(query), corpus=corpus, k=2)
print(results)
```

**Why this works:**
- Faster than ElasticSearch for local use
- No server, no Java dependency
- Alternative: `rank_bm25` is simpler but 100x slower — stick with `bm25s`

---

### 3. Hybrid Search (Dense + Sparse combined)

**Best simple library:** `Qdrant` (native hybrid) or `LangChain EnsembleRetriever`

```python
# LangChain EnsembleRetriever — simplest hybrid setup
from langchain.retrievers import BM25Retriever, EnsembleRetriever
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings

bm25 = BM25Retriever.from_texts(chunks)
bm25.k = 3

vectorstore = FAISS.from_texts(chunks, OpenAIEmbeddings())
dense = vectorstore.as_retriever(search_kwargs={"k": 3})

hybrid = EnsembleRetriever(retrievers=[bm25, dense], weights=[0.5, 0.5])
hybrid.invoke("your question")  # RRF fusion happens automatically
```

**Note:** Qdrant's Python client does this natively with sparse+dense vectors in one query — no manual merging needed.

---

### 4. SQL / Structured Retrieval (Text-to-SQL)

**Best simple library:** `vanna` — open source, RAG-native, 2-step setup

```python
import vanna
from vanna.openai import OpenAI_Chat
from vanna.chromadb import ChromaDB_VectorStore

class MyVanna(ChromaDB_VectorStore, OpenAI_Chat):
    def __init__(self, config=None):
        ChromaDB_VectorStore.__init__(self, config=config)
        OpenAI_Chat.__init__(self, config=config)

vn = MyVanna(config={"api_key": "sk-...", "model": "gpt-4o"})
vn.connect_to_sqlite("my_database.db")

# Train it on your schema (one-time)
vn.train(ddl="CREATE TABLE sales (id INT, revenue FLOAT, date DATE)")

# Ask in plain English — returns + runs SQL
vn.ask("What were total sales last month?")
```

**Why this works:**
- Vanna self-learns — correct queries get stored and improve future accuracy
- Works with SQLite, PostgreSQL, Snowflake, BigQuery — same API

---

### 5. Knowledge Graph Retrieval (GraphRAG)

**Best simple library:** `neo4j-graphrag` — official Neo4j Python package

```python
from neo4j import GraphDatabase
from neo4j_graphrag.embeddings import OpenAIEmbeddings
from neo4j_graphrag.generation import GraphRAG
from neo4j_graphrag.llm import OpenAILLM
from neo4j_graphrag.retrievers import VectorRetriever

driver = GraphDatabase.driver("neo4j://localhost:7687", auth=("neo4j", "password"))
embedder = OpenAIEmbeddings(model="text-embedding-3-small")
retriever = VectorRetriever(driver, "my_index", embedder)

llm = OpenAILLM(model_name="gpt-4o")
rag = GraphRAG(retriever=retriever, llm=llm)

response = rag.search("Who approved the deal in Q3?", retriever_config={"top_k": 5})
print(response.answer)
```

**Why this works:**
- `SimpleKGPipeline` auto-extracts entities + relationships from your docs to build the graph
- Needs a running Neo4j instance (free local via Docker or Neo4j Desktop)

---

### 6. Hierarchical / Tree Retrieval (RAPTOR)

**Best simple library:** `llama-index` RAPTOR Pack — built-in, plug-and-play

```python
from llama_index.packs.raptor import RaptorPack
from llama_index.core import SimpleDirectoryReader

docs = SimpleDirectoryReader("./docs").load_data()

# Builds the tree automatically — embeds, clusters, summarizes recursively
raptor = RaptorPack(docs, llm=your_llm, embed_model=your_embed_model)

# Collapse mode: query all tree levels flat (recommended for most cases)
response = raptor.run("Give me a high-level summary of all documents", mode="collapsed")
print(response)
```

**Why this works:**
- Solves the core weakness of naive RAG: it can answer *both* specific and broad questions by picking the right tree level
- Alternative: `HIRO` on GitHub for a more standalone implementation

---

### 7. Agentic Retrieval

**Best simple library:** See the [Production-Ready Agentic RAG Frameworks](#production-ready-agentic-rag-frameworks) section below.

---

## Library Cheatsheet

| Retrieval Type | Simplest Library | Install |
|---|---|---|
| Dense / Semantic | `sentence-transformers` + FAISS | `pip install sentence-transformers faiss-cpu` |
| Sparse / BM25 | `bm25s` | `pip install bm25s` |
| Hybrid | LangChain `EnsembleRetriever` or Qdrant | `pip install langchain qdrant-client` |
| Text-to-SQL | `vanna` | `pip install vanna` |
| Graph | `neo4j-graphrag` | `pip install neo4j-graphrag` |
| Hierarchical / RAPTOR | LlamaIndex RAPTOR Pack | `pip install llama-index-packs-raptor` |
| Agentic | Agno / PydanticAI / Haystack | See next section |

---

## Production-Ready Agentic RAG Frameworks

These are the **best production-ready frameworks** for agentic RAG — ordered from simplest to most complex, all supporting agents, sub-agents, MCP, tools, and agentic loops.

---

### 🥇 Agno — Simplest + Most Feature-Rich (Recommended)

**This is your FastMCP equivalent for agentic RAG.** It's ~10,000x faster to instantiate than LangGraph, supports MCP natively, teams, sub-agents, built-in RAG, memory, and a hosted monitoring dashboard — all in minimal code.

#### Basic Agent with RAG + Tools + Memory

```python
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.duckduckgo import DuckDuckGoTools
from agno.knowledge.pdf import PDFKnowledgeBase
from agno.vectordb.qdrant import Qdrant

# Agent with RAG + tools + memory in one shot
agent = Agent(
    model=OpenAIChat(id="gpt-4o"),
    tools=[DuckDuckGoTools()],                        # tools
    knowledge=PDFKnowledgeBase(                       # agentic RAG
        path="./docs",
        vector_db=Qdrant(collection="my_docs")
    ),
    search_knowledge=True,                            # auto RAG on every query
    markdown=True,
    show_tool_calls=True
)
agent.print_response("Summarize my docs and search latest news on the topic", stream=True)
```

#### Sub-agents / Teams (Supervisor Pattern)

```python
from agno.agent import Agent
from agno.team import Team

researcher = Agent(name="Researcher", tools=[DuckDuckGoTools()], ...)
analyst   = Agent(name="Analyst",    knowledge=my_kb, ...)

team = Team(
    members=[researcher, analyst],
    mode="coordinate",           # supervisor assigns tasks to sub-agents
    model=OpenAIChat(id="gpt-4o")
)
team.print_response("Research and analyze AI trends from my documents")
```

#### MCP Support

```python
from agno.tools.mcp import MCPTools

agent = Agent(
    model=OpenAIChat(id="gpt-4o"),
    tools=[MCPTools(server_url="http://localhost:8000/mcp")]  # plug any MCP server
)
```

**Features:**
- ✅ Built-in RAG
- ✅ Teams/Sub-agents
- ✅ MCP support
- ✅ Memory
- ✅ Monitoring dashboard at agno.com
- ✅ ~3.75KB memory per agent
- ✅ ~10,000x faster instantiation than LangGraph

**Best for:** All-in-one agentic RAG with minimal code

---

### 🥈 PydanticAI — Best for Type-Safe Production

If your production app needs **structured outputs, strict typing, validated responses** — PydanticAI is the pick. Clean, Pythonic, great docs, and full MCP support.

#### Structured Output Agent with MCP

```python
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStreamableHTTP
from pydantic import BaseModel

class Answer(BaseModel):
    summary: str
    sources: list[str]
    confidence: float

mcp = MCPServerStreamableHTTP(url="http://localhost:8000/mcp")

agent = Agent(
    "openai:gpt-4o",
    result_type=Answer,            # structured output — always valid Pydantic model
    toolsets=[mcp],                # MCP tools plugged in directly
    system_prompt="Answer using documents and tools"
)

async with agent:
    result = await agent.run("What are the key risks in my contract?")
    print(result.output.summary)   # fully typed, validated
    print(result.output.confidence)
```

#### Agentic Loop / Sub-agent Pattern

```python
# Agent calls another agent as a tool
inner_agent = Agent("openai:gpt-4o", ...)

@outer_agent.tool
async def delegate_to_expert(ctx, query: str) -> str:
    result = await inner_agent.run(query)
    return result.output
```

**Features:**
- ✅ MCP support
- ✅ Structured outputs (Pydantic models)
- ✅ Sub-agents as tools
- ✅ Type-safe
- ✅ Best for APIs/production services

**Best for:** Type-safe production apps with validated outputs

---

### 🥉 Haystack — Best for Complex Pipeline RAG

Built specifically for **production RAG pipelines** with conditional routing, looping, fallbacks, and component-level swappability — everything is a modular pipeline node.

#### Agentic Fallback Pipeline

```python
from haystack import Pipeline
from haystack.components.retrievers import InMemoryBM25Retriever
from haystack.components.generators import OpenAIGenerator
from haystack.components.routers import ConditionalRouter

# Agentic fallback: try RAG first, fall back to web search if no answer
routes = [
    {"condition": "{{'no_answer' in replies[0]}}", "output": "{{query}}", "output_name": "go_to_websearch"},
    {"condition": "{{True}}", "output": "{{replies[0]}}", "output_name": "answer"},
]

pipeline = Pipeline()
pipeline.add_component("retriever", InMemoryBM25Retriever(doc_store))
pipeline.add_component("llm", OpenAIGenerator(model="gpt-4o"))
pipeline.add_component("router", ConditionalRouter(routes=routes))
pipeline.add_component("web_search", SerperDevWebSearch())

# Connect them
pipeline.connect("retriever", "llm")
pipeline.connect("llm.replies", "router.replies")
pipeline.connect("router.go_to_websearch", "web_search.query")  # fallback loop

result = pipeline.run({"retriever": {"query": "your question"}})
```

**Features:**
- ✅ Conditional routing
- ✅ Agentic loops/fallbacks
- ✅ Swap any component
- ✅ Visual pipeline builder (deepset Studio)
- ✅ Production tracing

**Best for:** Complex pipelines with branching logic ("try vector search, if poor result, retry with web search, if still bad, escalate to human")

---

### Framework Comparison Table

| Framework | Best For | MCP | Sub-agents | Simplicity |
|---|---|---|---|---|
| **Agno** | All-in-one: RAG + agents + teams | ✅ | ✅ Teams | ⭐⭐⭐⭐⭐ |
| **PydanticAI** | Type-safe, structured outputs, APIs | ✅ | ✅ as tools | ⭐⭐⭐⭐⭐ |
| **Haystack** | Complex pipelines, routing, fallbacks | ✅ | ✅ | ⭐⭐⭐⭐ |
| **OpenAI Agents SDK** | OpenAI-only stack, clean handoffs | ✅ | ✅ handoffs | ⭐⭐⭐⭐ |
| **Google ADK** | Gemini + multi-agent, enterprise | ✅ | ✅ | ⭐⭐⭐ |
| **LangGraph** | Complex stateful graphs, full control | ✅ | ✅ | ⭐⭐ |

### Recommended Picks

1. **Start with Agno** — it does everything (RAG + MCP + teams + memory + monitoring) with the least code, and is genuinely production-ready

2. **Use PydanticAI** when your production system needs strict typed outputs and validated responses going into APIs or databases

3. **Use Haystack** when your RAG pipeline has complex branching — like "try vector search, if poor result, retry with web search, if still bad, escalate to human"

---

## Quick Reference Tables

### RAG Complexity Spectrum

| Level | Tool | Lines of Code | Setup Time | Production Ready |
|---|---|---|---|---|
| 1 | Pure Python | ~15 | 5 min | ❌ |
| 2 | Qdrant local | ~20 | 10 min | ⚠️ |
| 3 | LlamaIndex | ~4 | 2 min | ✅ |
| 4 | LangChain | ~10 | 15 min | ✅ |
| 5 | Hybrid + Re-rank | ~30 | 30 min | ✅✅ |
| 6 | Agentic (Agno) | ~15 | 20 min | ✅✅ |
| 7 | GraphRAG | ~50+ | hours | ✅✅✅ |

### When to Use Which Retrieval Method

| Your Data Type | Recommended Retrieval |
|---|---|
| General documents (PDFs, articles) | Hybrid (BM25 + Vector) |
| Code repositories | BM25 (exact matches matter) |
| Research papers | RAPTOR (hierarchical) |
| Customer support tickets | Vector (semantic similarity) |
| Legal contracts | Hybrid + Graph (entities + clauses) |
| Database tables | SQL (Text-to-SQL RAG) |
| Knowledge bases with relationships | GraphRAG |
| Multi-step complex queries | Agentic RAG |

### Installation Quick Commands

```bash
# Level 1-2: Basics
pip install ollama sentence-transformers faiss-cpu numpy

# Level 2-3: Vector DBs + Frameworks
pip install chromadb qdrant-client llama-index

# Level 4: LangChain
pip install langchain langchain-community langchain-openai

# Level 5: Hybrid + Advanced
pip install bm25s cohere

# Level 6: Agentic
pip install agno pydantic-ai haystack-ai

# Level 7: Graph
pip install neo4j neo4j-graphrag
```

---

## Conclusion

**Start simple, scale as needed:**

1. **Learning?** → Start with Level 1 (Pure Python) or Level 3 (LlamaIndex)
2. **Building an MVP?** → Level 3 (LlamaIndex) + Qdrant
3. **Production app?** → Level 5 (Hybrid) + Level 6 (Agentic with Agno)
4. **Enterprise/Complex?** → Level 6-7 (Agentic + GraphRAG)

**The key insight:** RAG is a pattern, not a single technology. Choose your retrieval method based on your data type and query patterns, not just "everyone uses embeddings so I should too."

---

*Last updated: March 2026*