import os
import textwrap
from typing import Annotated, Sequence, TypedDict

from langchain.agents.agent_toolkits import create_retriever_tool
from langchain.chains import LLMChain, RetrievalQA
from langchain.prompts import PromptTemplate
from langchain.schema import BaseMessage
from langchain.tools import Tool
from langchain_community.agent_toolkits import SQLDatabaseToolkit
from langchain_community.agent_toolkits.sql.base import create_sql_agent
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS  # or Chroma, Weaviate, etc.
from langchain_openai import ChatOpenAI
from langgraph.graph import MessageGraph, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import create_react_agent
from chromadb.config import DEFAULT_TENANT, DEFAULT_DATABASE, Settings
from .retrieverutils import get_retriever_tool

from .extensions import postgresdb
from .config import Config
from .mcp_client import get_mcp_client
import chromadb


async def build_langgraph_agent(api_key, model_name, user_jwt):
    system_prompt = textwrap.dedent(
        """
You are crAPI Assistant — an expert agent that helps users explore and test the Completely Ridiculous API (crAPI), a vulnerable-by-design application for learning and evaluating modern API security issues.

Your goals are:
- Answer questions about crAPI's endpoints, architecture, security flaws, and functionality.
- Help users explore crAPI’s behavior via code execution (e.g., curl, Python requests, etc.).
- Simulate attacks or pentests against crAPI to help users understand security issues like broken auth, BOLA, insecure API design, etc.
- Provide references or retrieved documentation when possible (RAG).
- Use tools such as code_interpreter, terminal, browser, or file_manager when needed.

You can:
- Write and run Python code (e.g., generate JWTs, exploit APIs)
- Simulate command-line interaction (e.g., curl calls to crAPI endpoints)
- Retrieve supporting content or documentation using a retriever
- Analyze API responses and suggest next steps
- Generate JSON or API payloads, explain logs, and provide security guidance
- Provide references or retrieved documentation when possible (RAG)

Constraints:
- You are interacting with a purposefully insecure application (crAPI) in a local or demo environment. It's okay to simulate exploitation and testing.
- Do NOT suggest actions against real-world or production APIs.
- Never access private user data or external systems outside crAPI.

You are helpful, accurate, and security-focused. Prioritize clarity, brevity, and correctness.

Examples:
- "Enumerate all crAPI endpoints."
- "Simulate a BOLA attack against the vehicle API."
- "Craft a request to reset password via the admin flow."
- "Run Python to decode this JWT."
- "What does the /workshop/api/me route expose?"

Always explain your reasoning briefly and select tools wisely.
Use the tools only if you don't know the answer.
    """
    )
    llm = ChatOpenAI(api_key=api_key, model=model_name)
    toolkit = SQLDatabaseToolkit(db=postgresdb, llm=llm)
    mcp_client = get_mcp_client(user_jwt)
    mcp_tools = await mcp_client.get_tools()
    db_tools = toolkit.get_tools()
    tools = mcp_tools + db_tools
    retriever_tool = get_retriever_tool(api_key)
    tools.append(retriever_tool)
    agent_node = create_react_agent(model=llm, tools=tools, prompt=system_prompt)
    return agent_node


async def execute_langgraph_agent(
    api_key, model_name, messages, user_jwt, session_id=None
):
    agent = await build_langgraph_agent(api_key, model_name, user_jwt)
    print("messages", messages)
    print("Session ID", session_id)
    response = await agent.ainvoke({"messages": messages})
    print("Response", response)
    return response
