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
from langchain_community.vectorstores import FAISS  # or Chroma, Weaviate, etc.
from langchain_openai import ChatOpenAI
from langgraph.graph import MessageGraph, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import create_react_agent
from chromadb.config import DEFAULT_TENANT, DEFAULT_DATABASE
import chromadb
from langchain_chroma import Chroma as ChromaClient

from .extensions import postgresdb
from .config import Config
from .mcp_client import get_mcp_client

from langchain_community.embeddings import OpenAIEmbeddings
from langchain_core.documents import Document


def get_chroma_client():
    chroma_client = chromadb.HttpClient(
        host=Config.CHROMA_HOST,
        port=Config.CHROMA_PORT,
        ssl=False,
        headers=None,
    )
    return chroma_client


def get_embedding_function(api_key):
    return OpenAIEmbeddings(
        openai_api_key=api_key,
        model="text-embedding-3-large",
    )


def get_chroma_vectorstore(api_key):
    chroma_client = get_chroma_client()
    vectorstore = ChromaClient(
        client=chroma_client,
        collection_name="chats",
        embedding_function=get_embedding_function(api_key),
        create_collection_if_not_exists=True,
    )
    return vectorstore


def add_to_chroma_collection(
    api_key, session_id, new_messages: list[dict[str, str]]
) -> list:
    vectorstore = get_chroma_vectorstore(api_key)
    print("new_messages", new_messages)
    # new_messages = [{'user': 'hi'}, {'assistant': 'Hello! How can I assist you today?'}]
    documents = []
    for message in new_messages:
        for role, content in message.items():
            documents.append(
                Document(
                    page_content=content,
                    metadata={"session_id": session_id, "role": role},
                )
            )
    print("documents", documents)
    res: list = vectorstore.add_documents(documents=documents)
    return res


def get_retriever_tool(api_key):
    vectorstore = get_chroma_vectorstore(api_key)
    retriever = vectorstore.as_retriever()
    retriever_tool = create_retriever_tool(
        retriever,
        name="chat_rag",
        description="""
        Use this to answer questions based on user chat history (summarized and semantically indexed).
        Use this when the user asks about prior chats, what they asked earlier, or wants a summary of past conversations.
        
        Use this tool when the user refers to anything mentioned before, asks for a summary of previous messages or sessions, 
        or references phrases like 'what I said earlier', 'things we discussed', 'my earlier question', 'until now', 'till date', 'all my conversations' or 'previously mentioned'.
        The chat history is semantically indexed and summarized using vector search.
        """,
    )
    return retriever_tool
