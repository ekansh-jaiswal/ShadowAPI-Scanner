import os
from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.prompts import PromptTemplate
from chatbot.extensions import db
from .config import Config
from langchain.chains import RetrievalQA
from langchain_openai import ChatOpenAI


async def get_any_api_key():
    if os.environ.get("CHATBOT_OPENAI_API_KEY"):
        return os.environ.get("CHATBOT_OPENAI_API_KEY")
    doc = await db.sessions.find_one(
        {"openai_api_key": {"$exists": True, "$ne": None}}, {"openai_api_key": 1}
    )
    if doc and "openai_api_key" in doc:
        return doc["openai_api_key"]
    return None
