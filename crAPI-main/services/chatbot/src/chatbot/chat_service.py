from uuid import uuid4
from langgraph.graph.message import Messages
from .retrieverutils import add_to_chroma_collection
from .extensions import db
from .langgraph_agent import execute_langgraph_agent


async def get_chat_history(session_id):
    doc = await db.chat_sessions.find_one({"session_id": session_id})
    messages = doc["messages"] if doc else []
    return messages


async def update_chat_history(session_id, messages):
    await db.chat_sessions.update_one(
        {"session_id": session_id}, {"$set": {"messages": messages}}, upsert=True
    )


async def delete_chat_history(session_id):
    await db.chat_sessions.delete_one({"session_id": session_id})


async def process_user_message(session_id, user_message, api_key, model_name, user_jwt):
    history = await get_chat_history(session_id)
    # generate a unique numeric id for the message that is random but unique
    source_message_id = uuid4().int & (1 << 63) - 1
    history.append({"id": source_message_id, "role": "user", "content": user_message})
    # Run LangGraph agent
    response = await execute_langgraph_agent(
        api_key, model_name, history, user_jwt, session_id
    )
    print("Response", response)
    reply: Messages = response.get("messages", [{}])[-1]
    print("Reply", reply.content)
    response_message_id = uuid4().int & (1 << 63) - 1
    history.append(
        {"id": response_message_id, "role": "assistant", "content": reply.content}
    )
    res = add_to_chroma_collection(
        api_key, session_id, [{"user": user_message}, {"assistant": reply.content}]
    )
    # Limit chat history to last 20 messages
    history = history[-20:]
    await update_chat_history(session_id, history)
    return reply.content, response_message_id
