#!/usr/bin/env python3
"""
Aerolink Telegram Bot - Claude Opus 4-7 + Thinking Mode via Aerolink Proxy
Available models: claude-opus-4-7 / claude-sonnet-4-6 / claude-haiku-4-5-20251001
Base URL: https://capi.aerolink.lat/
Features: typing indicator, file support (photos/docs), long message splitting
"""

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ChatAction
from anthropic import Anthropic
import logging
import asyncio
import base64
import os

# Logging setup
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# === CONFIG (from environment variables on Render) ===
AEROLINK_API_KEY = os.environ.get("AEROLINK_API_KEY", "aero_live_uQ0EFYU54Nw_dpXMCCJ4M3GIHIuvxj_DqutYkLyUCYA")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "8661760698:AAGobvipmg_0eW4FDx2rbk7t2AQ31jznvNs")
MAX_TELEGRAM_MSG_LENGTH = 4096

# Initialize Anthropic client pointing to Aerolink Proxy
client = Anthropic(
    api_key=AEROLINK_API_KEY,
    base_url="https://capi.aerolink.lat"
)


async def keep_typing(chat_id, context, stop_event):
    """Keep sending 'typing...' action until stop_event is set."""
    while not stop_event.is_set():
        try:
            await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)
        except Exception:
            pass
        await asyncio.sleep(4)


async def send_long_message(update, text):
    """Split and send messages that exceed Telegram's 4096 char limit."""
    if len(text) <= MAX_TELEGRAM_MSG_LENGTH:
        await update.message.reply_text(text)
        return

    chunks = []
    while text:
        if len(text) <= MAX_TELEGRAM_MSG_LENGTH:
            chunks.append(text)
            break
        split_at = text.rfind('\n', 0, MAX_TELEGRAM_MSG_LENGTH)
        if split_at == -1 or split_at < MAX_TELEGRAM_MSG_LENGTH // 2:
            split_at = text.rfind(' ', 0, MAX_TELEGRAM_MSG_LENGTH)
        if split_at == -1:
            split_at = MAX_TELEGRAM_MSG_LENGTH
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip()

    for i, chunk in enumerate(chunks):
        await update.message.reply_text(chunk)
        if i < len(chunks) - 1:
            await asyncio.sleep(0.3)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message."""
    user = update.effective_user
    await update.message.reply_text(
        f"👋 Hi {user.first_name}!\n\n"
        "🤖 **Aerolink Proxy Bot** is ready.\n"
        "🧠 Model: Claude Opus 4-7 (Thinking Mode)\n\n"
        "📝 **What I can do:**\n"
        "• Send me any text message\n"
        "• Send me photos (I'll analyze them)\n"
        "• Send me documents (text files, code, etc.)\n\n"
        "⏳ You'll see *typing...* while I'm thinking.\n"
        "📏 Long replies are auto-split.\n\n"
        "Just send your message!",
        parse_mode="Markdown"
    )
    logger.info(f"User {user.id} started the bot")


async def handle_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages and proxy to Aerolink/Claude."""
    user_text = update.message.text
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id

    logger.info(f"Received text from {user_id}: {user_text[:50]}...")

    stop_typing = asyncio.Event()
    typing_task = asyncio.create_task(keep_typing(chat_id, context, stop_typing))

    try:
        response = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=16384,
            thinking={
                "type": "enabled",
                "budget_tokens": 4096
            },
            messages=[
                {"role": "user", "content": user_text}
            ]
        )

        stop_typing.set()
        await typing_task

        reply_text = ""
        for block in response.content:
            if block.type == "text":
                reply_text = block.text
                break

        if reply_text:
            await send_long_message(update, reply_text)
            logger.info(f"Response sent to {user_id} ({len(reply_text)} chars)")
        else:
            await update.message.reply_text("⚠️ No text response received.")

    except Exception as e:
        stop_typing.set()
        await typing_task
        error_msg = f"❌ API Error: {str(e)}"
        logger.error(error_msg)
        await update.message.reply_text(error_msg)


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle photo messages."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    caption = update.message.caption or "What's in this image? Describe it in detail."

    logger.info(f"Received photo from {user_id}")

    stop_typing = asyncio.Event()
    typing_task = asyncio.create_task(keep_typing(chat_id, context, stop_typing))

    try:
        photo = update.message.photo[-1]
        file = await context.bot.get_file(photo.file_id)
        photo_bytes = await file.download_as_bytearray()
        photo_b64 = base64.b64encode(bytes(photo_bytes)).decode('utf-8')

        response = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=16384,
            thinking={
                "type": "enabled",
                "budget_tokens": 4096
            },
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/jpeg",
                                "data": photo_b64
                            }
                        },
                        {"type": "text", "text": caption}
                    ]
                }
            ]
        )

        stop_typing.set()
        await typing_task

        reply_text = ""
        for block in response.content:
            if block.type == "text":
                reply_text = block.text
                break

        if reply_text:
            await send_long_message(update, reply_text)
            logger.info(f"Photo analysis sent to {user_id}")
        else:
            await update.message.reply_text("⚠️ No response for the image.")

    except Exception as e:
        stop_typing.set()
        await typing_task
        error_msg = f"❌ Photo Error: {str(e)}"
        logger.error(error_msg)
        await update.message.reply_text(error_msg)


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle document uploads."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    caption = update.message.caption or "Analyze this file and summarize its contents."
    doc = update.message.document

    logger.info(f"Received document from {user_id}: {doc.file_name} ({doc.file_size} bytes)")

    if doc.file_size > 10 * 1024 * 1024:
        await update.message.reply_text("⚠️ File too large. Maximum size is 10MB.")
        return

    stop_typing = asyncio.Event()
    typing_task = asyncio.create_task(keep_typing(chat_id, context, stop_typing))

    try:
        file = await context.bot.get_file(doc.file_id)
        file_bytes = await file.download_as_bytearray()

        mime = doc.mime_type or ""
        if mime.startswith("image/"):
            file_b64 = base64.b64encode(bytes(file_bytes)).decode('utf-8')
            messages = [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": mime,
                                "data": file_b64
                            }
                        },
                        {"type": "text", "text": caption}
                    ]
                }
            ]
        else:
            try:
                file_text = bytes(file_bytes).decode('utf-8')
            except UnicodeDecodeError:
                try:
                    file_text = bytes(file_bytes).decode('latin-1')
                except Exception:
                    stop_typing.set()
                    await typing_task
                    await update.message.reply_text("⚠️ Can't read this file type. Send text files, code, or images.")
                    return

            if len(file_text) > 50000:
                file_text = file_text[:50000] + "\n\n... [TRUNCATED - file too long]"

            messages = [
                {
                    "role": "user",
                    "content": f"File: {doc.file_name}\n\n```\n{file_text}\n```\n\n{caption}"
                }
            ]

        response = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=16384,
            thinking={
                "type": "enabled",
                "budget_tokens": 4096
            },
            messages=messages
        )

        stop_typing.set()
        await typing_task

        reply_text = ""
        for block in response.content:
            if block.type == "text":
                reply_text = block.text
                break

        if reply_text:
            await send_long_message(update, reply_text)
            logger.info(f"Document analysis sent to {user_id}")
        else:
            await update.message.reply_text("⚠️ No response for the document.")

    except Exception as e:
        stop_typing.set()
        await typing_task
        error_msg = f"❌ Document Error: {str(e)}"
        logger.error(error_msg)
        await update.message.reply_text(error_msg)


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Log errors caused by updates."""
    logger.error(msg="Exception while handling an update:", exc_info=context.error)


def main():
    """Start the bot."""
    print("Starting Aerolink Telegram Bot...")
    print("Model: claude-opus-4-7 (Thinking Mode)")
    print("Features: typing indicator, photo/document support, long message splitting")

    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_prompt))

    app.add_error_handler(error_handler)

    print("Bot is running... Press Ctrl+C to stop.")
    logger.info("Aerolink Telegram Bot started successfully")

    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
