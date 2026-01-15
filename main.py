import aiohttp.web as web
import asyncio
import os
from datetime import datetime
import mimetypes
from aiofiles import open as aioopen
import logging
import sys
import hashlib
from pathlib import Path
import re
from supabase import create_client, Client
import base64
import uuid
import base64
import PyPDF2
from io import BytesIO
from dotenv import load_dotenv
import os
from groq import Groq

load_dotenv()   # 👈 THIS loads .env

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

groq_client = Groq(api_key=GROQ_API_KEY)


# ────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────
ADMIN_EMAIL = "zapierobroy77777559977@gmail.com"
SUPABASE_URL = "https://obnhesobzgppiidigdtu.supabase.co"
SUPABASE_KEY = "sb_publishable_-zpPTE45VhRROAZOV0xxFg_iTMVSYLA"
LOG_DIR = Path("logs")
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Create directories
LOG_DIR.mkdir(exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)-7s] %(name)-12s %(funcName)18s:%(lineno)4d → %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "filemanager.log"),
        logging.FileHandler(LOG_DIR / "operations.log")
    ]
)
logger = logging.getLogger("filemanager")
operation_logger = logging.getLogger("operations")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ────────────────────────────────────────────────
# HELPERS
# ────────────────────────────────────────────────
def safe_filename(original: str) -> str:
    """Sanitize filename - prevent path traversal & dangerous chars"""
    name = Path(original).name
    name = re.sub(r'[^a-zA-Z0-9._\-\u0600-\u06FF\s]', '_', name)
    if len(name) > 180:
        base, ext = os.path.splitext(name)
        name = base[:170] + ext
    return name

def calculate_file_hash(file_bytes: bytes, algorithm="md5") -> str | None:
    """Calculate hash from bytes"""
    try:
        hasher = hashlib.new(algorithm)
        hasher.update(file_bytes)
        return hasher.hexdigest()
    except Exception as e:
        logger.error(f"Hash calculation failed: {e}")
        return None

def log_operation(operation: str, file_id=None, filename=None, user_email=None,
                  success=True, details=None, error_message=None):
    try:
        data = {
            'operation': operation.upper(),
            'file_id': file_id,
            'filename': filename,
            'user_email': user_email,
            'operation_time': datetime.utcnow().isoformat(),
            'details': details,
            'success': success,
            'error_message': error_message
        }
        supabase.table('operations_log').insert(data).execute()
        msg = f"{operation:8} | {filename or '-':<35} | {user_email or '-':<28} | {'OK' if success else 'FAIL'}"
        if details: msg += f" | {details}"
        if error_message: msg += f" | {error_message}"
        if success:
            operation_logger.info(msg)
        else:
            operation_logger.error(msg)
    except Exception as e:
        logger.error(f"Operation logging failed: {e}")

# Wrapper to run Supabase sync calls in thread (non-blocking)
async def run_supabase_sync(func, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

# JSON Error Response Helper
def json_error(message, status=500):
    return web.json_response({"success": False, "message": message}, status=status)

# ────────────────────────────────────────────────
# MIDDLEWARE FOR JSON ERRORS
# ────────────────────────────────────────────────
async def json_error_middleware(app, handler):
    async def middleware_handler(request):
        try:
            response = await handler(request)
            return response
        except web.HTTPException as ex:
            return json_error(str(ex), ex.status)
        except Exception as ex:
            logger.error(f"Unhandled error: {ex}", exc_info=True)
            return json_error(f"Internal server error: {str(ex)}", 500)
    return middleware_handler

# ────────────────────────────────────────────────
# ROUTES - FILES STORED IN SUPABASE DB
# ────────────────────────────────────────────────
async def read_root(request):
    try:
        async with aioopen("index.html", "r", encoding="utf-8") as f:
            return web.Response(text=await f.read(), content_type='text/html')
    except FileNotFoundError:
        return web.Response(text="<h1>index.html not found</h1>", status=404)
    except Exception as e:
        logger.error(f"Root page error: {e}")
        raise web.HTTPInternalServerError()
    
    
    
async def last_read_root(request):
    try:
        async with aioopen("images.html", "r", encoding="utf-8") as f:
            return web.Response(text=await f.read(), content_type='text/html')
    except FileNotFoundError:
        return web.Response(text="<h1>images.html not found</h1>", status=404)
    except Exception as e:
        logger.error(f"Root page error: {e}")
        raise web.HTTPInternalServerError()

async def get_files(request):
    try:
        res = await run_supabase_sync(
            supabase.table('files')
            .select("id, filename, filetype, size, uploaded_at, email, download_count, last_accessed")
            .eq('status', 'active')
            .order('uploaded_at', desc=True)
            .execute
        )
        files = res.data or []
        total_size = sum(f['size'] for f in files)
        return web.json_response({
            "success": True,
            "files": files,
            "total_files": len(files),
            "total_size_bytes": total_size
        })
    except Exception as e:
        logger.error(f"get_files error: {e}", exc_info=True)
        raise

async def upload_file(request):
    original_name = None
    email = "anonymous@user.com"
    try:
        reader = await request.multipart()
        file_content = bytearray()
        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == "file":
                original_name = safe_filename(part.filename)
                async for chunk in part:
                    file_content.extend(chunk)
            elif part.name == "email":
                email = (await part.text()).strip()[:180]
        
        if not original_name or not file_content:
            log_operation("UPLOAD", user_email=email, success=False, error_message="Missing file")
            return json_error("File is required", 400)
        
        file_size = len(file_content)
        
        if file_size == 0:
            log_operation("UPLOAD", filename=original_name, user_email=email, success=False, error_message="Empty file")
            return json_error("Empty file not allowed. Please upload a file with content.", 400)
        
        if file_size > MAX_FILE_SIZE:
            log_operation("UPLOAD", filename=original_name, user_email=email, success=False, error_message="File too large")
            return json_error(f"File too large. Maximum size is {MAX_FILE_SIZE//1024//1024}MB", 413)
        
        # Check if file with same name already exists
        existing = await run_supabase_sync(
            supabase.table('files')
            .select("id")
            .eq('filename', original_name)
            .eq('status', 'active')
            .execute
        )
        
        if existing.data:
            log_operation("UPLOAD", filename=original_name, user_email=email, success=False, error_message="File already exists")
            return json_error(f"File '{original_name}' already exists. Please rename your file or delete the existing one first.", 409)
        
        # Calculate hash
        file_hash = calculate_file_hash(bytes(file_content))
        
        # Encode file content as base64 for storage in PostgreSQL
        file_b64 = base64.b64encode(bytes(file_content)).decode('utf-8')
        
        data = {
            "filename": original_name,
            "filetype": Path(original_name).suffix.lstrip('.').upper() or "FILE",
            "size": file_size,
            "uploaded_at": datetime.utcnow().isoformat(),
            "email": email,
            "md5_hash": file_hash,
            "last_accessed": datetime.utcnow().isoformat(),
            "status": "active",
            "download_count": 0,
            "file_data": file_b64  # Store base64 encoded file in DB
        }
        
        result = await run_supabase_sync(supabase.table('files').insert(data).execute)
        file_id = result.data[0]["id"]
        
        log_operation("UPLOAD", file_id, original_name, email, True,
                      f"Size: {file_size:,} Hash: {file_hash}")
        
        return web.json_response({
            "success": True,
            "message": f"File '{original_name}' uploaded successfully",
            "id": file_id,
            "filename": original_name,
            "size": file_size,
            "hash": file_hash
        })
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        log_operation("UPLOAD", filename=original_name, user_email=email,
                      success=False, error_message=str(e))
        raise

async def download_file(request):
    try:
        file_id = int(request.match_info['file_id'])
        
        # Fetch file with data from DB
        res = await run_supabase_sync(
            supabase.table('files')
            .select("filename, size, md5_hash, download_count, file_data")
            .eq('id', file_id)
            .eq('status', 'active')
            .single()
            .execute
        )
        
        if not res.data:
            raise web.HTTPNotFound(text="File not found or deleted")
        
        file = res.data
        
        if not file.get('file_data'):
            log_operation("DOWNLOAD", file_id, file['filename'], None, False, error_message="File data missing")
            raise web.HTTPNotFound(text="File data not found in database")
        
        # Decode base64 file content
        try:
            file_bytes = base64.b64decode(file['file_data'])
        except Exception as e:
            logger.error(f"Failed to decode file data for ID {file_id}: {e}")
            raise web.HTTPInternalServerError(text="File data corrupted")
        
        mime, _ = mimetypes.guess_type(file['filename'])
        mime = mime or 'application/octet-stream'
        
        # Update download count
        current_count = file.get('download_count', 0)
        await run_supabase_sync(
            supabase.table('files')
            .update({"download_count": current_count + 1, "last_accessed": datetime.utcnow().isoformat()})
            .eq('id', file_id)
            .execute
        )
        
        log_operation("DOWNLOAD", file_id, file['filename'], success=True,
                      details=f"Size: {file['size']:,}")
        
        return web.Response(
            body=file_bytes,
            headers={
                "Content-Disposition": f'attachment; filename="{file["filename"]}"',
                "Content-Type": mime,
                "Content-Length": str(len(file_bytes)),
                "X-File-Hash": file["md5_hash"] or ""
            }
        )
    except web.HTTPException:
        raise
    except ValueError:
        raise web.HTTPBadRequest(text="Invalid file ID")
    except Exception as e:
        logger.error(f"Download error: {e}")
        raise


async def delete_file(request):
    try:
        file_id = int(request.match_info.get("file_id"))
    except (TypeError, ValueError):
        return json_error("Invalid file ID", 400)

    # ---------------------------
    # Extract email
    # ---------------------------
    email = request.query.get("email", "").strip()

    if not email:
        try:
            data = await request.json()
            email = data.get("email", "").strip()
        except Exception:
            pass

    if not email:
        return json_error("Email is required", 400)

    logger.info(f"🗑️ HARD DELETE | file_id={file_id} | email={email}")

    # ---------------------------
    # Admin check
    # ---------------------------
    if email != ADMIN_EMAIL:
        log_operation("DELETE", file_id, user_email=email,
                      success=False, error_message="Unauthorized")
        return json_error("Access denied (admin only)", 403)

    try:
        # ---------------------------
        # Fetch file first (for logging)
        # ---------------------------
        fetch_res = await run_supabase_sync(
            supabase.table("files")
            .select("id, filename, size")
            .eq("id", file_id)
            .single()
            .execute
        )

        if not fetch_res.data:
            return json_error("File not found", 404)

        file = fetch_res.data

        # ---------------------------
        # HARD DELETE FROM DB
        # ---------------------------
        delete_res = await run_supabase_sync(
            supabase.table("files")
            .delete()
            .eq("id", file_id)
            .execute
        )

        # Verify deletion
        verify_res = await run_supabase_sync(
            supabase.table("files")
            .select("id")
            .eq("id", file_id)
            .execute
        )

        if verify_res.data:
            return json_error("Delete failed: row still exists", 500)

        # ---------------------------
        # Log success
        # ---------------------------
        log_operation(
            "DELETE",
            file_id,
            file["filename"],
            email,
            True,
            f"Size: {file['size']:,}"
        )

        return web.json_response({
            "success": True,
            "message": f"File '{file['filename']}' permanently deleted"
        })

    except Exception as e:
        logger.error("🔥 Hard delete failed", exc_info=True)
        log_operation("DELETE", file_id, user_email=email,
                      success=False, error_message=str(e))
        return json_error("Internal server error", 500)

async def update_file(request):
    try:
        file_id = int(request.match_info.get("file_id"))
    except (TypeError, ValueError):
        return json_error("Invalid file ID", 400)

    try:
        reader = await request.multipart()
        new_content = bytearray()
        new_filename = None
        email = None

        while True:
            part = await reader.next()
            if part is None:
                break

            if part.name == "file":
                new_filename = safe_filename(part.filename)
                async for chunk in part:
                    new_content.extend(chunk)

            elif part.name == "email":
                email = (await part.text()).strip()

        # ---------------------------
        # Validation
        # ---------------------------
        if not email:
            return json_error("Email is required", 400)

        if email != ADMIN_EMAIL:
            log_operation("UPDATE", file_id, user_email=email,
                          success=False, error_message="Unauthorized")
            return json_error("Access denied (admin only)", 403)

        if not new_filename or not new_content:
            return json_error("File is required for update", 400)

        new_size = len(new_content)

        if new_size > MAX_FILE_SIZE:
            return json_error(
                f"File too large. Max {MAX_FILE_SIZE // 1024 // 1024}MB",
                413
            )

        # ---------------------------
        # Fetch existing file (verify exists)
        # ---------------------------
        old_res = await run_supabase_sync(
            supabase.table("files")
            .select("id, filename")
            .eq("id", file_id)
            .single()
            .execute
        )

        if not old_res.data:
            return json_error("File not found", 404)

        # ---------------------------
        # Prepare update data
        # ---------------------------
        new_hash = calculate_file_hash(bytes(new_content))
        file_b64 = base64.b64encode(bytes(new_content)).decode("utf-8")

        update_payload = {
            "filename": new_filename,
            "filetype": Path(new_filename).suffix.lstrip(".").upper() or "FILE",
            "size": new_size,
            "md5_hash": new_hash,
            "last_accessed": datetime.utcnow().isoformat(),
            "file_data": file_b64
        }

        # ---------------------------
        # UPDATE (no assumptions)
        # ---------------------------
        await run_supabase_sync(
            supabase.table("files")
            .update(update_payload)
            .eq("id", file_id)
            .execute
        )

        # ---------------------------
        # VERIFY UPDATE (CRITICAL)
        # ---------------------------
        verify_res = await run_supabase_sync(
            supabase.table("files")
            .select("filename, size, md5_hash")
            .eq("id", file_id)
            .single()
            .execute
        )

        if not verify_res.data:
            return json_error(
                "Update failed: row not found after update",
                500
            )

        if verify_res.data["md5_hash"] != new_hash:
            return json_error(
                "Update blocked by database policy (RLS)",
                403
            )

        # ---------------------------
        # Log success
        # ---------------------------
        log_operation(
            "UPDATE",
            file_id,
            new_filename,
            email,
            True,
            f"Size: {new_size:,} Hash: {new_hash}"
        )

        return web.json_response({
            "success": True,
            "message": f"File '{new_filename}' updated successfully",
            "filename": new_filename,
            "size": new_size,
            "hash": new_hash
        })

    except web.HTTPException:
        raise

    except Exception as e:
        logger.error("🔥 Update failed", exc_info=True)
        log_operation(
            "UPDATE",
            file_id,
            success=False,
            error_message=str(e)
        )
        return json_error("Internal server error", 500)





async def save_url(request):
    try:
        reader = await request.multipart()
        url = None
        title = None
        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == "url":
                url = (await part.text()).strip()
            elif part.name == "title":
                title = (await part.text()).strip()
        
        if not url:
            raise web.HTTPBadRequest(text="url is required")
        
        if not title:
            title = url
        
        # Generate unique short code
        import random
        import string
        max_attempts = 10
        short_code = None
        
        for attempt in range(max_attempts):
            timestamp = str(int(datetime.utcnow().timestamp() * 1000))
            random_part = ''.join(random.choices(string.ascii_letters + string.digits, k=3))
            short_code = hashlib.md5(f"{timestamp}{random_part}".encode()).hexdigest()[:5]
            
            # Check if short_code already exists
            existing = await run_supabase_sync(
                supabase.table('urls')
                .select("id")
                .eq('short_code', short_code)
                .execute
            )
            
            if not existing.data:
                break
            short_code = None
        
        if not short_code:
            raise RuntimeError("Could not generate unique short code after multiple attempts")
        
        # Insert URL
        result = await run_supabase_sync(
            supabase.table('urls')
            .insert({
                "url": url,
                "title": title,
                "short_code": short_code,
                "created_at": datetime.utcnow().isoformat()
            })
            .execute
        )
        
        return web.json_response({
            "success": True,
            "id": result.data[0]["id"],
            "short_code": short_code,
            "message": "URL saved"
        })
    except Exception as e:
        logger.error(f"Save URL error: {e}")
        raise

async def get_urls(request):
    try:
        res = await run_supabase_sync(
            supabase.table('urls')
            .select("id, url, title, short_code, created_at")
            .order('created_at', desc=True)
            .execute
        )
        return web.json_response({
            "success": True,
            "urls": res.data or [],
            "total": len(res.data or [])
        })
    except Exception as e:
        logger.error(f"Get URLs error: {e}")
        raise

async def url_redirect(request):
    """Redirect to the saved URL - this is the endpoint that should redirect"""
    try:
        url_id = int(request.match_info['url_id'])
    except (ValueError, KeyError):
        return web.Response(text="Invalid URL ID", status=400)
    
    try:
        res = await run_supabase_sync(
            supabase.table('urls')
            .select("url")
            .eq('id', url_id)
            .single()
            .execute
        )
        
        if not res.data or not res.data.get('url'):
            return web.Response(text="URL not found", status=404)
        
        target_url = res.data["url"]
        
        # Make sure URL has a scheme (http:// or https://)
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        logger.info(f"Redirecting URL ID {url_id} to {target_url}")
        
        # Return a proper redirect response
        return web.Response(
            status=302,
            headers={'Location': target_url}
        )
        
    except Exception as e:
        logger.error(f"URL redirect error: {e}", exc_info=True)
        return web.Response(text=f"Redirect failed: {str(e)}", status=500)

async def delete_url(request):
    try:
        url_id = int(request.match_info['url_id'])
    except (ValueError, KeyError):
        return json_error("Invalid URL ID", 400)
    
    # FIXED: Try to get email from multiple sources
    email = None
    
    # 1. Try query params first
    email = request.query.get('email', '').strip()
    
    # 2. If not in query, try JSON body
    if not email:
        try:
            data = await request.json()
            email = data.get('email', '').strip()
        except:
            pass
    
    # 3. If not in JSON, try form data
    if not email:
        try:
            post_data = await request.post()
            email = post_data.get('email', '').strip()
        except:
            pass
    
    logger.info(f"Delete URL request for ID {url_id} with email: {email}")
    
    if not email:
        return json_error("Email is required for deletion", 400)
    
    if email != ADMIN_EMAIL:
        logger.warning(f"Unauthorized URL delete attempt by {email} for URL ID {url_id}")
        return json_error(f"Access denied. Only admin ({ADMIN_EMAIL}) can delete URLs.", 403)
    
    try:
        res = await run_supabase_sync(
            supabase.table('urls')
            .select("id, url, title")
            .eq('id', url_id)
            .single()
            .execute
        )
        
        if not res.data:
            return json_error("URL not found", 404)
        
        url_data = res.data
        
        await run_supabase_sync(
            supabase.table('urls')
            .delete()
            .eq('id', url_id)
            .execute
        )
        
        logger.info(f"URL deleted: ID={url_id}, Title='{url_data['title']}', By={email}")
        
        return web.json_response({
            "success": True,
            "message": f"URL '{url_data['title']}' deleted successfully"
        })
    
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete URL failed: {e}", exc_info=True)
        return json_error(f"Failed to delete URL: {str(e)}", 500)


class SessionManager:
    def __init__(self):
        self.sessions = {}
    
    def create_session(self):
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'history': [],
            'file_data': None,
            'file_name': None,
            'file_type': None
        }
        return session_id
    
    def get_session(self, session_id):
        return self.sessions.get(session_id)
    
    def add_to_history(self, session_id, role, content):
        if session_id in self.sessions:
            self.sessions[session_id]['history'].append({
                'role': role,
                'content': content
            })
    
    def set_file_data(self, session_id, file_data, filename, file_type):
        if session_id in self.sessions:
            self.sessions[session_id]['file_data'] = file_data
            self.sessions[session_id]['file_name'] = filename
            self.sessions[session_id]['file_type'] = file_type

session_manager = SessionManager()

def get_mime_type(filename):
    """Get MIME type from filename"""
    ext = filename.lower().split('.')[-1]
    mime_types = {
        'pdf': 'application/pdf',
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'bmp': 'image/bmp',
        'tiff': 'image/tiff',
        'gif': 'image/gif',
        'webp': 'image/webp'
    }
    return mime_types.get(ext, 'application/octet-stream')

def check_pdf_pages(file_data):
    """Check if PDF has more than 2 pages"""
    try:
        pdf_reader = PyPDF2.PdfReader(BytesIO(file_data))
        return len(pdf_reader.pages)
    except:
        return 0

def create_system_prompt():
    """Create system prompt with strict boundaries"""
    return """You are a specialized Q&A assistant with STRICT RULES.

CRITICAL RULES - FOLLOW EXACTLY:
1. ONLY answer questions based on the provided document/image content
2. NEVER provide information from outside the document
3. If asked about question numbers (e.g., "question 5", "Q7", "5th question"):
   - Identify that specific question in the document
   - Explain which option is correct and WHY
   - Provide step-by-step explanation from beginner to advanced level
   - Break down the reasoning clearly

4. For questions NOT in the document (e.g., "Who is the president of USA?"):
   - Respond: "I apologize, but I can only answer questions based on the uploaded document. The information about [topic] is not present in the provided content. Please ask questions related to the document."

5. For greetings/chitchat (hi, hello, how are you):
   - Respond briefly and friendly
   - Remind user you're here to help with the document
   - Example: "Hello! I'm here to help you understand the content in your uploaded document. Feel free to ask any questions about it!"

6. When explaining answers:
   - Start with basic concept (beginner level)
   - Build up to detailed explanation (intermediate)
   - Provide comprehensive reasoning (advanced)
   - Use examples from the document

7. Always reference the specific question/section when answering

REMEMBER: You have NO knowledge beyond the uploaded document. Do not make assumptions or provide external information."""

async def create_session_handler(request):
    """Create a new session"""
    session_id = session_manager.create_session()
    return web.json_response({'session_id': session_id})

async def upload_file_handler(request):
    """Handle file upload"""
    try:
        reader = await request.multipart()
        session_id = None
        file_data = None
        filename = None
        
        async for part in reader:
            if part.name == 'session_id':
                session_id = await part.text()
            elif part.name == 'file':
                filename = part.filename
                file_data = await part.read()
        
        if not session_id or not file_data:
            return web.json_response(
                {'error': 'Missing session_id or file'},
                status=400
            )
        
        session = session_manager.get_session(session_id)
        if not session:
            return web.json_response(
                {'error': 'Invalid session_id'},
                status=404
            )
        
        # Check file type
        mime_type = get_mime_type(filename)
        
        # Check if PDF has more than 2 pages
        if mime_type == 'application/pdf':
            num_pages = check_pdf_pages(file_data)
            if num_pages > 2:
                return web.json_response(
                    {'error': f'PDF has {num_pages} pages. Maximum allowed is 2 pages. Please upload a smaller file.'},
                    status=400
                )
        
        if not (mime_type.startswith('image/') or mime_type == 'application/pdf'):
            return web.json_response(
                {'error': 'Unsupported file type. Use PDF or image files.'},
                status=400
            )
        
        # Convert to base64
        base64_data = base64.b64encode(file_data).decode('utf-8')
        
        # Store file data
        session_manager.set_file_data(session_id, base64_data, filename, mime_type)
        
        return web.json_response({
            'status': 'success',
            'message': f'File "{filename}" uploaded successfully',
            'file_type': mime_type
        })
    
    except Exception as e:
        return web.json_response(
            {'error': f'Upload failed: {str(e)}'},
            status=500
        )

async def query_handler(request):
    """Handle user queries"""
    try:
        data = await request.json()
        session_id = data.get('session_id')
        query = data.get('query')
        
        if not session_id or not query:
            return web.json_response(
                {'error': 'Missing session_id or query'},
                status=400
            )
        
        session = session_manager.get_session(session_id)
        if not session:
            return web.json_response(
                {'error': 'Invalid session_id'},
                status=404
            )
        
        if not session['file_data']:
            return web.json_response(
                {'error': 'No file uploaded in this session. Please upload a file first.'},
                status=400
            )
        
        # Add user query to history
        session_manager.add_to_history(session_id, 'user', query)
        
        # Build messages for Groq API - using simpler format
        messages = [
            {
                'role': 'system',
                'content': create_system_prompt()
            }
        ]
        
        # For Groq, we'll send images directly and PDFs as base64 with a note
        if len(session['history']) == 1:  # First message
            if session['file_type'].startswith('image/'):
                # Send image directly
                messages.append({
                    'role': 'user',
                    'content': [
                        {
                            'type': 'image_url',
                            'image_url': {
                                'url': f"data:{session['file_type']};base64,{session['file_data']}"
                            }
                        },
                        {
                            'type': 'text',
                            'text': query
                        }
                    ]
                })
            else:
                # For PDFs, we need to handle it as text since Groq doesn't support PDF directly
                # We'll extract text from the PDF
                try:
                    pdf_data = base64.b64decode(session['file_data'])
                    pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_data))
                    pdf_text = ""
                    for page_num in range(len(pdf_reader.pages)):
                        page = pdf_reader.pages[page_num]
                        pdf_text += f"Page {page_num + 1}:\n{page.extract_text()}\n\n"
                    
                    messages.append({
                        'role': 'user',
                        'content': f"Document content from {session['file_name']}:\n\n{pdf_text}\n\nUser question: {query}"
                    })
                except:
                    return web.json_response(
                        {'error': 'Failed to process PDF. Please try uploading an image instead.'},
                        status=500
                    )
        else:
            # Handle conversation history
            if session['file_type'].startswith('image/'):
                # First message with image
                messages.append({
                    'role': 'user',
                    'content': [
                        {
                            'type': 'image_url',
                            'image_url': {
                                'url': f"data:{session['file_type']};base64,{session['file_data']}"
                            }
                        },
                        {
                            'type': 'text',
                            'text': session['history'][0]['content']
                        }
                    ]
                })
            else:
                # For PDFs in history
                try:
                    pdf_data = base64.b64decode(session['file_data'])
                    pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_data))
                    pdf_text = ""
                    for page_num in range(len(pdf_reader.pages)):
                        page = pdf_reader.pages[page_num]
                        pdf_text += f"Page {page_num + 1}:\n{page.extract_text()}\n\n"
                    
                    messages.append({
                        'role': 'user',
                        'content': f"Document content from {session['file_name']}:\n\n{pdf_text}\n\nUser question: {session['history'][0]['content']}"
                    })
                except:
                    pass
            
            # Add rest of history
            for msg in session['history'][1:]:
                messages.append({
                    'role': msg['role'],
                    'content': msg['content']
                })
        
        # Call Groq API
        completion = groq_client.chat.completions.create(
            model="meta-llama/llama-4-scout-17b-16e-instruct",  # Use vision model for images
            messages=messages,
            temperature=0.7,
            max_tokens=2048,
            top_p=0.9
        )
        
        response_text = completion.choices[0].message.content
        
        # Add assistant response to history
        session_manager.add_to_history(session_id, 'assistant', response_text)
        
        return web.json_response({
            'response': response_text,
            'file_name': session['file_name']
        })
    
    except Exception as e:
        return web.json_response(
            {'error': f'Query failed: {str(e)}. The AI model may not support this file format. Try uploading an image instead of PDF.'},
            status=500
        )

async def get_history_handler(request):
    """Get conversation history"""
    session_id = request.match_info.get('session_id')
    
    session = session_manager.get_session(session_id)
    if not session:
        return web.json_response(
            {'error': 'Invalid session_id'},
            status=404
        )
    
    return web.json_response({
        'history': session['history'],
        'file_name': session['file_name']
    })

async def clear_history_handler(request):
    """Clear conversation history but keep file"""
    data = await request.json()
    session_id = data.get('session_id')
    
    session = session_manager.get_session(session_id)
    if not session:
        return web.json_response(
            {'error': 'Invalid session_id'},
            status=404
        )
    
    session['history'] = []
    return web.json_response({'status': 'History cleared'})

# CORS middleware
@web.middleware
async def cors_middleware(request, handler):
    if request.method == 'OPTIONS':
        response = web.Response()
    else:
        response = await handler(request)
    
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

async def index_handler(request):
    """Serve the HTML file"""
    try:
        with open('ai.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return web.Response(text=html_content, content_type='text/html')
    except FileNotFoundError:
        return web.Response(text="ai.html file not found!", status=404)


# ────────────────────────────────────────────────
# APP SETUP
# ────────────────────────────────────────────────

def create_app():
    app = web.Application(client_max_size=MAX_FILE_SIZE + 2*1024*1024)
    app.middlewares.append(json_error_middleware)
    app.router.add_get('/ai-boat', index_handler)
    app.router.add_post('/api/session/create', create_session_handler)
    app.router.add_post('/api/uploads', upload_file_handler)
    app.router.add_post('/api/query', query_handler)
    app.router.add_get('/api/history/{session_id}', get_history_handler)
    app.router.add_post('/api/history/clear', clear_history_handler)
    app.router.add_get('/', read_root)
    app.router.add_get('/images', last_read_root)
    app.router.add_get('/api/files', get_files)
    app.router.add_post('/api/upload', upload_file)
    app.router.add_put('/api/files/{file_id}/update', update_file)
    app.router.add_delete('/api/files/{file_id}/delete', delete_file)
    app.router.add_get('/api/files/{file_id}/download', download_file)
    app.router.add_post('/api/save-url', save_url)
    app.router.add_get('/api/urls', get_urls)
    app.router.add_delete('/api/urls/{url_id}/delete', delete_url)
    # This is the redirect endpoint - when visited, it redirects to the saved URL
    app.router.add_get('/api/url/{url_id}', url_redirect)
    logger.info("All routes registered:")
    for r in app.router.routes():
        logger.info(f" {r.method:6} {r.resource.canonical}")
    return app

async def main():
    logger.info("=" * 80)
    logger.info(" FILE MANAGER SERVER - SUPABASE STORAGE ".center(80, "="))
    logger.info(f" Max file size : {MAX_FILE_SIZE//1024//1024} MB")
    logger.info(f" Storage : Supabase PostgreSQL (base64 encoded)")
    logger.info("=" * 80)
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 9000)
    await site.start()
    logger.info("Server running → http://0.0.0.0:9000")
    logger.info("Press Ctrl+C to stop")
    await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)