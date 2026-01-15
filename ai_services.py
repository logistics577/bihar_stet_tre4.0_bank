from aiohttp import web
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

# Create app and routes
app = web.Application(middlewares=[cors_middleware])

# Serve HTML file at root
app.router.add_get('/', index_handler)

# API routes
app.router.add_post('/api/session/create', create_session_handler)
app.router.add_post('/api/upload', upload_file_handler)
app.router.add_post('/api/query', query_handler)
app.router.add_get('/api/history/{session_id}', get_history_handler)
app.router.add_post('/api/history/clear', clear_history_handler)

if __name__ == '__main__':
    print("🚀 Server starting on http://localhost:9001")
    print("📝 Ready to accept file uploads and queries!")
    print("💡 Maximum 2 pages PDF supported!")
    web.run_app(app, host='0.0.0.0', port=9001)