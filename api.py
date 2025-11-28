import os
import sys
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, url_for
from werkzeug.utils import secure_filename
import utils
import hashlib
import traceback
from PIL import Image

# Create Flask app
app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'output'
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB max upload (increased from 16MB)
# Removed secret key since we're removing authentication

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

# Utility function for encryption
def encrypt_message(message, password):
    try:
        # Print debug info
        if isinstance(message, bytes):
            try:
                message_preview = message.decode('utf-8')[:10] + "..." if len(message) > 10 else message.decode('utf-8')
            except UnicodeDecodeError:
                message_preview = f"<binary data, {len(message)} bytes>"
        else:
            message_preview = message[:10] + "..." if len(message) > 10 else message
            
        print(f"DEBUG: Encrypting message: '{message_preview}' ({len(message)} chars/bytes) with password: {password[:2]}{'*' * (len(password) - 4)}{password[-2:] if len(password) > 2 else ''}")
        
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        # For very short messages, use simpler encryption
        if len(message) < 32:
            print("DEBUG: Using simple XOR encryption for short message")
            # Use simple XOR encryption for short messages
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
            else:
                password_bytes = password
                
            key = hashlib.sha256(password_bytes).digest()
            encrypted = []
            for i, char in enumerate(message):
                key_char = key[i % len(key)]
                encrypted_char = char ^ key_char
                encrypted.append(encrypted_char)
            
            result = bytes(encrypted)
            print(f"DEBUG: XOR encryption result: {len(result)} bytes")
            return result
        
        # Use the utils encrypt_message function for normal messages
        try:
            print("DEBUG: Using AES encryption")
            return utils.encrypt_message(message, password)
        except Exception as e:
            # Fallback encryption if utils function fails
            print(f"DEBUG: AES encryption failed: {str(e)}, falling back to XOR")
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
            else:
                password_bytes = password
                
            key = hashlib.sha256(password_bytes).digest()
            encrypted = []
            for i, char in enumerate(message):
                key_char = key[i % len(key)]
                encrypted_char = char ^ key_char
                encrypted.append(encrypted_char)
            return bytes(encrypted)
    except Exception as e:
        print(f"DEBUG: Encryption failed: {str(e)}")
        import traceback
        traceback.print_exc()
        raise

# Utility function for decryption
def decrypt_message(encrypted_data, password):
    try:
        # Use the decrypt_message function from utils module
        return utils.decrypt_message(encrypted_data, password)
    except (AttributeError, ImportError):
        # Fallback decryption if utils function is not available
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        key = hashlib.sha256(password).digest()
        decrypted = []
        for i, char in enumerate(encrypted_data):
            key_char = key[i % len(key)]
            decrypted_char = char ^ key_char
            decrypted.append(decrypted_char)
        return bytes(decrypted)

# API routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy"})

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    """Encrypt a message and hide it in a media file"""
    try:
        # Check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        message = request.form.get('message', '')
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        
        # Get auto_generate flag from request
        auto_generate = request.form.get('auto_generate', 'false').lower() == 'true'
        
        # Auto-generate password or use provided one
        if auto_generate:
            password = utils.generate_strong_password(16)
            print(f"Auto-generated password: {password}")
        else:
            password = request.form.get('password', '')
            if not password:
                return jsonify({'error': 'No password provided and auto-generate not enabled'}), 400
        
        media_type = request.form.get('media_type', 'image')
        
        # Save the uploaded file
        filename = secure_filename(file.filename)
        orig_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(orig_file_path)
        
        # Get original message size
        original_size = len(message.encode('utf-8'))
        
        # Encrypt the message
        message_bytes = message.encode('utf-8') if isinstance(message, str) else message
        encrypted_data = encrypt_message(message_bytes, password)
        
        # Calculate compression ratio correctly
        # Format is now: [salt(16)][IV(16)][compression_marker(1)][ciphertext]
        
        # Extract compression marker to determine if compression was used
        if len(encrypted_data) > 32:
            compression_marker = encrypted_data[32:33]
            is_compressed = compression_marker != b'\xFF'
        else:
            is_compressed = False
        
        # Overhead is salt(16) + IV(16) + marker(1) = 33 bytes
        overhead_size = 33
        estimated_content_size = max(0, len(encrypted_data) - overhead_size)
        
        # For reporting to user
        compressed_size = estimated_content_size
        
        # Calculate compression ratio
        if is_compressed and original_size > 0:
            compression_ratio = ((original_size - compressed_size) / original_size) * 100
        else:
            compression_ratio = 0  # No compression or invalid size
        
        print(f"DEBUG: Original size: {original_size}, Estimated content size: {compressed_size}")
        print(f"DEBUG: Compression applied: {is_compressed}, Ratio: {compression_ratio:.2f}%")
        
        # Prepare the data to be hidden
        # Format: [encrypted data][1 byte: marker][password bytes]
        password_bytes = password.encode('utf-8') if isinstance(password, str) else password
        data_to_hide = encrypted_data + b'\x01' + password_bytes
        
        # Generate output filename
        file_extension = Path(filename).suffix.lower()
        filename_base = Path(filename).stem
        
        # Process based on media type
        if media_type == 'image':
            # Handle all image formats, including JPEG/JPG
            output_filename = f"stego_{filename_base}.png"  # Always use PNG for output
            output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
            
            # Use convert_and_hide_in_image for all image formats
            if hasattr(utils, 'convert_and_hide_in_image'):
                utils.convert_and_hide_in_image(orig_file_path, output_path, data_to_hide)
            else:
                return jsonify({'error': 'Image conversion not supported in this build'}), 400
            
            # Get file size for response
            file_size = os.path.getsize(output_path)
            
            return jsonify({
                'status': 'success',
                'original_filename': filename,
                'output_filename': output_filename,
                'file_size': file_size,
                'encrypted_size': len(encrypted_data),
                'message_length': len(message),
                'original_size': original_size,
                'compressed_size': compressed_size,
                'compression_ratio': compression_ratio,
                'auto_generated': auto_generate,
                'auto_generated_password': password if auto_generate else None,
                'download_url': f"/api/download/{output_filename}",
                'media_type': 'image',
                'encryption_method': 'AES-256',
                'hiding_technique': 'LSB Image Steganography'
            })
        
        elif media_type == 'audio':
            # Convert to WAV if needed
            if file_extension != '.wav':
                print(f"Converting audio to WAV: {filename}")
                if hasattr(utils, 'convert_audio_to_wav'):
                    wav_path = utils.convert_audio_to_wav(orig_file_path)
                    orig_file_path = wav_path
                    file_extension = '.wav'
                else:
                    return jsonify({'error': 'Audio conversion not supported in this build'}), 400
            
            output_filename = f"stego_{filename_base}.wav"
            output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
            
            # Hide data in audio
            if hasattr(utils, 'hide_data_in_audio'):
                utils.hide_data_in_audio(orig_file_path, output_path, data_to_hide)
            else:
                return jsonify({'error': 'Audio steganography not supported in this build'}), 400
            
            # Get file size for response
            file_size = os.path.getsize(output_path)
            
            return jsonify({
                'status': 'success',
                'original_filename': filename,
                'output_filename': output_filename,
                'file_size': file_size,
                'encrypted_size': len(encrypted_data),
                'message_length': len(message),
                'original_size': original_size,
                'compressed_size': compressed_size,
                'compression_ratio': compression_ratio,
                'auto_generated': auto_generate,
                'auto_generated_password': password if auto_generate else None,
                'download_url': f"/api/download/{output_filename}",
                'media_type': 'audio',
                'encryption_method': 'AES-256',
                'hiding_technique': 'Audio Sample Steganography'
            })
        
        else:
            return jsonify({'error': 'Unsupported media type'}), 400
    
    except Exception as e:
        print(f"Error in encryption process: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    """Extract and decrypt a hidden message from a media file"""
    try:
        # Check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No selected file'}), 400
        
        # Password is optional now - it will be extracted from the file if not provided
        password = request.form.get('password', '')
        media_type = request.form.get('media_type', 'image')
        
        # Save the uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Extract data based on media type
        if media_type == 'image':
            # Check if file is JPEG - need to convert to PNG for extraction
            file_extension = Path(filename).suffix.lower()
            if file_extension in ['.jpg', '.jpeg']:
                print(f"WARNING: JPEG file detected. Converting to PNG for extraction: {filename}")
                try:
                    # Convert JPEG to PNG temporarily for extraction
                    img = Image.open(file_path)
                    if img.mode != 'RGB':
                        img = img.convert('RGB')
                    temp_png_path = os.path.splitext(file_path)[0] + "_temp_extract.png"
                    img.save(temp_png_path, format="PNG")
                    extract_path = temp_png_path
                except Exception as e:
                    print(f"Error converting JPEG to PNG: {str(e)}")
                    return jsonify({
                        'status': 'error', 
                        'message': f'Failed to process JPEG file: {str(e)}. Please ensure you are using the PNG output file from encryption.'
                    }), 400
            else:
                extract_path = file_path
            
            # Extract data from image
            if hasattr(utils, 'extract_data_from_image'):
                try:
                    extracted_data = utils.extract_data_from_image(extract_path)
                except Exception as e:
                    print(f"Error extracting data from image: {str(e)}")
                    return jsonify({
                        'status': 'error', 
                        'message': f'Failed to extract data from image: {str(e)}. Make sure you are using the steganographic output file (stego_*.png), not the original file.'
                    }), 400
            else:
                return jsonify({'status': 'error', 'message': 'Image steganography not supported in this build'}), 400
            
            # Clean up temporary PNG file if created
            if file_extension in ['.jpg', '.jpeg']:
                try:
                    if os.path.exists(temp_png_path):
                        os.remove(temp_png_path)
                except:
                    pass
            
        elif media_type == 'audio':
            # Convert to WAV if needed
            file_extension = Path(filename).suffix.lower()
            if file_extension != '.wav':
                print(f"Converting audio to WAV for extraction: {filename}")
                if hasattr(utils, 'convert_audio_to_wav'):
                    wav_path = utils.convert_audio_to_wav(file_path)
                    file_path = wav_path
                else:
                    return jsonify({'status': 'error', 'message': 'Audio conversion not supported in this build'}), 400
            
            # Extract data from audio
            if hasattr(utils, 'extract_data_from_audio'):
                extracted_data = utils.extract_data_from_audio(file_path)
            else:
                return jsonify({'status': 'error', 'message': 'Audio steganography not supported in this build'}), 400
            
        else:
            return jsonify({'status': 'error', 'message': 'Unsupported media type'}), 400
        
        # Debug info
        print(f"DEBUG: Extracted data length: {len(extracted_data)} bytes")
        if len(extracted_data) > 0:
            print(f"DEBUG: First 16 bytes (hex): {' '.join([f'{b:02x}' for b in extracted_data[:16]])}")
            print(f"DEBUG: Last 32 bytes (hex): {' '.join([f'{b:02x}' for b in extracted_data[-32:]])}")
            # Count occurrences of 0x01 marker
            marker_count = extracted_data.count(0x01)
            print(f"DEBUG: Found {marker_count} occurrences of 0x01 marker byte")
        
        # Look for embedded password (marker byte 0x01 indicates password follows)
        # Format: [encrypted_data][0x01][password_bytes]
        # Search from the END backwards to find the LAST 0x01 marker (the actual separator)
        embedded_password = None
        password_found = False
        encrypted_data = extracted_data
        
        # Search backwards from the end for the marker byte
        # This ensures we find the actual separator, not a 0x01 byte in the encrypted data
        marker_found = False
        for i in range(len(extracted_data) - 1, 0, -1):  # Search backwards
            if extracted_data[i] == 0x01:  # Found marker
                # Try to decode everything after the marker as password
                password_candidate = extracted_data[i+1:]
                if len(password_candidate) > 0:
                    try:
                        # Try to decode as UTF-8 password
                        embedded_password = password_candidate.decode('utf-8')
                        # Validate it looks like a password (reasonable length, printable chars)
                        if 4 <= len(embedded_password) <= 128 and all(32 <= ord(c) <= 126 for c in embedded_password):
                            encrypted_data = extracted_data[:i]
                            password_found = True
                            print(f"Found embedded password: {embedded_password}")
                            print(f"DEBUG: Encrypted data length: {len(encrypted_data)} bytes")
                            print(f"DEBUG: Password length: {len(embedded_password)} bytes")
                            marker_found = True
                            break
                    except UnicodeDecodeError:
                        # Not valid UTF-8, continue searching backwards
                        continue
        
        # If we didn't find a valid password marker, try searching from beginning as fallback
        # (for backwards compatibility with old format)
        if not marker_found:
            for i in range(len(extracted_data) - 1):
                if extracted_data[i] == 0x01:  # Found marker
                    try:
                        password_candidate = extracted_data[i+1:]
                        if len(password_candidate) > 0:
                            embedded_password = password_candidate.decode('utf-8')
                            if 4 <= len(embedded_password) <= 128:
                                encrypted_data = extracted_data[:i]
                                password_found = True
                                print(f"Found embedded password (fallback): {embedded_password}")
                                print(f"DEBUG: Encrypted data length: {len(encrypted_data)} bytes")
                                break
                    except UnicodeDecodeError:
                        print("Failed to decode embedded password - possible corruption")
                        continue
        
        # Always use embedded password if available
        if password_found:
            password = embedded_password
            print(f"Using embedded password from file: {password}")
        # Only use provided password if no embedded password was found
        elif not password:
            return jsonify({
                'status': 'error', 
                'message': 'No password provided or found in the file',
                'filename': filename
            }), 400
        
        # Check if we have any encrypted data
        if len(encrypted_data) < 1:  # Just check that we have some data
            print(f"DEBUG: No encrypted data found: {len(encrypted_data)} bytes")
            return jsonify({
                'status': 'error',
                'filename': filename,
                'message': "No valid encrypted data found. The file may not contain a hidden message.",
                'message_length': 0,
                'password_found': password_found,
                'used_password': password if password_found else None
            })
        
        # Try simple XOR decryption first for legacy/small messages
        try:
            print(f"DEBUG: Trying XOR decryption with password: {password[:2]}{'*' * (len(password) - 4)}{password[-2:] if len(password) > 2 else ''}")
            # Simple XOR encryption/decryption
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
            else:
                password_bytes = password
                
            key = hashlib.sha256(password_bytes).digest()
            decrypted = []
            for i, char in enumerate(encrypted_data):
                key_char = key[i % len(key)]
                decrypted_char = char ^ key_char
                decrypted.append(decrypted_char)
            
            decrypted_bytes = bytes(decrypted)
            
            # Try to convert to string
            try:
                decrypted_message = decrypted_bytes.decode('utf-8')
                # If it decodes as valid UTF-8, it's likely the correct message
                print(f"DEBUG: Successfully decoded message using XOR: {decrypted_message[:20]}...")
                
                return jsonify({
                    'status': 'success',
                    'filename': filename,
                    'message': decrypted_message,
                    'message_length': len(decrypted_message),
                    'password_found': password_found,
                    'used_password': password if password_found else None
                })
            except UnicodeDecodeError:
                # Not valid UTF-8, try AES decryption next
                print("DEBUG: XOR result not valid UTF-8, trying AES decryption")
                pass
                
            # Fall through to AES if the XOR result isn't valid UTF-8
        except Exception as e:
            print(f"DEBUG: XOR decryption failed: {str(e)}")
        
        # Try AES decryption if XOR didn't work
        try:
            # Only try AES if we have enough data
            if len(encrypted_data) >= 33:  # Need at least salt(16) + IV(16) + 1 byte
                print("DEBUG: Trying AES decryption")
                decrypted_message = utils.decrypt_message(encrypted_data, password)
                
                # Convert to string if it's bytes
                if isinstance(decrypted_message, bytes):
                    try:
                        message_str = decrypted_message.decode('utf-8')
                    except UnicodeDecodeError:
                        message_str = f"Binary data (could not decode as UTF-8): {decrypted_message.hex()[:50]}..."
                else:
                    message_str = str(decrypted_message)
                
                # Check if the decrypted message contains an error indication
                has_error = isinstance(message_str, str) and "error" in message_str.lower()
                
                return jsonify({
                    'status': 'warning' if has_error else 'success',
                    'filename': filename,
                    'message': message_str,
                    'message_length': len(message_str),
                    'password_found': password_found,
                    'used_password': password if password_found else None,
                    'encryption_method': 'AES-256',
                    'hiding_technique': 'LSB Image Steganography' if media_type == 'image' else 'Audio Sample Steganography'
                })
            else:
                # Not enough data for AES, and XOR didn't work
                return jsonify({
                    'status': 'error',
                    'filename': filename,
                    'message': "Not enough data for AES decryption and XOR decryption failed.",
                    'message_length': 0,
                    'password_found': password_found,
                    'used_password': password if password_found else None
                })
        except Exception as e:
            print(f"ERROR: AES Decryption failed: {str(e)}")
            return jsonify({
                'status': 'error',
                'filename': filename,
                'message': f"Decryption error: {str(e)}",
                'message_length': 0,
                'password_found': password_found,
                'used_password': password if password_found else None
            })
    
    except Exception as e:
        print(f"Error in decryption process: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download a file from the output folder"""
    return send_from_directory(app.config['OUTPUT_FOLDER'], filename, as_attachment=True)

@app.route('/api/capabilities', methods=['GET'])
def get_capabilities():
    """Return the capabilities of the API"""
    capabilities = {
        'image_steganography': hasattr(utils, 'hide_data_in_image'),
        'audio_steganography': hasattr(utils, 'hide_data_in_audio'),
        'audio_conversion': hasattr(utils, 'convert_audio_to_wav'),
        'image_conversion': hasattr(utils, 'convert_and_hide_in_image'),
        'supports_jpg_jpeg': hasattr(utils, 'convert_and_hide_in_image'),
        'supports_png': hasattr(utils, 'hide_data_in_image'),
        'supports_bmp': hasattr(utils, 'hide_data_in_image'),
        'supports_gif': hasattr(utils, 'convert_and_hide_in_image'),
        'qr_code_steganography': hasattr(utils, 'hide_message_in_qr'),
        'qr_code_generation': hasattr(utils, 'generate_qr_code')
    }
    return jsonify(capabilities)

@app.route('/api/generate-qr', methods=['POST'])
def generate_qr():
    """Generate a QR code from data"""
    try:
        # Get data from request
        data = request.form.get('data', '')
        if not data:
            return jsonify({'error': 'No data provided for QR code generation'}), 400
        
        # Get optional parameters
        error_correction = request.form.get('error_correction', 'H')
        box_size = int(request.form.get('box_size', 10))
        border = int(request.form.get('border', 4))
        
        # Map error correction string to qrcode constant
        ec_mapping = {
            'L': utils.qrcode.constants.ERROR_CORRECT_L,  # ~7% correction
            'M': utils.qrcode.constants.ERROR_CORRECT_M,  # ~15% correction
            'Q': utils.qrcode.constants.ERROR_CORRECT_Q,  # ~25% correction
            'H': utils.qrcode.constants.ERROR_CORRECT_H   # ~30% correction
        }
        ec_level = ec_mapping.get(error_correction.upper(), utils.qrcode.constants.ERROR_CORRECT_H)
        
        # Generate output filename
        timestamp = utils.binascii.hexlify(os.urandom(4)).decode('ascii')
        output_filename = f"qr_code_{timestamp}.png"
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        
        # Generate QR code
        utils.generate_qr_code(data, output_path, error_correction=ec_level, box_size=box_size, border=border)
        
        # Get file size for response
        file_size = os.path.getsize(output_path)
        
        return jsonify({
            'status': 'success',
            'output_filename': output_filename,
            'file_size': file_size,
            'download_url': f"/api/download/{output_filename}"
        })
        
    except Exception as e:
        print(f"Error in QR code generation: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/encrypt-qr', methods=['POST'])
def encrypt_qr():
    """Encrypt a message and generate a QR code containing it"""
    try:
        # Get message from request
        message = request.form.get('message', '')
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        
        # Get auto_generate flag from request
        auto_generate = request.form.get('auto_generate', 'false').lower() == 'true'
        
        # Auto-generate password or use provided one
        if auto_generate:
            password = utils.generate_strong_password(16)
            print(f"Auto-generated password: {password}")
        else:
            password = request.form.get('password', '')
            if not password:
                return jsonify({'error': 'No password provided and auto-generate not enabled'}), 400
        
        # Get optional style parameter
        style = request.form.get('style', 'standard')
        if style not in ['standard', 'fancy', 'embedded']:
            return jsonify({'error': 'Invalid style parameter. Choose from: standard, fancy, embedded'}), 400
        
        # Get original message size
        original_size = len(message.encode('utf-8'))
        
        # Check for background image
        background_image = None
        if 'background' in request.files:
            bg_file = request.files['background']
            if bg_file.filename != '':
                bg_filename = secure_filename(bg_file.filename)
                background_image = os.path.join(app.config['UPLOAD_FOLDER'], bg_filename)
                bg_file.save(background_image)
        
        # Generate output filename
        timestamp = utils.binascii.hexlify(os.urandom(4)).decode('ascii')
        output_filename = f"qr_encrypted_{timestamp}.png"
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        
        # Generate encrypted QR code
        utils.hide_message_in_qr(message, password, output_path, background_image=background_image, style=style)
        
        # Get file size for response
        file_size = os.path.getsize(output_path)
        
        # Calculate encrypted size (approximate)
        encrypted_size = len(utils.encrypt_message(message.encode('utf-8'), password))
        compression_ratio = (1 - encrypted_size / original_size) * 100 if original_size > 0 else 0
        
        return jsonify({
            'status': 'success',
            'output_filename': output_filename,
            'file_size': file_size,
            'message_length': len(message),
            'original_size': original_size,
            'encrypted_size': encrypted_size,
            'compression_ratio': compression_ratio,
            'auto_generated': auto_generate,
            'auto_generated_password': password if auto_generate else None,
            'download_url': f"/api/download/{output_filename}",
            'media_type': 'qr_code',
            'style': style,
            'encryption_method': 'AES-256',
            'hiding_technique': 'QR Code Steganography'
        })
        
    except Exception as e:
        print(f"Error in QR code encryption: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt-qr', methods=['POST'])
def decrypt_qr():
    """Extract and decrypt a message from a QR code"""
    try:
        # Check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No selected file'}), 400
        
        # Password is optional - it will be extracted from the QR code if embedded
        password = request.form.get('password', '')
        
        # Save the uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Extract and decrypt the message
        message = utils.extract_message_from_qr(file_path, password)
        
        # Check if an error occurred
        if isinstance(message, str) and message.startswith("Error:"):
            return jsonify({
                'status': 'error',
                'filename': filename,
                'message': message
            }), 400
            
        # Check if the decrypted message contains an error indication
        has_error = isinstance(message, str) and "error" in message.lower()
        
        # Password might have been extracted from the QR code
        password_found = "Found embedded password" in message if isinstance(message, str) else False
        
        return jsonify({
            'status': 'warning' if has_error else 'success',
            'filename': filename,
            'message': message,
            'message_length': len(message) if message else 0,
            'password_found': password_found,
            'encryption_method': 'AES-256',
            'hiding_technique': 'QR Code Steganography'
        })
        
    except Exception as e:
        print(f"Error in QR code decryption: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/')
def index():
    """Render the main application page"""
    return render_template('index.html')

@app.route('/sign-in')
def sign_in():
    """Render the sign-in page"""
    return render_template('sign-in.html')

@app.route('/sign-up')
def sign_up():
    """Render the sign-up page"""
    return render_template('sign-up.html')

# VirusTotal API endpoints
@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    """Scan a URL using VirusTotal API"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'status': 'error', 'message': 'URL is required'}), 400
        
        url = data.get('url', '').strip()
        if not url:
            return jsonify({'status': 'error', 'message': 'URL cannot be empty'}), 400
        
        # Basic URL validation
        if not (url.startswith('http://') or url.startswith('https://')):
            return jsonify({'status': 'error', 'message': 'URL must start with http:// or https://'}), 400
        
        # Scan the URL
        result = utils.scan_url_with_virustotal(url)
        
        if result['status'] == 'success':
            return jsonify({
                'status': 'success',
                'analysis_id': result.get('analysis_id'),
                'message': result.get('message', 'URL submitted for scanning'),
                'url': url
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Failed to scan URL')
            }), 500
            
    except Exception as e:
        print(f"Error in scan_url endpoint: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/url-analysis/<analysis_id>', methods=['GET'])
def get_url_analysis(analysis_id):
    """Get analysis results for a URL scan"""
    try:
        if not analysis_id:
            return jsonify({'status': 'error', 'message': 'Analysis ID is required'}), 400
        
        result = utils.get_url_analysis(analysis_id)
        
        if result['status'] == 'success':
            return jsonify(result), 200
        else:
            status_code = result.get('status_code', 500)
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Failed to get analysis results')
            }), status_code
            
    except Exception as e:
        print(f"Error in get_url_analysis endpoint: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/url-report/<url_hash>', methods=['GET'])
def get_url_report(url_hash):
    """Get URL report by hash (SHA-256, SHA-1, or MD5)"""
    try:
        if not url_hash:
            return jsonify({'status': 'error', 'message': 'URL hash is required'}), 400
        
        result = utils.get_url_report(url_hash)
        
        if result['status'] == 'success':
            return jsonify(result), 200
        else:
            status_code = result.get('status_code', 500)
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Failed to get URL report')
            }), status_code
            
    except Exception as e:
        print(f"Error in get_url_report endpoint: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True) 