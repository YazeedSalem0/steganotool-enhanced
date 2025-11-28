# SteganoTool Enhanced - Technical Report

## Executive Summary

SteganoTool Enhanced is a comprehensive steganography application that enables secure message hiding within digital media files. The system combines advanced encryption techniques (AES-256-CBC) with Least Significant Bit (LSB) steganography to provide a robust solution for covert data transmission. The application supports multiple media types including images (PNG, JPG, BMP), audio files (WAV), and QR codes, with both web-based and command-line interfaces.

**Version:** 1.0  
**Date:** 2024  
**Technology Stack:** Python 3.8+, Flask, PyCryptodome, Pillow, OpenCV

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Core Functionalities](#3-core-functionalities)
4. [Technical Flows](#4-technical-flows)
5. [Security Architecture](#5-security-architecture)
6. [API Design](#6-api-design)
7. [Data Formats](#7-data-formats)
8. [Implementation Details](#8-implementation-details)

---

## 1. Project Overview

### 1.1 Purpose

SteganoTool Enhanced provides a secure platform for hiding encrypted messages within digital media files. The application ensures that hidden data remains undetectable while maintaining the visual/audible integrity of carrier files.

### 1.2 Key Features

- **Multi-Media Support**: Images (PNG, JPG, BMP), Audio (WAV), and QR Codes
- **Strong Encryption**: AES-256-CBC with PBKDF2 key derivation
- **Data Compression**: Automatic zlib compression for efficiency
- **Password Management**: Auto-generation or custom passwords with optional embedding
- **Dual Interface**: Web-based GUI and command-line client
- **Format Conversion**: Automatic conversion between formats for optimal steganography
- **VirusTotal Integration**: URL security scanning capabilities

### 1.3 Technology Stack

| Component | Technology |
|-----------|-----------|
| Backend Framework | Flask 2.2.3 |
| Encryption Library | PyCryptodome 3.17.0 |
| Image Processing | Pillow 9.4.0, NumPy 1.24.2, OpenCV 4.7.0.72 |
| QR Code Generation | qrcode 8.0.0, pyzbar 0.1.9 |
| Audio Processing | wave, FFmpeg |
| Compression | zlib |
| Web Interface | Bootstrap 5, JavaScript |

---

## 2. System Architecture

### 2.1 High-Level Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        WEB[Web Browser]
        CLI[Command Line Client]
    end
    
    subgraph "Application Layer"
        API[Flask API Server]
        ROUTES[API Routes]
        TEMPLATES[HTML Templates]
    end
    
    subgraph "Business Logic Layer"
        ENCRYPT[Encryption Module]
        STEGANO[Steganography Module]
        COMPRESS[Compression Module]
        QR[QR Code Module]
    end
    
    subgraph "Data Layer"
        UPLOAD[Upload Directory]
        OUTPUT[Output Directory]
        CACHE[Cache/Temp Files]
    end
    
    subgraph "External Services"
        VT[VirusTotal API]
        FFMPEG[FFmpeg Converter]
    end
    
    WEB --> API
    CLI --> API
    API --> ROUTES
    ROUTES --> ENCRYPT
    ROUTES --> STEGANO
    ROUTES --> QR
    ENCRYPT --> COMPRESS
    STEGANO --> UPLOAD
    STEGANO --> OUTPUT
    QR --> OUTPUT
    API --> VT
    STEGANO --> FFMPEG
```

### 2.2 Component Architecture

```mermaid
graph LR
    subgraph "Core Modules"
        UTILS[utils.py<br/>Core Functions]
        API_MOD[api.py<br/>API Endpoints]
        CLIENT[client.py<br/>CLI Interface]
    end
    
    subgraph "Utils Module Functions"
        ENC_FUNC[encrypt_message<br/>decrypt_message]
        COMP_FUNC[compress_data<br/>decompress_data]
        IMG_FUNC[hide_data_in_image<br/>extract_data_from_image]
        AUD_FUNC[hide_data_in_audio<br/>extract_data_from_audio]
        QR_FUNC[generate_qr_code<br/>hide_message_in_qr<br/>extract_message_from_qr]
        VT_FUNC[scan_url_with_virustotal<br/>get_url_analysis]
    end
    
    API_MOD --> UTILS
    CLIENT --> API_MOD
    UTILS --> ENC_FUNC
    UTILS --> COMP_FUNC
    UTILS --> IMG_FUNC
    UTILS --> AUD_FUNC
    UTILS --> QR_FUNC
    UTILS --> VT_FUNC
```

---

## 3. Core Functionalities

### 3.1 Encryption & Decryption

The system implements a dual-encryption strategy:
- **Short messages (<32 bytes)**: XOR encryption with SHA-256 key derivation
- **Standard messages**: AES-256-CBC encryption with PBKDF2 key derivation

### 3.2 Steganography Techniques

- **LSB (Least Significant Bit)**: Primary technique for images and audio
- **QR Code Encoding**: Direct data encoding in QR code structure
- **Multi-channel embedding**: Data distributed across RGB channels for images

### 3.3 Media Processing

- **Image Processing**: Automatic format conversion (JPG→PNG), RGB normalization
- **Audio Processing**: Format conversion to WAV, sample-based embedding
- **QR Code Processing**: Generation with multiple styles, background image support

---

## 4. Technical Flows

### 4.1 Overall Encryption & Hiding Flow

```mermaid
flowchart TD
    START([User Input:<br/>Message + Carrier File + Password]) --> VALIDATE{Validate Inputs}
    VALIDATE -->|Invalid| ERROR1[Return Error]
    VALIDATE -->|Valid| ENCODE[Encode Message to UTF-8 Bytes]
    
    ENCODE --> COMPRESS{Compress Data?}
    COMPRESS -->|Size Reduced| COMP_DATA[Compressed Data + Marker 0x00]
    COMPRESS -->|Size Increased| NO_COMP[Original Data + Marker 0xFF]
    
    COMP_DATA --> ENCRYPT
    NO_COMP --> ENCRYPT
    
    ENCRYPT[Encrypt with AES-256-CBC] --> DERIVE[Derive Key via PBKDF2]
    DERIVE --> GEN_IV[Generate Random IV]
    GEN_IV --> ENC_DATA[Encrypted Data Format:<br/>Salt + IV + Marker + Ciphertext]
    
    ENC_DATA --> PACKAGE[Package Data:<br/>Encrypted Data + 0x01 + Password]
    
    PACKAGE --> MEDIA_TYPE{Media Type?}
    
    MEDIA_TYPE -->|Image| IMG_CONVERT[Convert to PNG/RGB]
    MEDIA_TYPE -->|Audio| AUD_CONVERT[Convert to WAV]
    MEDIA_TYPE -->|QR Code| QR_GEN[Generate QR Code]
    
    IMG_CONVERT --> IMG_LSB[LSB Embedding in Pixels]
    AUD_CONVERT --> AUD_LSB[LSB Embedding in Samples]
    QR_GEN --> QR_ENCODE[Encode in QR Structure]
    
    IMG_LSB --> SAVE[Save Output File]
    AUD_LSB --> SAVE
    QR_ENCODE --> SAVE
    
    SAVE --> RESPONSE[Return Success Response<br/>with Download URL]
    RESPONSE --> END([End])
    
    ERROR1 --> END
```

### 4.2 Decryption & Extraction Flow

```mermaid
flowchart TD
    START([User Input:<br/>Stego File + Optional Password]) --> UPLOAD[Upload File]
    UPLOAD --> MEDIA_TYPE{Media Type?}
    
    MEDIA_TYPE -->|Image| IMG_LOAD[Load Image as NumPy Array]
    MEDIA_TYPE -->|Audio| AUD_LOAD[Load Audio Samples]
    MEDIA_TYPE -->|QR Code| QR_READ[Read QR Code Data]
    
    IMG_LOAD --> IMG_EXTRACT[Extract LSB from Pixels]
    AUD_LOAD --> AUD_EXTRACT[Extract LSB from Samples]
    QR_READ --> QR_DECODE[Decode Hex Data]
    
    IMG_EXTRACT --> PARSE[Parse Data Format]
    AUD_EXTRACT --> PARSE
    QR_DECODE --> PARSE
    
    PARSE --> FIND_MARKER{Find 0x01 Marker?}
    
    FIND_MARKER -->|Found| EMBED_PASS[Use Embedded Password]
    FIND_MARKER -->|Not Found| USER_PASS{User Password<br/>Provided?}
    
    USER_PASS -->|Yes| USE_USER[Use User Password]
    USER_PASS -->|No| ERROR1[Return Error:<br/>No Password]
    
    EMBED_PASS --> EXTRACT_ENC[Extract Encrypted Data]
    USE_USER --> EXTRACT_ENC
    
    EXTRACT_ENC --> CHECK_MARKER{Check Compression<br/>Marker}
    
    CHECK_MARKER -->|0x00| COMPRESSED[Data is Compressed]
    CHECK_MARKER -->|0xFF| UNCOMPRESSED[Data Not Compressed]
    
    COMPRESSED --> DECRYPT[Decrypt with AES-256-CBC]
    UNCOMPRESSED --> DECRYPT
    
    DECRYPT --> DERIVE_KEY[Derive Key from Password + Salt]
    DERIVE_KEY --> DECRYPT_DATA[Decrypt Ciphertext]
    
    DECRYPT_DATA --> CHECK_COMP{Compression<br/>Marker?}
    
    CHECK_COMP -->|0x00| DECOMPRESS[Decompress with zlib]
    CHECK_COMP -->|0xFF| SKIP_DECOMP[Skip Decompression]
    
    DECOMPRESS --> DECODE[Decode UTF-8]
    SKIP_DECOMP --> DECODE
    
    DECODE --> VALIDATE{Valid UTF-8?}
    
    VALIDATE -->|Yes| SUCCESS[Return Decrypted Message]
    VALIDATE -->|No| TRY_XOR[Try XOR Decryption<br/>for Legacy Messages]
    
    TRY_XOR --> XOR_DECRYPT[XOR Decrypt]
    XOR_DECRYPT --> XOR_VALID{Valid UTF-8?}
    
    XOR_VALID -->|Yes| SUCCESS
    XOR_VALID -->|No| ERROR2[Return Error:<br/>Decryption Failed]
    
    SUCCESS --> END([End])
    ERROR1 --> END
    ERROR2 --> END
```

### 4.3 Image Steganography Flow

```mermaid
sequenceDiagram
    participant User
    participant API
    participant Utils
    participant PIL
    participant NumPy
    
    User->>API: Upload Image + Message + Password
    API->>Utils: encrypt_message(message, password)
    Utils->>Utils: compress_data(message)
    Utils->>Utils: derive_key(password)
    Utils->>Utils: AES-256-CBC encrypt
    Utils-->>API: encrypted_data
    
    API->>Utils: convert_and_hide_in_image(input, output, data)
    Utils->>PIL: Image.open(input_path)
    PIL-->>Utils: Image object
    Utils->>PIL: Convert to RGB mode
    Utils->>PIL: Save as temporary PNG
    PIL-->>Utils: temp_png_path
    
    Utils->>Utils: hide_data_in_image(temp_png, output, data)
    Utils->>PIL: Image.open(temp_png)
    Utils->>NumPy: Convert to NumPy array
    NumPy-->>Utils: img_array
    
    Utils->>Utils: Convert data to binary string
    Utils->>Utils: Embed bits in LSB of pixels
    Utils->>NumPy: Modify array values
    Utils->>PIL: Create Image from array
    Utils->>PIL: Save as PNG
    
    Utils-->>API: output_path
    API-->>User: Success + Download URL
```

### 4.4 Audio Steganography Flow

```mermaid
sequenceDiagram
    participant User
    participant API
    participant Utils
    participant Wave
    participant FFmpeg
    
    User->>API: Upload Audio + Message + Password
    API->>Utils: encrypt_message(message, password)
    Utils-->>API: encrypted_data
    
    API->>Utils: hide_data_in_audio(input, output, data)
    
    alt Audio is not WAV
        Utils->>FFmpeg: convert_audio_to_wav(input)
        FFmpeg-->>Utils: wav_path
    end
    
    Utils->>Wave: wave.open(audio_path, 'rb')
    Wave-->>Utils: Audio parameters + frames
    
    Utils->>Utils: Convert data to binary string
    Utils->>Utils: Embed bits in LSB of audio samples
    Utils->>Wave: Create new WAV file
    Utils->>Wave: Write modified frames
    
    Utils-->>API: output_path
    API-->>User: Success + Download URL
```

### 4.5 QR Code Steganography Flow

```mermaid
flowchart TD
    START([Message + Password + Style]) --> ENCRYPT[Encrypt Message]
    ENCRYPT --> PACKAGE[Package:<br/>Encrypted Data + 0x01 + Password]
    PACKAGE --> HEX[Convert to Hex String]
    
    HEX --> QR_CREATE[Create QRCode Instance]
    QR_CREATE --> QR_ADD[Add Hex Data to QR]
    QR_ADD --> QR_MAKE[Make QR Code]
    
    QR_MAKE --> STYLE{Style Type?}
    
    STYLE -->|Standard| STD_IMG[Black/White Image]
    STYLE -->|Fancy| FANCY_IMG[Colored Image]
    STYLE -->|Embedded| EMBED_IMG[Low Contrast Image]
    
    STD_IMG --> BG_CHECK{Background<br/>Image?}
    FANCY_IMG --> BG_CHECK
    EMBED_IMG --> BG_CHECK
    
    BG_CHECK -->|Yes| LOAD_BG[Load Background Image]
    BG_CHECK -->|No| SAVE_QR[Save QR Code]
    
    LOAD_BG --> RESIZE[Resize to Match QR]
    RESIZE --> BLEND{Style?}
    
    BLEND -->|Embedded| ALPHA_BLEND[Alpha Blend 70%]
    BLEND -->|Other| PASTE[Paste QR on Background]
    
    ALPHA_BLEND --> SAVE_QR
    PASTE --> SAVE_QR
    
    SAVE_QR --> END([QR Code with Hidden Message])
```

### 4.6 API Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant Flask
    participant API_Route
    participant Utils
    participant FileSystem
    
    Client->>Flask: POST /api/encrypt
    Flask->>API_Route: encrypt()
    
    API_Route->>API_Route: Validate request
    API_Route->>FileSystem: Save uploaded file
    
    API_Route->>Utils: encrypt_message(message, password)
    Utils-->>API_Route: encrypted_data
    
    API_Route->>Utils: hide_data_in_image/audio()
    Utils->>FileSystem: Process file
    Utils-->>API_Route: output_path
    
    API_Route->>FileSystem: Get file metadata
    API_Route->>API_Route: Build response JSON
    API_Route-->>Flask: JSON response
    Flask-->>Client: HTTP 200 + JSON
    
    Note over Client,FileSystem: Download via GET /api/download/<filename>
```

### 4.7 Data Format Structure

```mermaid
graph TB
    subgraph "Encrypted Data Format"
        SALT[Salt: 16 bytes<br/>Random for PBKDF2]
        IV[IV: 16 bytes<br/>Random for AES-CBC]
        MARKER[Compression Marker: 1 byte<br/>0x00 = Compressed<br/>0xFF = Not Compressed]
        CIPHER[Ciphertext: Variable<br/>Padded AES-256-CBC]
    end
    
    subgraph "Packaged Data Format"
        ENC_DATA[Encrypted Data<br/>Salt + IV + Marker + Ciphertext]
        SEP[Separator: 0x01<br/>1 byte marker]
        PASSWORD[Password: Variable<br/>UTF-8 encoded]
    end
    
    subgraph "Binary Embedding Format"
        BINARY[Binary String<br/>8 bits per byte]
        TERMINATOR[Terminator: 00000000<br/>8 bits null byte]
    end
    
    SALT --> IV
    IV --> MARKER
    MARKER --> CIPHER
    CIPHER --> ENC_DATA
    ENC_DATA --> SEP
    SEP --> PASSWORD
    PASSWORD --> BINARY
    BINARY --> TERMINATOR
```

---

## 5. Security Architecture

### 5.1 Encryption Security

```mermaid
graph LR
    subgraph "Key Derivation"
        PASS[Password] --> PBKDF2[PBKDF2-HMAC-SHA256<br/>100,000 iterations]
        SALT[Random Salt<br/>16 bytes] --> PBKDF2
        PBKDF2 --> KEY[AES-256 Key<br/>32 bytes]
    end
    
    subgraph "Encryption Process"
        KEY --> AES[AES-256-CBC]
        IV[Random IV<br/>16 bytes] --> AES
        DATA[Plaintext Data] --> AES
        AES --> CIPHER[Ciphertext]
    end
    
    subgraph "Security Features"
        FEAT1[Strong Key Derivation]
        FEAT2[Random IV per Message]
        FEAT3[Compression for Efficiency]
        FEAT4[Password Embedding Option]
    end
```

### 5.2 Steganography Security

- **LSB Technique**: Minimal visual/audible impact
- **Multi-channel Distribution**: Data spread across RGB channels
- **Format Preservation**: Output maintains original format characteristics
- **Capacity Validation**: System checks if carrier can hold data before processing

---

## 6. API Design

### 6.1 API Endpoints

```mermaid
graph TB
    subgraph "Core Endpoints"
        E1[POST /api/encrypt<br/>Encrypt & Hide Message]
        E2[POST /api/decrypt<br/>Extract & Decrypt Message]
        E3[GET /api/download/<filename><br/>Download Processed File]
        E4[GET /api/capabilities<br/>Get System Capabilities]
        E5[GET /api/health<br/>Health Check]
    end
    
    subgraph "QR Code Endpoints"
        QR1[POST /api/generate-qr<br/>Generate QR Code]
        QR2[POST /api/encrypt-qr<br/>Encrypt & Generate QR]
        QR3[POST /api/decrypt-qr<br/>Extract from QR]
    end
    
    subgraph "Security Endpoints"
        VT1[POST /api/scan-url<br/>Scan URL with VirusTotal]
        VT2[GET /api/url-analysis/<id><br/>Get Analysis Results]
        VT3[GET /api/url-report/<hash><br/>Get URL Report]
    end
    
    subgraph "Web Pages"
        W1[GET /<br/>Main Page]
        W2[GET /sign-in<br/>Sign In Page]
        W3[GET /sign-up<br/>Sign Up Page]
    end
```

### 6.2 Request/Response Flow

```mermaid
graph LR
    subgraph "Encrypt Request"
        REQ1[file: multipart/form-data]
        REQ2[message: text]
        REQ3[password: text]
        REQ4[auto_generate: boolean]
        REQ5[media_type: enum]
    end
    
    subgraph "Encrypt Response"
        RES1[status: success]
        RES2[output_filename: string]
        RES3[download_url: string]
        RES4[compression_ratio: float]
        RES5[encrypted_size: int]
        RES6[auto_generated_password: string]
    end
    
    REQ1 --> RES1
    REQ2 --> RES1
    REQ3 --> RES1
    REQ4 --> RES1
    REQ5 --> RES1
```

---

## 7. Data Formats

### 7.1 Encrypted Data Structure

```
┌─────────────────────────────────────────────────────────────┐
│ Encrypted Data Format (Variable Length)                     │
├─────────────────────────────────────────────────────────────┤
│ Salt (16 bytes)          │ Random salt for PBKDF2           │
├─────────────────────────────────────────────────────────────┤
│ IV (16 bytes)            │ Random IV for AES-CBC             │
├─────────────────────────────────────────────────────────────┤
│ Compression Marker (1)   │ 0x00 = Compressed, 0xFF = Not    │
├─────────────────────────────────────────────────────────────┤
│ Ciphertext (Variable)    │ AES-256-CBC encrypted data       │
│                          │ (PKCS7 padded)                   │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Packaged Data Structure

```
┌─────────────────────────────────────────────────────────────┐
│ Packaged Data Format (For Embedding)                        │
├─────────────────────────────────────────────────────────────┤
│ Encrypted Data (Variable) │ Salt + IV + Marker + Ciphertext │
├─────────────────────────────────────────────────────────────┤
│ Separator (1 byte)        │ 0x01 marker byte                │
├─────────────────────────────────────────────────────────────┤
│ Password (Variable)      │ UTF-8 encoded password          │
│                          │ (Optional, if auto-generated)    │
└─────────────────────────────────────────────────────────────┘
```

### 7.3 Binary Embedding Format

```
┌─────────────────────────────────────────────────────────────┐
│ Binary String Format (For LSB Embedding)                    │
├─────────────────────────────────────────────────────────────┤
│ Bit Stream (Variable)    │ Each byte converted to 8 bits    │
│                          │ Bits embedded in LSB positions   │
├─────────────────────────────────────────────────────────────┤
│ Terminator (8 bits)       │ 00000000 (null byte)            │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. Implementation Details

### 8.1 Key Algorithms

#### Encryption Algorithm
- **Algorithm**: AES-256-CBC
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Padding**: PKCS7
- **IV Generation**: Cryptographically secure random (16 bytes)

#### Compression Algorithm
- **Method**: zlib (level 9 - maximum compression)
- **Conditional**: Only applied if size reduction achieved
- **Marker**: 0x00 (compressed) or 0xFF (not compressed)

#### Steganography Algorithm
- **Method**: Least Significant Bit (LSB)
- **Distribution**: Sequential embedding across channels
- **Termination**: Null byte (0x00) terminator

### 8.2 File Processing Pipeline

```mermaid
graph TB
    INPUT[Input File] --> DETECT{Detect Format}
    
    DETECT -->|Image| IMG_CHECK{Format?}
    DETECT -->|Audio| AUD_CHECK{Format?}
    
    IMG_CHECK -->|PNG/BMP| IMG_READY[Ready for Processing]
    IMG_CHECK -->|JPG/JPEG| IMG_CONVERT[Convert to PNG]
    IMG_CONVERT --> IMG_READY
    
    AUD_CHECK -->|WAV| AUD_READY[Ready for Processing]
    AUD_CHECK -->|Other| AUD_CONVERT[Convert to WAV via FFmpeg]
    AUD_CONVERT --> AUD_READY
    
    IMG_READY --> PROCESS[Process with LSB]
    AUD_READY --> PROCESS
    
    PROCESS --> OUTPUT[Output File]
```

### 8.3 Error Handling Strategy

```mermaid
graph TD
    OPERATION[Operation] --> VALIDATE{Validation}
    VALIDATE -->|Pass| PROCESS[Process]
    VALIDATE -->|Fail| ERROR1[Return 400 Bad Request]
    
    PROCESS --> CHECK{Check Capacity}
    CHECK -->|Sufficient| EMBED[Embed Data]
    CHECK -->|Insufficient| ERROR2[Return 400:<br/>Data Too Large]
    
    EMBED --> SAVE{Save File}
    SAVE -->|Success| SUCCESS[Return 200 Success]
    SAVE -->|Failure| ERROR3[Return 500<br/>Server Error]
    
    PROCESS --> EXCEPT{Exception?}
    EXCEPT -->|Yes| LOG[Log Error]
    LOG --> ERROR3
    EXCEPT -->|No| SUCCESS
```

---

## 9. Performance Considerations

### 9.1 Processing Times

- **Image Processing**: ~100-500ms for typical images (1024x768)
- **Audio Processing**: ~200-1000ms depending on file size
- **QR Code Generation**: ~50-200ms
- **Encryption/Decryption**: ~10-50ms for typical messages

### 9.2 Capacity Limits

| Media Type | Capacity Formula | Example |
|------------|------------------|---------|
| Image | width × height × 3 bits | 1024×768 = ~294KB |
| Audio | sample_count bits | 1 min @ 44.1kHz = ~2.6MB |
| QR Code | Version dependent | Version 40 = ~2.9KB |

### 9.3 Optimization Strategies

- **Lazy Compression**: Only compress if beneficial
- **Format Conversion**: Batch operations where possible
- **Memory Management**: Stream processing for large files
- **Caching**: Temporary file cleanup after processing

---

## 10. Security Considerations

### 10.1 Threat Model

```mermaid
graph TB
    subgraph "Threats"
        T1[Unauthorized Access]
        T2[Data Interception]
        T3[Steganalysis]
        T4[Brute Force Attacks]
    end
    
    subgraph "Mitigations"
        M1[Strong Encryption<br/>AES-256]
        M2[Secure Key Derivation<br/>PBKDF2]
        M3[LSB Technique<br/>Minimal Detectability]
        M4[Password Complexity<br/>Auto-generation]
    end
    
    T1 --> M1
    T2 --> M1
    T3 --> M3
    T4 --> M2
    T4 --> M4
```

### 10.2 Best Practices

1. **Password Security**: Use auto-generated passwords for maximum security
2. **File Integrity**: Avoid modifying steganographic files (resizing, cropping, etc.)
3. **Format Preservation**: Always use PNG for images, WAV for audio
4. **Capacity Planning**: Ensure carrier file is large enough for message
5. **Secure Transmission**: Use HTTPS for web interface, secure channels for file transfer

---

## 11. Future Enhancements

### 11.1 Planned Features

- Video file steganography support
- Advanced steganography techniques (DCT, FFT)
- Multi-layer encryption
- Distributed steganography across multiple files
- Steganalysis detection tools
- Enhanced QR code styles and customization

### 11.2 Scalability Improvements

- Asynchronous processing for large files
- Queue-based job processing
- Distributed processing support
- Cloud storage integration
- API rate limiting and throttling

---

## 12. Conclusion

SteganoTool Enhanced provides a robust, secure, and user-friendly platform for steganographic operations. The system's architecture supports multiple media types, implements strong encryption, and provides both web and command-line interfaces. The use of industry-standard algorithms (AES-256, PBKDF2) ensures security, while the LSB technique maintains carrier file integrity.

The modular design allows for easy extension and maintenance, making it suitable for both educational and production environments. The comprehensive API design enables integration with other systems, while the dual interface approach accommodates different user preferences.

---

## Appendix A: API Reference

### A.1 Encryption Endpoint

**Endpoint**: `POST /api/encrypt`

**Request**:
- `file` (multipart/form-data): Carrier file
- `message` (form-data): Message to hide
- `password` (form-data): Encryption password (optional if auto_generate=true)
- `auto_generate` (form-data): Boolean flag for auto-password generation
- `media_type` (form-data): "image" | "audio"

**Response**:
```json
{
  "status": "success",
  "output_filename": "stego_image.png",
  "download_url": "/api/download/stego_image.png",
  "compression_ratio": 45.2,
  "encrypted_size": 1024,
  "auto_generated_password": "Abc123!@#"
}
```

### A.2 Decryption Endpoint

**Endpoint**: `POST /api/decrypt`

**Request**:
- `file` (multipart/form-data): Steganographic file
- `password` (form-data): Decryption password (optional if embedded)
- `media_type` (form-data): "image" | "audio"

**Response**:
```json
{
  "status": "success",
  "message": "Decrypted message text",
  "message_length": 150,
  "password_found": true
}
```

---

## Appendix B: Glossary

- **LSB (Least Significant Bit)**: The rightmost bit in a binary number, changing it has minimal impact on the value
- **Steganography**: The practice of hiding information within other non-secret data
- **Stego File**: A file containing hidden steganographic data
- **Carrier File**: The original file used to hide data
- **PBKDF2**: Password-Based Key Derivation Function 2, used for key generation
- **IV (Initialization Vector)**: Random data used to initialize encryption algorithms
- **CBC (Cipher Block Chaining)**: A mode of operation for block ciphers

---

**Document Version**: 1.0  
**Last Updated**: 2024  
**Author**: Technical Documentation Team

