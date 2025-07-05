// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import OpenSSL

public class SwiftCMSSigner {
    public init() {}
    
    public func createCMSSignedMessageBase64(inputData: Data, certPEM: String, keyPEM: String) -> String? {
        // 1. Initialize OpenSSL algorithms and load error strings
        // This sets up the necessary internal state for OpenSSL functions to work properly
        OpenSSL_add_all_algorithms()
        ERR_load_CRYPTO_strings()
        
        // 2. Create a memory BIO for the input data
        // We’ll use this as the source of the data we want to sign
        guard let inputBIO = BIO_new(BIO_s_mem()) else {
            print("Failed to create input BIO")
            return nil
        }
        inputData.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            BIO_write(inputBIO, buffer.baseAddress, Int32(buffer.count))
        }
        
        // 3. Create a memory BIO for the certificate (in PEM format)
        // This will hold the signer’s X.509 certificate
        guard let certBIO = BIO_new(BIO_s_mem()) else {
            print("Failed to create certificate BIO")
            BIO_free(inputBIO)
            return nil
        }
        certPEM.withCString { ptr in
            BIO_puts(certBIO, ptr)
        }
        
        // 4. Create a memory BIO for the private key (in PEM format)
        // This is the corresponding private key for the certificate
        guard let keyBIO = BIO_new(BIO_s_mem()) else {
            print("Failed to create key BIO")
            BIO_free(inputBIO)
            BIO_free(certBIO)
            return nil
        }
        keyPEM.withCString { ptr in
            BIO_puts(keyBIO, ptr)
        }
        
        // 5. Read the X.509 certificate from the BIO
        // If this fails, it means the certificate string is invalid or incorrectly formatted
        guard let x509 = PEM_read_bio_X509(certBIO, nil, nil, nil) else {
            print("Error loading certificate: \(getOpenSSLError())")
            BIO_free(inputBIO)
            BIO_free(certBIO)
            BIO_free(keyBIO)
            return nil
        }
        
        // 6. Read the private key from the BIO
        // Again, if this fails, the key might be invalid or not match the certificate
        guard let pkey = PEM_read_bio_PrivateKey(keyBIO, nil, nil, nil) else {
            print("Error loading private key: \(getOpenSSLError())")
            BIO_free(inputBIO)
            BIO_free(certBIO)
            BIO_free(keyBIO)
            X509_free(x509)
            return nil
        }
        
        // 7. Create a CMS signed structure with flags similar to the OpenSSL CLI
        //    CMS_DETACHED = don’t embed the original data inside the signature
        //    CMS_BINARY = treat the input as binary (no canonicalization)
        //    CMS_NOATTR = skip some default signing attributes that OpenSSL adds by default
        let cmsFlags: Int32 = CMS_DETACHED | CMS_BINARY | CMS_NOATTR
        guard let cms = CMS_sign(x509, pkey, nil, inputBIO, UInt32(cmsFlags)) else {
            print("CMS_sign failed: \(getOpenSSLError())")
            BIO_free(inputBIO)
            BIO_free(certBIO)
            BIO_free(keyBIO)
            X509_free(x509)
            EVP_PKEY_free(pkey)
            return nil
        }
        
        // 8. Set up an output BIO in memory where the signed CMS (in DER format) will be written
        // This is where the final signed binary structure will be stored
        guard let outBIO = BIO_new(BIO_s_mem()) else {
            print("Failed to create output BIO")
            BIO_free(inputBIO)
            BIO_free(certBIO)
            BIO_free(keyBIO)
            X509_free(x509)
            EVP_PKEY_free(pkey)
            CMS_ContentInfo_free(cms)
            return nil
        }
        
        // The function below (i2d_CMS_bio_stream) is the exact equivalent of this terminal command:
        //      openssl cms -sign -in input_data.bin -binary -outform DER ...
        // It writes the CMS structure to outBIO in DER format
        if i2d_CMS_bio_stream(outBIO, cms, nil, Int32(cmsFlags)) != 1 {
            print("Failed to write CMS to BIO: \(getOpenSSLError())")
            BIO_free(inputBIO)
            BIO_free(certBIO)
            BIO_free(keyBIO)
            BIO_free(outBIO)
            X509_free(x509)
            EVP_PKEY_free(pkey)
            CMS_ContentInfo_free(cms)
            return nil
        }
        
        // 9. Read all bytes from the output BIO (DER format) into a buffer
        // This gives us the raw binary representation of the signed message
        let length = BIO_ctrl_pending(outBIO)
        var derBuffer = [UInt8](repeating: 0, count: Int(length))
        BIO_read(outBIO, &derBuffer, Int32(length))
        
        // 10. Convert the binary DER data into a Swift Data object
        // This lets us manipulate or encode it easily in Swift
        let derData = Data(derBuffer)
        
        // 11. Base64-encode the result to get a text version of the CMS structure
        //    If you want it to look like PEM (64-character lines), you can use options like [.lineLength64Characters]
        let base64String = derData.base64EncodedString()
        
        // 12. Free all OpenSSL resources to avoid memory leaks
        // Always good practice after you’re done with OpenSSL objects
        BIO_free(inputBIO)
        BIO_free(certBIO)
        BIO_free(keyBIO)
        BIO_free(outBIO)
        CMS_ContentInfo_free(cms)
        X509_free(x509)
        EVP_PKEY_free(pkey)
        
        return base64String
    }
    
    private func getOpenSSLError() -> String {
        var errorBuffer = [UInt8](repeating: 0, count: 256)
        ERR_error_string_n(ERR_get_error(), &errorBuffer, errorBuffer.count)
        return String(cString: errorBuffer)
    }
}
