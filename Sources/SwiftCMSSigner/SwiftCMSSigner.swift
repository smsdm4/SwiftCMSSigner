// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import OpenSSL

public class SwiftCMSSigner {
    public init() {}
    
    public func createCMSSignedMessageBase64(inputData: Data, certPEM: String, keyPEM: String) -> String? {
        // 1. مقداردهی اولیه الگوریتم‌ها و بارگذاری رشته‌های خطا
        OpenSSL_add_all_algorithms()
        ERR_load_CRYPTO_strings()
        
        // 2. ساخت یک BIO حافظه‌ای برای داده‌ی ورودی
        guard let inputBIO = BIO_new(BIO_s_mem()) else {
            print("Failed to create input BIO")
            return nil
        }
        inputData.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            BIO_write(inputBIO, buffer.baseAddress, Int32(buffer.count))
        }
        
        // 3. ساخت یک BIO برای Certificate (PEM)
        guard let certBIO = BIO_new(BIO_s_mem()) else {
            print("Failed to create certificate BIO")
            BIO_free(inputBIO)
            return nil
        }
        certPEM.withCString { ptr in
            BIO_puts(certBIO, ptr)
        }
        
        // 4. ساخت یک BIO برای Private Key (PEM)
        guard let keyBIO = BIO_new(BIO_s_mem()) else {
            print("Failed to create key BIO")
            BIO_free(inputBIO)
            BIO_free(certBIO)
            return nil
        }
        keyPEM.withCString { ptr in
            BIO_puts(keyBIO, ptr)
        }
        
        // 5. خواندن X509 Certificate از BIO
        guard let x509 = PEM_read_bio_X509(certBIO, nil, nil, nil) else {
            print("Error loading certificate: \(getOpenSSLError())")
            BIO_free(inputBIO)
            BIO_free(certBIO)
            BIO_free(keyBIO)
            return nil
        }
        
        // 6. خواندن Private Key از BIO
        guard let pkey = PEM_read_bio_PrivateKey(keyBIO, nil, nil, nil) else {
            print("Error loading private key: \(getOpenSSLError())")
            BIO_free(inputBIO)
            BIO_free(certBIO)
            BIO_free(keyBIO)
            X509_free(x509)
            return nil
        }
        
        // 7. ساخت CMS Signed Data با فلگ‌های مشابه دستور CLI
        //    CMS_DETACHED = امضاء جدا (بدون درج داده‌ی اصلی داخل CMS)
        //    CMS_BINARY = باینری بودن ورودی
        //    CMS_NOATTR = حذف رفتارهای پیش‌فرض برخی صفت‌ها
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
        
        // 8. آماده‌سازی یک BIO خروجی در حافظه برای نوشتن ساختار CMS (به‌صورت DER)
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
        
        // i2d_CMS_bio_stream دقیقا همان کاری را می‌کند که دستور:
        //    openssl cms -sign -in input_data.bin -binary -outform DER ...
        // در ترمینال انجام می‌دهد و ساختار CMS را به صورت DER داخل outBIO می‌نویسد.
        if i2d_CMS_bio_stream(outBIO, cms, /*inputBIO*/ nil, Int32(cmsFlags)) != 1 {
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
        
        // 9. خواندن تمام بایت‌های DER از outBIO
        let length = BIO_ctrl_pending(outBIO)
        var derBuffer = [UInt8](repeating: 0, count: Int(length))
        BIO_read(outBIO, &derBuffer, Int32(length))
        
        // 10. تبدیل باینری DER به Data
        let derData = Data(derBuffer)
        
        // 11. کدگذاری Base64 روی Data حاصل
        //    اگر بخواهید خروجی شبیه PEM بشود (با ساختار خطی 64 کاراکتری)، می‌توانید از options: [.lineLength64Characters] استفاده کنید.
        let base64String = derData.base64EncodedString()
        
        // 12. آزادسازی تمام منابع و ساختارهای OpenSSL
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
