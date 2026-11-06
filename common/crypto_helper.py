import os
import zlib
import hashlib
import struct
import msgpack
os.environ["CRYPTOGRAPHY_OPENSSL_NO_LEGACY"] = "1" # Openssl eski sürüm hatasını önler.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoHelper:
    # GÜVENLİK: Token'ı CRYPTO_SHARED_TOKEN ortam değişkeninden oku.
    # Değişken yoksa geriye dönük uyumluluk için "TOGU2024" kullanılır (UYARI loglanır).
    _DEFAULT_TOKEN = "TOGU2024"
    SHARED_TOKEN = os.environ.get("CRYPTO_SHARED_TOKEN", "")
    VERSION = 0x01 # İletişim protokolümüzün versiyon numarasıdır (1 byte - Hex: 0x01). İleride protokol değişirse sunucunun eski istemcilerden gelen verileri reddedebilmesini sağlar.
    _token_warning_logged = False

    @classmethod
    def _derive_key(cls) -> bytes:
        """Paylaşılan kelimeden 256-bit AES anahtarı türetir."""
        import app_config as config
        _token = cls.SHARED_TOKEN
        if not _token:
            if getattr(config, "PRODUCTION", False):
                raise ValueError(
                    "[KRİPTO HATA] URETİM MODUNDA CRYPTO_SHARED_TOKEN tanimlanmak zorundadir! "
                    "Varsayilan token (TOGU2024) kullanimi guvenlik nedeniyle engellenmistir."
                )
            else:
                _token = cls._DEFAULT_TOKEN
                if not cls._token_warning_logged:
                    import logging
                    logging.getLogger("CryptoHelper").warning(
                        "[KRİPTO] CRYPTO_SHARED_TOKEN ortam değişkeni tanımlı değil! "
                        "Varsayılan token kullanılıyor. Üretim ortamında bu güvenlik açığıdır."
                    )
                    cls._token_warning_logged = True
        # Anahtar türetme fonksiyonu: Güvenlik için paylaşılan anahtarı (SHARED_TOKEN) alır
        # ve SHA-256 algoritması ile şifreleyerek 256-bit (32 byte) uzunluğunda kriptografik
        # bir anahtar (Key) üretir. AES-GCM şifrelemesi bu anahtarı kullanır.
        return hashlib.sha256(_token.encode('utf-8')).digest()

    @classmethod
    def encrypt_and_compress(cls, data_dict: dict) -> bytes:
        """
        1. msgpack.packb ile serileştirir.
        2. zlib ile sıkıştırır.
        3. AES-GCM ile şifreler.
        4. [VERSION (1 byte) | NONCE (12 bytes) | TAG (16 bytes) | CIPHERTEXT] yapısında paket oluşturur.
        """
        packed_data = msgpack.packb(data_dict, use_bin_type=True)
        compressed_data = zlib.compress(packed_data)
        
        key = cls._derive_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        
        ciphertext_with_tag = aesgcm.encrypt(nonce, compressed_data, None)
        
        tag = ciphertext_with_tag[-16:]
        ciphertext = ciphertext_with_tag[:-16]
        
        packet = struct.pack('B', cls.VERSION)
        packet += nonce
        packet += tag
        packet += ciphertext
        
        return packet

    @classmethod
    def decrypt_and_decompress(cls, packet: bytes) -> dict:
        """
        1. Paketten VERSION, NONCE, TAG ve CIPHERTEXT'i ayırır.
        2. AES-GCM ile deşifre eder.
        3. zlib ile dekompresyon yapar.
        4. msgpack.unpackb ile veriyi sözlüğe (dict) çevirir.
        """
        if len(packet) == 0:
            raise ValueError("Paket boş!")

        version = packet[0]
        if version != cls.VERSION:
            raise ValueError(f"Geçersiz protokol sürümü: {version}")

        if len(packet) < 1 + 12 + 16:
            raise ValueError(f"Paket boyutu çok kısa: {len(packet)} bytes")

        nonce = packet[1:13]
        tag = packet[13:29]
        ciphertext = packet[29:]
        
        ciphertext_with_tag = ciphertext + tag
        
        key = cls._derive_key()
        aesgcm = AESGCM(key)
        
        decrypted_compressed = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        decompressed_packed = zlib.decompress(decrypted_compressed)
        data_dict = msgpack.unpackb(decompressed_packed, raw=False)
        
        return data_dict

